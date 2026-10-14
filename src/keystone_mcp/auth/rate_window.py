"""Shared sliding-window rate counters for throttles (memory or Redis)."""

from __future__ import annotations

import hashlib
import logging
import math
import threading
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Protocol

from redis.asyncio import Redis
from redis.exceptions import RedisError

from keystone_mcp.observability.metrics import record_throttle_backend_error

logger = logging.getLogger(__name__)

_MAX_IN_MEMORY_KEYS = 20_000
_ERROR_LOG_INTERVAL_SECONDS = 60.0

_last_error_log_at = 0.0
_error_log_lock = threading.Lock()

_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now_ms = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local window_start = now_ms - window_ms
redis.call('ZREMRANGEBYSCORE', key, '-inf', '(' .. window_start)
local count = redis.call('ZCARD', key)
if count < limit then
  redis.call('ZADD', key, now_ms, member)
  redis.call('PEXPIRE', key, window_ms)
  return {1, 0}
end
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local oldest_ms = tonumber(oldest[2])
local retry_ms = oldest_ms + window_ms - now_ms
local retry_after = math.ceil(retry_ms / 1000)
if retry_after < 1 then
  retry_after = 1
end
return {0, retry_after}
"""


@dataclass(frozen=True, slots=True)
class WindowDecision:
    allowed: bool
    retry_after: int  # seconds, 0 when allowed


class SlidingWindow(Protocol):
    async def hit(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        now: float | None = None,
    ) -> WindowDecision: ...


def _throttle_redis_key(key_prefix: str, kind: str, logical_key: str) -> str:
    digest = hashlib.sha256(logical_key.encode()).hexdigest()[:32]
    return f"{key_prefix}throttle:{kind}:{digest}"


def _log_redis_error_once(kind: str, exc: BaseException) -> None:
    global _last_error_log_at
    with _error_log_lock:
        now = time.monotonic()
        if now - _last_error_log_at < _ERROR_LOG_INTERVAL_SECONDS:
            return
        _last_error_log_at = now
    logger.warning(
        "throttle Redis backend error (kind=%s): %s",
        kind,
        exc,
    )


class InMemorySlidingWindow:
    """In-process sliding window with a bounded key table."""

    def __init__(self) -> None:
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def hit_sync(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        now: float | None = None,
    ) -> WindowDecision:
        if limit <= 0:
            return WindowDecision(allowed=True, retry_after=0)
        ts = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._hits.get(key)
            if bucket is None:
                bucket = deque()
            else:
                self._hits.move_to_end(key)
            cutoff = ts - window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry = max(1, int(math.ceil(bucket[0] + window_seconds - ts)))
                if bucket:
                    self._hits[key] = bucket
                else:
                    self._hits.pop(key, None)
                return WindowDecision(allowed=False, retry_after=retry)
            bucket.append(ts)
            self._hits[key] = bucket
            while len(self._hits) > _MAX_IN_MEMORY_KEYS:
                self._hits.popitem(last=False)
            return WindowDecision(allowed=True, retry_after=0)

    async def hit(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        now: float | None = None,
    ) -> WindowDecision:
        return self.hit_sync(key, limit=limit, window_seconds=window_seconds, now=now)


class RedisSlidingWindow:
    """Redis-backed sliding window shared across replicas.

    ``now`` is taken from the caller (``time.time()`` in production) rather
    than Redis ``TIME``, so tests can inject a clock. Replica clock skew of
    about one second is acceptable for throttle windows.
    """

    def __init__(self, redis: Redis, *, key_prefix: str, kind: str) -> None:
        self._redis = redis
        self._key_prefix = key_prefix
        self._kind = kind
        self._script = redis.register_script(_SLIDING_WINDOW_LUA)

    async def hit(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        now: float | None = None,
    ) -> WindowDecision:
        if limit <= 0:
            return WindowDecision(allowed=True, retry_after=0)
        now_ms = int((time.time() if now is None else now) * 1000)
        window_ms = window_seconds * 1000
        member = f"{now_ms}:{uuid.uuid4().hex[:8]}"
        redis_key = _throttle_redis_key(self._key_prefix, self._kind, key)
        try:
            allowed_raw, retry_raw = await self._script(
                keys=[redis_key],
                args=[now_ms, window_ms, limit, member],
            )
        except RedisError as exc:
            record_throttle_backend_error(kind=self._kind)
            _log_redis_error_once(self._kind, exc)
            return WindowDecision(allowed=True, retry_after=0)
        allowed = int(allowed_raw) == 1
        retry_after = int(retry_raw) if not allowed else 0
        return WindowDecision(allowed=allowed, retry_after=retry_after)
