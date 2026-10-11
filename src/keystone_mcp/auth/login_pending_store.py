"""Shared short-lived login state (pending transactions, one-time codes).

Production uses the platform Redis cluster (same connection pool as OAuth
sessions). Records are single-use: :meth:`consume` atomically reads and deletes.
"""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable

from redis.asyncio import Redis
from redis.exceptions import NoScriptError, ResponseError

_CONSUME_SCRIPT = """
local value = redis.call('GET', KEYS[1])
if value then
    redis.call('DEL', KEYS[1])
end
return value
"""


@runtime_checkable
class LoginPendingStore(Protocol):
    """Namespace-isolated pending login records with TTL and atomic consume."""

    async def put(self, namespace: str, key: str, payload: str, ttl_seconds: int) -> None: ...

    async def get(self, namespace: str, key: str) -> str | None: ...

    async def consume(self, namespace: str, key: str) -> str | None: ...

    async def aclose(self) -> None: ...


class _MemoryEntry:
    __slots__ = ("payload", "expires_at")

    def __init__(self, payload: str, expires_at: float) -> None:
        self.payload = payload
        self.expires_at = expires_at


class InMemoryLoginPendingStore:
    """Ephemeral store for unit tests."""

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], _MemoryEntry] = {}

    def _lookup(self, namespace: str, key: str) -> _MemoryEntry | None:
        entry = self._entries.get((namespace, key))
        if entry is None:
            return None
        if entry.expires_at <= time.time():
            self._entries.pop((namespace, key), None)
            return None
        return entry

    async def put(self, namespace: str, key: str, payload: str, ttl_seconds: int) -> None:
        ttl = max(int(ttl_seconds), 1)
        self._entries[(namespace, key)] = _MemoryEntry(payload, time.time() + ttl)

    async def get(self, namespace: str, key: str) -> str | None:
        entry = self._lookup(namespace, key)
        return entry.payload if entry is not None else None

    async def consume(self, namespace: str, key: str) -> str | None:
        entry_key = (namespace, key)
        entry = self._lookup(namespace, key)
        if entry is None:
            return None
        self._entries.pop(entry_key, None)
        return entry.payload

    async def aclose(self) -> None:
        return None


class RedisLoginPendingStore:
    """Login pending state in shared Redis (GETDEL / Lua for atomic consume)."""

    def __init__(
        self,
        redis: Redis,
        key_prefix: str = "km:login:",
        *,
        owns_redis: bool = False,
    ) -> None:
        prefix = key_prefix if key_prefix.endswith(":") else f"{key_prefix}:"
        self._prefix = prefix
        self._redis = redis
        self._owns_redis = owns_redis
        self._consume_sha: str | None = None

    @property
    def redis(self) -> Redis:
        return self._redis

    def _record_key(self, namespace: str, key: str) -> str:
        return f"{self._prefix}{namespace}:{key}"

    async def _consume_via_lua(self, redis_key: str) -> str | None:
        for attempt in range(2):
            try:
                if self._consume_sha is None:
                    self._consume_sha = await self._redis.script_load(_CONSUME_SCRIPT)
                result = await self._redis.evalsha(self._consume_sha, 1, redis_key)
                return result if isinstance(result, str) else None
            except NoScriptError:
                # Script cache flushed (SCRIPT FLUSH / failover); reload once.
                self._consume_sha = None
                if attempt == 0:
                    continue
                return None

    async def _atomic_consume(self, redis_key: str) -> str | None:
        try:
            return await self._redis.getdel(redis_key)
        except ResponseError:
            # GETDEL unavailable on older Redis; Lua script is equivalent.
            return await self._consume_via_lua(redis_key)

    async def put(self, namespace: str, key: str, payload: str, ttl_seconds: int) -> None:
        ttl = max(int(ttl_seconds), 1)
        await self._redis.set(self._record_key(namespace, key), payload, ex=ttl)

    async def get(self, namespace: str, key: str) -> str | None:
        return await self._redis.get(self._record_key(namespace, key))

    async def consume(self, namespace: str, key: str) -> str | None:
        return await self._atomic_consume(self._record_key(namespace, key))

    async def aclose(self) -> None:
        if self._owns_redis:
            await self._redis.aclose()


def build_login_pending_store(
    settings: object,
    oauth_store: object | None = None,
) -> LoginPendingStore:
    """Construct the login pending store. Redis is required.

    Falling back to :class:`InMemoryLoginPendingStore` here used to hide a
    missing ``KEYSTONE_MCP_REDIS_URL``: the server started, and then pending
    login transactions and one-time authorization codes lived in one process's
    memory. Behind more than one replica that silently breaks the login flow
    (the code is minted on one replica and redeemed on another), and every
    restart drops sessions in flight. Like :func:`build_oauth_store`, this now
    refuses to start instead. The in-memory class stays for tests, which
    construct it directly.
    """
    prefix = getattr(settings, "login_pending_key_prefix", "km:login:")

    # Prefer the OAuth store's pool so both share one connection.
    shared_redis: Redis | None = None
    if oauth_store is not None:
        shared_redis = getattr(oauth_store, "redis", None)
    if shared_redis is not None:
        return RedisLoginPendingStore(shared_redis, key_prefix=prefix, owns_redis=False)

    redis_url = getattr(settings, "redis_url", "").strip()
    if not redis_url:
        raise RuntimeError(
            "KEYSTONE_MCP_REDIS_URL is required for login pending state (pending "
            "authorization transactions and one-time codes). Set it to the shared "
            "keystone Redis (e.g. redis://redis:6379/0)."
        )

    redis = Redis.from_url(redis_url, decode_responses=True)
    return RedisLoginPendingStore(redis, key_prefix=prefix, owns_redis=True)
