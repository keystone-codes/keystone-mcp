"""Request throttles for authenticated tool calls and unauthenticated login.

Per-identity throttling keys on the verified email after OAuth. Login throttling
keys on client IP for every ``POST /login`` and ``POST /register`` attempt, and on
email for failed credential checks only — successful logins do not consume the
email budget.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import math
import threading
import time
from collections import OrderedDict, defaultdict, deque
from typing import Protocol

from redis.asyncio import Redis
from redis.exceptions import RedisError
from starlette.requests import Request
from starlette.responses import Response

from keystone_mcp.auth.rate_window import InMemorySlidingWindow, RedisSlidingWindow, SlidingWindow

logger = logging.getLogger(__name__)

_ERROR_LOG_INTERVAL_SECONDS = 60.0
_last_login_fail_error_log_at = 0.0
_login_fail_error_log_lock = threading.Lock()

# Bounds on `LoginAttemptThrottle._ip_hits`. Without them, an
# attacker who never repeats a source address — trivial with IPv6, which
# offers an effectively unlimited pool — leaves one stale, single-timestamp
# bucket behind per address forever: `check_ip` only prunes the bucket for
# the key it is looking at, and a key that is never looked up again is never
# pruned. `_MAX_TRACKED_IPS` caps how many distinct addresses are remembered
# at once (oldest evicted first); `_SWEEP_EVERY_N_CALLS` bounds how often a
# full pass drops buckets that have aged out of the window entirely, so
# memory is bounded by call volume rather than by how many distinct addresses
# have ever been seen.
_MAX_TRACKED_IPS = 20_000
_SWEEP_EVERY_N_CALLS = 2_000


def ip_bucket(host: str) -> str:
    """Normalize a peer address for per-network login/OAuth throttling."""
    if not host or host == "unknown":
        return host or "unknown"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    if isinstance(ip, ipaddress.IPv4Address):
        return str(ip)
    if ip.ipv4_mapped is not None:
        return str(ip.ipv4_mapped)
    return str(ipaddress.ip_network(f"{ip}/64", strict=False))


# Same shape of bound on `LoginAttemptThrottle._email_failures`.
# `check_email_failures` used to read `self._email_failures[normalized]` on a
# `defaultdict`, so merely *checking* an email — no failed login required —
# planted a permanent empty bucket for it: an attacker probing one login per
# email address, never repeating one, grew the dict without bound and without
# ever being throttled. The fix is twofold: a read-only check no longer
# creates an entry (only `record_login_failure` does), and the entries that
# *are* created are bounded the same way `_ip_hits` is, with their own
# counters so sweeping one table does not reset the other's cadence.
_MAX_TRACKED_EMAILS = 20_000
_EMAIL_SWEEP_EVERY_N_CALLS = 2_000

# Longest email `LoginAttemptThrottle` will use verbatim as a dict key
#. RFC 5321 caps a real address at 254 octets; 320 leaves room
# for callers that pass something a little longer without being unbounded.
# Truncating (rather than refusing) is deliberately safe either way: two
# distinct attacker-controlled strings sharing the first 320 characters now
# share one throttle budget, which only makes the limit *more* conservative.
_MAX_EMAIL_LEN = 320


class PerIdentityThrottle:
    def __init__(
        self,
        max_requests: int = 30,
        window_seconds: int = 60,
        *,
        window: SlidingWindow | None = None,
    ) -> None:
        self._max = max_requests
        self._window_seconds = window_seconds
        self._window = window or InMemorySlidingWindow()
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, identity_key: str, now: float | None = None) -> bool:
        """Record a hit and return True if within the limit, False if exceeded."""
        if isinstance(self._window, RedisSlidingWindow):
            raise RuntimeError("use acheck")
        if self._max <= 0:
            return True
        ts = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._hits[identity_key]
            cutoff = ts - self._window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self._max:
                return False
            bucket.append(ts)
            return True

    async def acheck(self, identity_key: str, now: float | None = None) -> bool:
        if isinstance(self._window, RedisSlidingWindow):
            decision = await self._window.hit(
                identity_key,
                limit=self._max,
                window_seconds=self._window_seconds,
                now=now,
            )
            return decision.allowed
        return self.check(identity_key, now=now)


def _normalize_email_key(email: str) -> str:
    """Normalize and length-cap an email before it is ever used as a dict key.

    See `_MAX_EMAIL_LEN` for why truncating (not refusing) an overlong value
    is safe.
    """
    return email.strip().lower()[:_MAX_EMAIL_LEN]


class LoginAttemptThrottle:
    """Sliding-window limits for unauthenticated login and client registration."""

    def __init__(
        self,
        ip_max: int = 30,
        email_max: int = 10,
        window_seconds: int = 300,
        *,
        window: SlidingWindow | None = None,
        kind: str = "login_ip",
    ) -> None:
        self._ip_max = ip_max
        self._email_max = email_max
        self._window_seconds = window_seconds
        self._ip_window = window
        self._ip_kind = kind
        self._ip_hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._ip_calls_since_sweep = 0
        self._email_failures: OrderedDict[str, deque[float]] = OrderedDict()
        self._email_calls_since_sweep = 0
        self._lock = threading.Lock()

    def enabled(self) -> bool:
        return self._ip_max > 0 or self._email_max > 0

    def check_ip(self, ip_key: str, now: float | None = None) -> tuple[bool, int]:
        """Record one attempt for *ip_key*; return whether it is within the IP limit."""
        if isinstance(self._ip_window, RedisSlidingWindow):
            raise RuntimeError("use acheck_ip")
        if self._ip_max <= 0:
            return True, 0
        ts = time.monotonic() if now is None else now
        key = ip_bucket(ip_key or "unknown")
        with self._lock:
            self._ip_calls_since_sweep += 1
            if (
                self._ip_calls_since_sweep >= _SWEEP_EVERY_N_CALLS
                or len(self._ip_hits) > _MAX_TRACKED_IPS
            ):
                self._sweep_ip_hits(ts)

            bucket = self._ip_hits.get(key)
            if bucket is None:
                bucket = deque()
            else:
                self._ip_hits.move_to_end(key)
            allowed, retry_after = self._within_limit(bucket, self._ip_max, ts)
            if allowed:
                bucket.append(ts)
                self._ip_hits[key] = bucket
                while len(self._ip_hits) > _MAX_TRACKED_IPS:
                    # Oldest-accessed address first; it is the one least
                    # likely to come back and ask about its own budget.
                    self._ip_hits.popitem(last=False)
                return True, 0
            if bucket:
                self._ip_hits[key] = bucket
            else:
                self._ip_hits.pop(key, None)
            return False, retry_after

    async def acheck_ip(self, ip_key: str, now: float | None = None) -> tuple[bool, int]:
        if isinstance(self._ip_window, RedisSlidingWindow):
            decision = await self._ip_window.hit(
                ip_bucket(ip_key or "unknown"),
                limit=self._ip_max,
                window_seconds=self._window_seconds,
                now=now,
            )
            return decision.allowed, decision.retry_after
        return self.check_ip(ip_key, now=now)

    def _sweep_ip_hits(self, ts: float) -> None:
        """Drop IP buckets that have aged out of the window entirely.

        A bucket's most recent hit being outside the window means every hit
        in it is, so this only needs to look at one timestamp per key rather
        than pruning each bucket fully.
        """
        self._ip_calls_since_sweep = 0
        cutoff = ts - self._window_seconds
        stale = [key for key, bucket in self._ip_hits.items() if not bucket or bucket[-1] <= cutoff]
        for key in stale:
            del self._ip_hits[key]

    def check_email_failures(self, email: str, now: float | None = None) -> tuple[bool, int]:
        """Return whether another login attempt is allowed for *email* (failures only).

        A read-only check: an email with no recorded failure is never added to
 `_email_failures` — there is nothing to look up, so this
        returns the "allowed" default without creating an entry.
        """
        if self._email_max <= 0:
            return True, 0
        normalized = _normalize_email_key(email)
        if not normalized:
            return True, 0
        ts = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._email_failures.get(normalized)
            if bucket is None:
                return True, 0
            allowed, retry_after = self._within_limit(bucket, self._email_max, ts)
            if not bucket:
                # Pruned to empty by the check above: drop the now-empty
                # entry instead of leaving it behind forever.
                self._email_failures.pop(normalized, None)
            return allowed, retry_after

    def record_login_failure(self, email: str, now: float | None = None) -> None:
        if self._email_max <= 0:
            return
        normalized = _normalize_email_key(email)
        if not normalized:
            return
        ts = time.monotonic() if now is None else now
        with self._lock:
            self._email_calls_since_sweep += 1
            if (
                self._email_calls_since_sweep >= _EMAIL_SWEEP_EVERY_N_CALLS
                or len(self._email_failures) > _MAX_TRACKED_EMAILS
            ):
                self._sweep_email_failures(ts)

            bucket = self._email_failures.get(normalized)
            if bucket is None:
                bucket = deque()
            else:
                self._email_failures.move_to_end(normalized)
            self._prune(bucket, ts)
            bucket.append(ts)
            self._email_failures[normalized] = bucket
            while len(self._email_failures) > _MAX_TRACKED_EMAILS:
                # Oldest-accessed email first, mirroring `check_ip`'s eviction.
                self._email_failures.popitem(last=False)

    def _sweep_email_failures(self, ts: float) -> None:
        """Drop email buckets that have aged out of the window entirely.

        Mirrors `_sweep_ip_hits`: a bucket's most recent hit being outside the
        window means every hit in it is, so one timestamp per key is enough.
        """
        self._email_calls_since_sweep = 0
        cutoff = ts - self._window_seconds
        stale = [
            key
            for key, bucket in self._email_failures.items()
            if not bucket or bucket[-1] <= cutoff
        ]
        for key in stale:
            del self._email_failures[key]

    def _prune(self, bucket: deque[float], ts: float) -> None:
        cutoff = ts - self._window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()

    def _within_limit(self, bucket: deque[float], max_hits: int, ts: float) -> tuple[bool, int]:
        self._prune(bucket, ts)
        if len(bucket) >= max_hits:
            retry = max(1, int(math.ceil(bucket[0] + self._window_seconds - ts)))
            return False, retry
        return True, 0


class LoginFailureLimiter(Protocol):
    async def check(self, email: str, ip: str) -> tuple[bool, int]: ...

    async def record_failure(self, email: str, ip: str) -> None: ...


def _log_login_failure_redis_error_once(exc: BaseException) -> None:
    global _last_login_fail_error_log_at
    with _login_fail_error_log_lock:
        now = time.monotonic()
        if now - _last_login_fail_error_log_at < _ERROR_LOG_INTERVAL_SECONDS:
            return
        _last_login_fail_error_log_at = now
    logger.warning("login failure limiter Redis error: %s", exc)


class InMemoryLoginFailureLimiter:
    def __init__(self, throttle: LoginAttemptThrottle) -> None:
        self._throttle = throttle

    async def check(self, email: str, ip: str) -> tuple[bool, int]:
        key = f"{_normalize_email_key(email)}|{ip_bucket(ip)}"
        return self._throttle.check_email_failures(key)

    async def record_failure(self, email: str, ip: str) -> None:
        key = f"{_normalize_email_key(email)}|{ip_bucket(ip)}"
        self._throttle.record_login_failure(key)


class RedisLoginFailureLimiter:
    def __init__(
        self,
        redis: Redis,
        *,
        key_prefix: str,
        max_failures: int,
        window_seconds: int,
    ) -> None:
        self._redis = redis
        self._key_prefix = key_prefix if key_prefix.endswith(":") else f"{key_prefix}:"
        self._max_failures = max_failures
        self._window_seconds = window_seconds

    def _redis_key(self, email: str, ip: str) -> str:
        digest = hashlib.sha256(_normalize_email_key(email).encode()).hexdigest()
        return f"{self._key_prefix}login_fail:{digest}:{ip_bucket(ip)}"

    async def check(self, email: str, ip: str) -> tuple[bool, int]:
        if self._max_failures <= 0:
            return True, 0
        key = self._redis_key(email, ip)
        try:
            raw = await self._redis.get(key)
        except RedisError as exc:
            _log_login_failure_redis_error_once(exc)
            return True, 0
        if raw is None:
            return True, 0
        count = int(raw)
        if count >= self._max_failures:
            try:
                ttl = await self._redis.ttl(key)
            except RedisError as exc:
                _log_login_failure_redis_error_once(exc)
                return True, 0
            return False, max(1, ttl if ttl > 0 else 1)
        return True, 0

    async def record_failure(self, email: str, ip: str) -> None:
        if self._max_failures <= 0:
            return
        key = self._redis_key(email, ip)
        try:
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.set(key, 0, ex=self._window_seconds, nx=True)
                pipe.incr(key)
                await pipe.execute()
        except RedisError as exc:
            _log_login_failure_redis_error_once(exc)


def peer_host(request: Request) -> str:
    if request.client is None:
        return "unknown"
    return request.client.host or "unknown"


def login_throttle_response(retry_after: int) -> Response:
    return Response(
        status_code=429,
        headers={"Retry-After": str(retry_after)},
        content="Too Many Requests",
    )


class IpLoginThrottleMiddleware:
    """ASGI wrapper that enforces the IP limit on the configured HTTP methods."""

    def __init__(
        self,
        app: object,
        throttle: LoginAttemptThrottle,
        methods: frozenset[str] = frozenset({"POST"}),
    ) -> None:
        self.app = app
        self._throttle = throttle
        self._methods = methods

    async def __call__(self, scope, receive, send):  # noqa: ANN001
        if scope.get("type") == "http":
            request = Request(scope, receive)
            if request.method in self._methods:
                allowed, retry_after = await self._throttle.acheck_ip(peer_host(request))
                if not allowed:
                    await login_throttle_response(retry_after)(scope, receive, send)
                    return
        await self.app(scope, receive, send)  # type: ignore[misc]


def wrap_asgi_with_ip_login_throttle(
    endpoint: object,
    throttle: LoginAttemptThrottle,
    methods: frozenset[str] = frozenset({"POST"}),
) -> IpLoginThrottleMiddleware:
    return IpLoginThrottleMiddleware(endpoint, throttle, methods)
