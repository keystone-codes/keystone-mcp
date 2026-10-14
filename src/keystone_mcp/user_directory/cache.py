"""In-memory TTL cache with separate allow/deny lifetimes."""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Generic, TypeVar

from keystone_mcp.user_directory.models import UserResolveResult
from keystone_mcp.user_directory.types import ApiKeyVerification
from keystone_mcp.users.models import utcnow

API_KEY_POSITIVE_CACHE_MAX = 10_000
API_KEY_NEGATIVE_CACHE_MAX = 10_000
RESOLUTION_CACHE_MAX = 50_000
_PURGE_INTERVAL_SECONDS = 30.0

_T = TypeVar("_T")


@dataclass(slots=True)
class _BoundedEntry(Generic[_T]):
    value: _T
    expires_at: float
    revision: int


class _BoundedTtlCache(Generic[_T]):
    """LRU-bounded TTL cache with periodic expiry purge."""

    def __init__(self, *, max_entries: int) -> None:
        self._max_entries = max_entries
        self._entries: OrderedDict[str, _BoundedEntry[_T]] = OrderedDict()
        self._last_purge_at = 0.0
        self._evictions = 0

    @property
    def evictions(self) -> int:
        return self._evictions

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)

    def _monotonic_now(self, now: float | None) -> float:
        return time.monotonic() if now is None else now

    def _purge_expired(self, *, now: float) -> None:
        dead = [key for key, entry in self._entries.items() if now >= entry.expires_at]
        for key in dead:
            self._entries.pop(key, None)

    def _maybe_purge(self, *, now: float) -> None:
        if now - self._last_purge_at >= _PURGE_INTERVAL_SECONDS:
            self._purge_expired(now=now)
            self._last_purge_at = now

    def _evict_lru(self) -> None:
        while len(self._entries) > self._max_entries:
            self._entries.popitem(last=False)
            self._evictions += 1

    def get(
        self,
        key: str,
        *,
        revision: int,
        now: float | None = None,
    ) -> _T | None:
        mono = self._monotonic_now(now)
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.revision != revision:
            self._entries.pop(key, None)
            return None
        if mono >= entry.expires_at:
            self._entries.pop(key, None)
            return None
        self._entries.move_to_end(key)
        return entry.value

    def put(
        self,
        key: str,
        value: _T,
        *,
        ttl: float,
        revision: int,
        now: float | None = None,
    ) -> int:
        mono = self._monotonic_now(now)
        self._maybe_purge(now=mono)
        self._entries[key] = _BoundedEntry(
            value=value,
            expires_at=mono + ttl,
            revision=revision,
        )
        self._entries.move_to_end(key)
        before = self._evictions
        self._evict_lru()
        return self._evictions - before


class ResolutionCache:
    """Per-email cache keyed by normalized email."""

    def __init__(
        self,
        *,
        allow_ttl_seconds: float,
        deny_ttl_seconds: float,
        max_entries: int = RESOLUTION_CACHE_MAX,
    ) -> None:
        self._allow_ttl = allow_ttl_seconds
        self._deny_ttl = deny_ttl_seconds
        self._entries = _BoundedTtlCache[_CacheEntry](max_entries=max_entries)

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)

    def get(
        self,
        email: str,
        *,
        revision: int,
        bypass_allow_cache: bool = False,
        now: float | None = None,
    ) -> UserResolveResult | None:
        entry = self._entries.get(email, revision=revision, now=now)
        if entry is None:
            return None
        if bypass_allow_cache and entry.result.is_allow_decision:
            return None
        cached = UserResolveResult(
            exists=entry.result.exists,
            roles=entry.result.roles,
            is_blocked=entry.result.is_blocked,
            subject_type=entry.result.subject_type,
            from_cache=True,
            revision=entry.revision,
        )
        return cached

    def put(
        self,
        email: str,
        result: UserResolveResult,
        *,
        revision: int,
        now: float | None = None,
    ) -> None:
        ttl = self._allow_ttl if result.is_allow_decision else self._deny_ttl
        self._entries.put(
            email,
            _CacheEntry(result=result, revision=revision),
            ttl=ttl,
            revision=revision,
            now=now,
        )


@dataclass(slots=True)
class _CacheEntry:
    result: UserResolveResult
    revision: int


class ApiKeyVerificationCache:
    """Positive and negative TTL caches keyed by SHA-256 of the raw API key."""

    def __init__(
        self,
        *,
        allow_ttl_seconds: float,
        deny_ttl_seconds: float,
        max_positive: int = API_KEY_POSITIVE_CACHE_MAX,
        max_negative: int = API_KEY_NEGATIVE_CACHE_MAX,
    ) -> None:
        self._allow_ttl = allow_ttl_seconds
        self._deny_ttl = deny_ttl_seconds
        self._positive = _BoundedTtlCache[ApiKeyVerification](max_entries=max_positive)
        self._negative = _BoundedTtlCache[bool](max_entries=max_negative)
        self._reported_positive_evictions = 0
        self._reported_negative_evictions = 0

    def clear(self) -> None:
        self._positive.clear()
        self._negative.clear()

    @property
    def positive_size(self) -> int:
        return len(self._positive)

    @property
    def negative_size(self) -> int:
        return len(self._negative)

    def get_positive(
        self,
        key_digest: str,
        *,
        revision: int,
        now: float | None = None,
    ) -> ApiKeyVerification | None:
        result = self._positive.get(key_digest, revision=revision, now=now)
        if result is None:
            return None
        if result.expires_at is not None and result.expires_at <= utcnow():
            return None
        return result

    def put_positive(
        self,
        key_digest: str,
        result: ApiKeyVerification,
        *,
        revision: int,
        now: float | None = None,
    ) -> int:
        ttl = self._allow_ttl
        if result.expires_at is not None:
            now_dt = utcnow()
            if result.expires_at <= now_dt:
                return 0
            remaining = (result.expires_at - now_dt).total_seconds()
            ttl = min(self._allow_ttl, remaining)
        return self._positive.put(
            key_digest,
            result,
            ttl=ttl,
            revision=revision,
            now=now,
        )

    def get_negative(
        self,
        key_digest: str,
        *,
        revision: int,
        now: float | None = None,
    ) -> bool:
        hit = self._negative.get(key_digest, revision=revision, now=now)
        return hit is True

    def put_negative(
        self,
        key_digest: str,
        *,
        revision: int,
        now: float | None = None,
    ) -> int:
        return self._negative.put(
            key_digest,
            True,
            ttl=self._deny_ttl,
            revision=revision,
            now=now,
        )

    @property
    def negative_evictions(self) -> int:
        return self._negative.evictions

    def drain_eviction_counts(self) -> tuple[int, int]:
        pos = self._positive.evictions - self._reported_positive_evictions
        neg = self._negative.evictions - self._reported_negative_evictions
        self._reported_positive_evictions = self._positive.evictions
        self._reported_negative_evictions = self._negative.evictions
        return pos, neg
