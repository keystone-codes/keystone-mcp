"""Cached fail-closed user-directory resolver."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections import OrderedDict
from typing import Protocol, runtime_checkable

import httpx

from keystone_mcp.observability.subject import normalize_subject
from keystone_mcp.user_directory.cache import ApiKeyVerificationCache, ResolutionCache
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker
from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.protocol import (
    ApiKeyDirectory,
    ApiKeyIdIndex,
    ApiKeyState,
    UserDirectory,
)
from keystone_mcp.user_directory.revision import RevisionReader
from keystone_mcp.user_directory.types import (
    ApiKeyVerification,
    UserResolveResult,
    parse_api_key,
)
from keystone_mcp.user_directory.util import normalize_email

logger = logging.getLogger(__name__)

_UNKNOWN_KEY_DIRECTORY_CALLS_PER_SECOND = 20.0
_UNKNOWN_KEY_DIRECTORY_BURST = 50.0
_VERIFIED_KEY_ID_MAX = 10_000


@runtime_checkable
class ApiKeyCacheObserver(Protocol):
    def record_api_key_verification(self, outcome: str) -> None: ...

    def set_api_key_cache_size(self, cache: str, size: int) -> None: ...

    def record_api_key_cache_evictions(self, cache: str, count: int) -> None: ...


class _UnknownKeyRateLimiter:
    def __init__(self, *, rate: float, burst: float) -> None:
        self._rate = rate
        self._burst = burst
        self._tokens = burst
        self._last_at = 0.0

    def allow(self, *, now: float | None = None) -> bool:
        mono = time.monotonic() if now is None else now
        elapsed = mono - self._last_at
        self._last_at = mono
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class CachedUserDirectoryResolver:
    """Fail-closed resolver with revision-aware cache and circuit breaker."""

    def __init__(
        self,
        backend: UserDirectory,
        *,
        revision_reader: RevisionReader,
        cache: ResolutionCache,
        circuit_breaker: CircuitBreaker,
        api_key_cache: ApiKeyVerificationCache | None = None,
    ) -> None:
        self._backend = backend
        self._revision_reader = revision_reader
        self._cache = cache
        self._api_key_cache = api_key_cache or ApiKeyVerificationCache(
            allow_ttl_seconds=cache._allow_ttl,
            deny_ttl_seconds=cache._deny_ttl,
        )
        self._circuit = circuit_breaker
        self._seen_revision: int | None = None
        self._observer: ApiKeyCacheObserver | None = None
        self._unknown_key_limiter = _UnknownKeyRateLimiter(
            rate=_UNKNOWN_KEY_DIRECTORY_CALLS_PER_SECOND,
            burst=_UNKNOWN_KEY_DIRECTORY_BURST,
        )
        self._verified_key_ids: OrderedDict[str, None] = OrderedDict()
        self._key_id_index_revision: int | None = None
        self._key_id_index_loaded_at: float = 0.0
        self._key_id_index_ids: frozenset[str] = frozenset()
        self._key_id_index_lock = asyncio.Lock()

    def set_observer(self, observer: ApiKeyCacheObserver | None) -> None:
        self._observer = observer

    @property
    def backend(self) -> UserDirectory:
        """The wrapped backend, for callers that need it (e.g. readiness checks)."""
        return self._backend

    def invalidate_local(self) -> None:
        self._cache.clear()
        self._api_key_cache.clear()
        self._verified_key_ids.clear()
        self._key_id_index_revision = None
        self._key_id_index_ids = frozenset()
        self._key_id_index_loaded_at = 0.0

    async def resolve(self, email: str, *, critical: bool = False) -> UserResolveResult:
        normalized = normalize_subject(email)
        revision = await self._revision_reader.current()
        await self._sync_revision(revision)

        cached = self._cache.get(
            normalized,
            revision=revision,
            bypass_allow_cache=critical,
        )
        if cached is not None:
            return cached

        if self._circuit.is_open():
            raise UserDirectoryUnavailableError(
                "users directory circuit breaker is open",
                code="circuit_open",
            )

        try:
            result = await self._backend.resolve_user(normalized)
        except UserDirectoryUnavailableError:
            self._circuit.record_failure()
            raise
        except (httpx.HTTPError, OSError) as exc:
            self._circuit.record_failure()
            raise UserDirectoryUnavailableError(
                "users directory is unavailable",
                code="catalog_unavailable",
            ) from exc

        self._circuit.record_success()
        fresh = UserResolveResult(
            exists=result.exists,
            roles=result.roles,
            is_blocked=result.is_blocked,
            subject_type=result.subject_type,
            from_cache=False,
            revision=revision,
        )
        self._cache.put(normalized, fresh, revision=revision)
        return fresh

    async def _sync_revision(self, revision: int) -> None:
        if self._seen_revision is None:
            self._seen_revision = revision
            return
        if revision != self._seen_revision:
            self.invalidate_local()
            self._seen_revision = revision

    def _record_outcome(self, outcome: str) -> None:
        if self._observer is not None:
            self._observer.record_api_key_verification(outcome)

    def _flush_cache_metrics(self) -> None:
        if self._observer is None:
            return
        self._observer.set_api_key_cache_size("positive", self._api_key_cache.positive_size)
        self._observer.set_api_key_cache_size("negative", self._api_key_cache.negative_size)
        pos_ev, neg_ev = self._api_key_cache.drain_eviction_counts()
        if pos_ev:
            self._observer.record_api_key_cache_evictions("positive", pos_ev)
        if neg_ev:
            self._observer.record_api_key_cache_evictions("negative", neg_ev)

    def _remember_verified_key_id(self, key_id: str) -> None:
        self._verified_key_ids[key_id] = None
        self._verified_key_ids.move_to_end(key_id)
        while len(self._verified_key_ids) > _VERIFIED_KEY_ID_MAX:
            self._verified_key_ids.popitem(last=False)

    async def _ensure_key_id_index(
        self,
        *,
        revision: int,
        allow_ttl: float,
        now: float | None = None,
    ) -> frozenset[str]:
        if not isinstance(self._backend, ApiKeyIdIndex):
            return frozenset()
        mono = time.monotonic() if now is None else now
        stale_revision = self._key_id_index_revision != revision
        stale_ttl = mono - self._key_id_index_loaded_at >= allow_ttl
        if not stale_revision and not stale_ttl and self._key_id_index_revision is not None:
            return self._key_id_index_ids

        async with self._key_id_index_lock:
            stale_revision = self._key_id_index_revision != revision
            stale_ttl = mono - self._key_id_index_loaded_at >= allow_ttl
            if not stale_revision and not stale_ttl and self._key_id_index_revision is not None:
                return self._key_id_index_ids
            try:
                ids = await self._backend.active_api_key_ids()
            except UserDirectoryUnavailableError:
                self._circuit.record_failure()
                raise
            except (httpx.HTTPError, OSError) as exc:
                self._circuit.record_failure()
                raise UserDirectoryUnavailableError(
                    "users directory is unavailable",
                    code="catalog_unavailable",
                ) from exc
            self._key_id_index_revision = revision
            self._key_id_index_loaded_at = mono
            self._key_id_index_ids = ids
            return ids

    async def api_key_state(self, key_id: str, *, subject: str) -> ApiKeyState:
        if "api_keys" not in self._backend.capabilities:
            return "unknown"
        if not isinstance(self._backend, ApiKeyDirectory):
            return "unknown"

        if self._circuit.is_open():
            raise UserDirectoryUnavailableError(
                "users directory circuit breaker is open",
                code="circuit_open",
            )

        normalized = normalize_email(subject)
        try:
            rows = await self._backend.list_api_keys(subject=subject, include_revoked=True)
        except UserDirectoryUnavailableError:
            self._circuit.record_failure()
            raise
        except (httpx.HTTPError, OSError) as exc:
            self._circuit.record_failure()
            raise UserDirectoryUnavailableError(
                "users directory is unavailable",
                code="catalog_unavailable",
            ) from exc

        self._circuit.record_success()
        record = next((row for row in rows if row.key_id == key_id), None)
        if record is None or normalize_email(record.subject) != normalized:
            return "unknown"
        if record.revoked_at is not None:
            return "revoked"
        if record.expires_at is not None:
            from keystone_mcp.users.models import utcnow

            if record.expires_at <= utcnow():
                return "expired"
        return "active"

    async def verify_api_key(
        self, key: str, *, now: float | None = None
    ) -> ApiKeyVerification | None:
        if "api_keys" not in self._backend.capabilities:
            return None
        if not isinstance(self._backend, ApiKeyDirectory):
            return None

        parsed = parse_api_key(key)
        if parsed is None:
            self._record_outcome("malformed")
            return None
        key_id, _secret = parsed

        revision = await self._revision_reader.current()
        await self._sync_revision(revision)
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()

        positive = self._api_key_cache.get_positive(digest, revision=revision, now=now)
        if positive is not None:
            self._record_outcome("valid")
            return positive

        has_index = isinstance(self._backend, ApiKeyIdIndex)
        if has_index:
            allow_ttl = self._api_key_cache._allow_ttl  # noqa: SLF001
            index_ids = await self._ensure_key_id_index(
                revision=revision,
                allow_ttl=allow_ttl,
                now=now,
            )
            if key_id not in index_ids:
                self._record_outcome("unknown_key_id")
                self._flush_cache_metrics()
                return None
        else:
            if self._api_key_cache.get_negative(digest, revision=revision, now=now):
                self._record_outcome("invalid")
                return None
            if key_id not in self._verified_key_ids and not self._unknown_key_limiter.allow(
                now=now
            ):
                self._record_outcome("limited")
                return None

        if self._circuit.is_open():
            self._record_outcome("unavailable")
            raise UserDirectoryUnavailableError(
                "users directory circuit breaker is open",
                code="circuit_open",
            )

        try:
            result = await self._backend.verify_api_key(key)
        except UserDirectoryUnavailableError:
            self._circuit.record_failure()
            self._record_outcome("unavailable")
            raise
        except (httpx.HTTPError, OSError) as exc:
            self._circuit.record_failure()
            self._record_outcome("unavailable")
            raise UserDirectoryUnavailableError(
                "users directory is unavailable",
                code="catalog_unavailable",
            ) from exc

        self._circuit.record_success()
        if result is not None:
            self._api_key_cache.put_positive(digest, result, revision=revision, now=now)
            self._remember_verified_key_id(key_id)
            self._record_outcome("valid")
        else:
            if not has_index:
                self._api_key_cache.put_negative(digest, revision=revision, now=now)
            self._record_outcome("invalid")
        self._flush_cache_metrics()
        return result

    async def aclose(self) -> None:
        await self._backend.aclose()
        await self._revision_reader.aclose()
