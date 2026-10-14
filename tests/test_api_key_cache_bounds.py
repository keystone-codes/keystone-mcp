"""Bounded API key verification caches and resolver guardrails."""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass, field
from unittest.mock import AsyncMock

import pytest

from keystone_mcp.user_directory.cache import (
    _PURGE_INTERVAL_SECONDS,
    API_KEY_NEGATIVE_CACHE_MAX,
    RESOLUTION_CACHE_MAX,
    ApiKeyVerificationCache,
    ResolutionCache,
)
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker
from keystone_mcp.user_directory.resolver import CachedUserDirectoryResolver
from keystone_mcp.user_directory.revision import InMemoryRevisionReader
from keystone_mcp.user_directory.types import (
    ApiKeyVerification,
    UserResolveResult,
    format_api_key,
    generate_api_key_material,
)


@dataclass
class _RecordingObserver:
    outcomes: list[str] = field(default_factory=list)

    def record_api_key_verification(self, outcome: str) -> None:
        self.outcomes.append(outcome)

    def set_api_key_cache_size(self, cache: str, size: int) -> None:
        pass

    def record_api_key_cache_evictions(self, cache: str, count: int) -> None:
        pass


class _CountingApiKeyBackend:
    """Minimal ``ApiKeyDirectory`` test double."""

    name = "counting"

    def __init__(self) -> None:
        self.verify_calls = 0

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"api_keys"})

    async def resolve_user(self, subject: str) -> UserResolveResult:
        return UserResolveResult(
            exists=False,
            roles=(),
            is_blocked=False,
            subject_type="human",
        )

    async def list_users(
        self,
        *,
        is_blocked: bool | None = False,
        role: str | None = None,
        email_contains: str | None = None,
    ) -> list:
        return []

    async def ping(self) -> None:
        return None

    async def aclose(self) -> None:
        return None

    async def issue_api_key(self, **_kwargs):
        raise NotImplementedError

    async def list_api_keys(self, **_kwargs) -> list:
        return []

    async def revoke_api_key(self, **_kwargs):
        raise NotImplementedError

    async def verify_api_key(self, key: str) -> ApiKeyVerification | None:
        self.verify_calls += 1
        return None


class _CountingApiKeyBackendWithIndex(_CountingApiKeyBackend):
    def __init__(self) -> None:
        super().__init__()
        self.index_calls = 0
        self._index_ids: frozenset[str] = frozenset()

    async def active_api_key_ids(self) -> frozenset[str]:
        self.index_calls += 1
        return self._index_ids

    def set_index_ids(self, ids: frozenset[str]) -> None:
        self._index_ids = ids


def _resolver(
    backend: _CountingApiKeyBackend | _CountingApiKeyBackendWithIndex,
    *,
    allow_ttl: float = 60.0,
    deny_ttl: float = 30.0,
) -> CachedUserDirectoryResolver:
    revision = InMemoryRevisionReader()
    cache = ResolutionCache(allow_ttl_seconds=allow_ttl, deny_ttl_seconds=deny_ttl)
    api_key_cache = ApiKeyVerificationCache(
        allow_ttl_seconds=allow_ttl,
        deny_ttl_seconds=deny_ttl,
    )
    resolver = CachedUserDirectoryResolver(
        backend,
        revision_reader=revision,
        cache=cache,
        circuit_breaker=CircuitBreaker(failure_threshold=5, recovery_seconds=30.0),
        api_key_cache=api_key_cache,
    )
    resolver.set_observer(_RecordingObserver())
    return resolver


def _wellformed_random_key() -> str:
    key_id, secret, full = generate_api_key_material()
    return full


@pytest.mark.asyncio
async def test_malformed_key_never_reaches_directory_or_cache() -> None:
    backend = _CountingApiKeyBackend()
    resolver = _resolver(backend)
    observer = resolver._observer  # noqa: SLF001
    assert isinstance(observer, _RecordingObserver)

    samples = [
        "ksk_" + secrets.token_hex(20),
        "ksk_zz" + "a" * 40,
        "",
    ]
    for sample in samples:
        assert await resolver.verify_api_key(sample) is None
        assert observer.outcomes[-1] == "malformed"

    assert backend.verify_calls == 0
    assert resolver._api_key_cache.positive_size == 0  # noqa: SLF001
    assert resolver._api_key_cache.negative_size == 0  # noqa: SLF001


@pytest.mark.asyncio
async def test_random_wellformed_keys_keep_caches_bounded() -> None:
    backend = _CountingApiKeyBackend()
    resolver = _resolver(backend, deny_ttl=3600.0)
    t0 = 0.0
    for i in range(50_000):
        await resolver.verify_api_key(_wellformed_random_key(), now=t0 + i * 0.1)

    assert resolver._api_key_cache.negative_size <= API_KEY_NEGATIVE_CACHE_MAX  # noqa: SLF001
    assert resolver._api_key_cache.positive_size == 0  # noqa: SLF001
    assert resolver._api_key_cache.negative_evictions > 0  # noqa: SLF001


@pytest.mark.asyncio
async def test_ci_key_keeps_working_during_garbage_flood(tmp_path) -> None:
    from keystone_mcp.config import Settings
    from keystone_mcp.user_directory.factory import build_user_directory_resolver
    from keystone_mcp.user_directory.local import LocalUserDirectory
    from keystone_mcp.users import service
    from keystone_mcp.users.db import make_session_factory, session_scope
    from support.users_store import make_users_store

    store, revision = await make_users_store(tmp_path)
    directory = LocalUserDirectory(store)
    settings = Settings(base_url="http://localhost:8080", redis_url="")
    resolver = build_user_directory_resolver(
        settings,
        directory=directory,
        revision_reader=revision,
    )
    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_user(
            session,
            email="svc-bot@example.com",
            full_name="Bot",
            roles=["member"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )
        _row, real_key = service.issue_api_key(
            session,
            subject="svc-bot@example.com",
            label=None,
            expires_in_days=90,
            created_by="test",
        )

    for i in range(50_000):
        await resolver.verify_api_key(_wellformed_random_key())
        if i % 1000 == 999:
            assert await resolver.verify_api_key(real_key) is not None


@pytest.mark.asyncio
async def test_ci_key_survives_allow_ttl_expiry_mid_flood(tmp_path) -> None:
    from keystone_mcp.config import Settings
    from keystone_mcp.user_directory.factory import build_user_directory_resolver
    from keystone_mcp.user_directory.local import LocalUserDirectory
    from keystone_mcp.users import service
    from keystone_mcp.users.db import make_session_factory, session_scope
    from support.users_store import make_users_store

    store, revision = await make_users_store(tmp_path)
    directory = LocalUserDirectory(store)
    settings = Settings(base_url="http://localhost:8080", redis_url="")
    resolver = build_user_directory_resolver(
        settings,
        directory=directory,
        revision_reader=revision,
    )
    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_user(
            session,
            email="svc-bot@example.com",
            full_name="Bot",
            roles=["member"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )
        _row, real_key = service.issue_api_key(
            session,
            subject="svc-bot@example.com",
            label=None,
            expires_in_days=90,
            created_by="test",
        )

    t0 = 1000.0
    assert await resolver.verify_api_key(real_key, now=t0) is not None
    allow_ttl = resolver._api_key_cache._allow_ttl  # noqa: SLF001
    mid = t0 + allow_ttl + 1.0
    for i in range(5000):
        await resolver.verify_api_key(_wellformed_random_key(), now=mid + i * 0.001)
        if i % 500 == 499:
            assert await resolver.verify_api_key(real_key, now=mid + i * 0.001) is not None


@pytest.mark.asyncio
async def test_unknown_key_id_with_index_never_calls_directory() -> None:
    backend = _CountingApiKeyBackendWithIndex()
    backend.set_index_ids(frozenset())
    resolver = _resolver(backend)
    observer = resolver._observer  # noqa: SLF001
    assert isinstance(observer, _RecordingObserver)

    for _ in range(10_000):
        await resolver.verify_api_key(_wellformed_random_key())
        assert observer.outcomes[-1] == "unknown_key_id"

    assert backend.verify_calls == 0
    assert backend.index_calls >= 1
    assert resolver._api_key_cache.positive_size == 0  # noqa: SLF001
    assert resolver._api_key_cache.negative_size == 0  # noqa: SLF001


@pytest.mark.asyncio
async def test_known_key_id_with_wrong_secret_does_not_block_real_key(tmp_path) -> None:
    from keystone_mcp.config import Settings
    from keystone_mcp.user_directory.factory import build_user_directory_resolver
    from keystone_mcp.user_directory.local import LocalUserDirectory
    from keystone_mcp.users import service
    from keystone_mcp.users.db import make_session_factory, session_scope
    from support.users_store import make_users_store

    store, revision = await make_users_store(tmp_path)
    directory = LocalUserDirectory(store)
    settings = Settings(base_url="http://localhost:8080", redis_url="")
    resolver = build_user_directory_resolver(
        settings,
        directory=directory,
        revision_reader=revision,
    )

    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_user(
            session,
            email="alice@example.com",
            full_name="Alice",
            roles=["member"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )
        row, real_key = service.issue_api_key(
            session,
            subject="alice@example.com",
            label=None,
            expires_in_days=90,
            created_by="test",
        )

    for _ in range(10_000):
        wrong = format_api_key(row.key_id, secrets.token_urlsafe(32)[:43])
        await resolver.verify_api_key(wrong)

    resolver._api_key_cache.clear()  # noqa: SLF001
    assert await resolver.verify_api_key(real_key) is not None
    assert resolver._api_key_cache.negative_size <= API_KEY_NEGATIVE_CACHE_MAX  # noqa: SLF001


@pytest.mark.asyncio
async def test_expired_entries_are_purged() -> None:
    cache = ApiKeyVerificationCache(allow_ttl_seconds=1.0, deny_ttl_seconds=1.0)
    revision = 1
    t0 = 100.0
    cache.put_negative("digest", revision=revision, now=t0)
    assert cache.negative_size == 1
    cache.put_negative("digest2", revision=revision, now=t0 + _PURGE_INTERVAL_SECONDS + 1)
    assert cache.negative_size == 1


@pytest.mark.asyncio
async def test_key_id_index_refreshes_on_revision_change() -> None:
    backend = _CountingApiKeyBackendWithIndex()
    backend.set_index_ids(frozenset())
    revision = InMemoryRevisionReader()
    resolver = _resolver(backend)
    resolver._revision_reader = revision  # noqa: SLF001

    key_id, secret, full = generate_api_key_material()
    await resolver.verify_api_key(full)
    assert backend.index_calls == 1

    backend.set_index_ids(frozenset({key_id}))
    revision.bump()
    verification = ApiKeyVerification(
        key_id=key_id,
        subject="svc:bot",
        subject_type="service",
        expires_at=None,
    )
    backend.verify_api_key = AsyncMock(return_value=verification)  # type: ignore[method-assign]
    assert await resolver.verify_api_key(full) is not None


@pytest.mark.asyncio
async def test_key_id_index_refreshes_after_allow_ttl() -> None:
    backend = _CountingApiKeyBackendWithIndex()
    key_id, _secret, full = generate_api_key_material()
    backend.set_index_ids(frozenset())
    revision = InMemoryRevisionReader()
    resolver = _resolver(backend, allow_ttl=5.0)
    resolver._revision_reader = revision  # noqa: SLF001

    t0 = 200.0
    await resolver.verify_api_key(full, now=t0)
    calls_after_first = backend.index_calls

    backend.set_index_ids(frozenset({key_id}))
    verification = ApiKeyVerification(
        key_id=key_id,
        subject="svc:bot",
        subject_type="service",
        expires_at=None,
    )
    backend.verify_api_key = AsyncMock(return_value=verification)  # type: ignore[method-assign]
    await resolver.verify_api_key(full, now=t0 + 6.0)
    assert backend.index_calls > calls_after_first
    assert await resolver.verify_api_key(full, now=t0 + 6.0) is not None


@pytest.mark.asyncio
async def test_key_id_index_is_loaded_once_for_concurrent_callers() -> None:
    backend = _CountingApiKeyBackendWithIndex()
    backend.set_index_ids(frozenset())
    resolver = _resolver(backend)

    async def _one() -> None:
        await resolver.verify_api_key(_wellformed_random_key())

    await asyncio.gather(*(_one() for _ in range(50)))
    assert backend.index_calls == 1


@pytest.mark.asyncio
async def test_fallback_limiter_applies_only_to_never_verified_key_ids() -> None:
    backend = _CountingApiKeyBackend()
    resolver = _resolver(backend)
    observer = resolver._observer  # noqa: SLF001
    assert isinstance(observer, _RecordingObserver)

    key_id, _secret, full = generate_api_key_material()
    verification = ApiKeyVerification(
        key_id=key_id,
        subject="svc:bot",
        subject_type="service",
        expires_at=None,
    )
    backend.verify_api_key = AsyncMock(return_value=verification)  # type: ignore[method-assign]
    assert await resolver.verify_api_key(full) is not None

    t0 = 5000.0
    for i in range(200):
        await resolver.verify_api_key(_wellformed_random_key(), now=t0 + i * 0.01)

    assert "limited" in observer.outcomes

    backend.verify_api_key = AsyncMock(return_value=verification)  # type: ignore[method-assign]
    assert await resolver.verify_api_key(full) is not None


@pytest.mark.asyncio
async def test_resolution_cache_is_bounded() -> None:
    revision = InMemoryRevisionReader()
    cache = ResolutionCache(allow_ttl_seconds=60.0, deny_ttl_seconds=30.0)
    rev = await revision.current()
    for i in range(60_000):
        result = UserResolveResult(
            exists=True,
            roles=("member",),
            is_blocked=False,
            subject_type="human",
            from_cache=False,
            revision=rev,
        )
        cache.put(f"user{i}@example.com", result, revision=rev)
    assert len(cache) <= RESOLUTION_CACHE_MAX
