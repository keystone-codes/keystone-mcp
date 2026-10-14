"""Local resolver cache invalidation when revision bump fails."""

from __future__ import annotations

import pytest
from redis.exceptions import RedisError

from keystone_mcp.config import Settings
from keystone_mcp.observability.metrics import _USERS_REVISION_BUMP_FAILED
from keystone_mcp.observability.service import RbacObservability
from keystone_mcp.user_directory.cache import ApiKeyVerificationCache, ResolutionCache
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.resolver import CachedUserDirectoryResolver
from keystone_mcp.user_directory.revision import InMemoryRevisionReader
from keystone_mcp.users import service
from keystone_mcp.users.db import make_session_factory, session_scope
from support.users_store import make_users_store


class _FailingRevisionWriter:
    async def bump(self) -> int:
        raise RedisError("simulated incr failure")


@pytest.mark.asyncio
async def test_local_resolver_sees_block_immediately_when_incr_fails(tmp_path) -> None:
    engine_store, _reader_unused = await make_users_store(tmp_path)
    store = engine_store
    store._revision = _FailingRevisionWriter()  # noqa: SLF001

    directory = LocalUserDirectory(store)
    revision = InMemoryRevisionReader()
    resolver = CachedUserDirectoryResolver(
        directory,
        revision_reader=revision,
        cache=ResolutionCache(allow_ttl_seconds=60.0, deny_ttl_seconds=30.0),
        circuit_breaker=CircuitBreaker(failure_threshold=5, recovery_seconds=30.0),
        api_key_cache=ApiKeyVerificationCache(allow_ttl_seconds=60.0, deny_ttl_seconds=30.0),
    )

    def _on_change(bump_ok: bool) -> None:
        resolver.invalidate_local()

    store.add_change_listener(_on_change)

    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        mutation = service.create_service_account(
            session,
            name="worker",
            description=None,
            roles=["member"],
            created_by="admin",
        )
        subject = f"svc:{mutation.account.name}"

    first = await resolver.resolve(subject)
    assert first.exists
    assert not first.is_blocked

    await store.update_service_account(name="worker", is_blocked=True, actor="admin")

    second = await resolver.resolve(subject)
    assert second.is_blocked


@pytest.mark.asyncio
async def test_bump_failure_increments_metric(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_METRICS_ENABLED", "true")
    settings = Settings(base_url="http://localhost:8080", redis_url="")
    observability = RbacObservability(settings)

    before = _USERS_REVISION_BUMP_FAILED._value.get()  # noqa: SLF001

    store, _ = await make_users_store(tmp_path)
    store._revision = _FailingRevisionWriter()  # noqa: SLF001
    directory = LocalUserDirectory(store)
    revision = InMemoryRevisionReader()
    resolver = CachedUserDirectoryResolver(
        directory,
        revision_reader=revision,
        cache=ResolutionCache(allow_ttl_seconds=60.0, deny_ttl_seconds=30.0),
        circuit_breaker=CircuitBreaker(failure_threshold=5, recovery_seconds=30.0),
    )

    def _on_change(bump_ok: bool) -> None:
        resolver.invalidate_local()
        if not bump_ok:
            observability.record_users_revision_bump_failed()

    store.add_change_listener(_on_change)

    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_user(
            session,
            email="bob@example.com",
            full_name="Bob",
            roles=["member"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )

    await store.set_blocked(
        email="bob@example.com",
        blocked=True,
        actor_email="admin@example.com",
    )

    after = _USERS_REVISION_BUMP_FAILED._value.get()  # noqa: SLF001
    assert after == before + 1.0


@pytest.mark.asyncio
async def test_listener_error_does_not_fail_mutation(tmp_path) -> None:
    store, _ = await make_users_store(tmp_path)

    def _bad_listener(_ok: bool) -> None:
        raise RuntimeError("listener broke")

    store.add_change_listener(_bad_listener)

    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_user(
            session,
            email="carol@example.com",
            full_name="Carol",
            roles=["member"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )

    result = await store.set_blocked(
        email="carol@example.com",
        blocked=True,
        actor_email="admin@example.com",
    )
    assert result.changed
