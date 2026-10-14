"""ApiKeyStateReader and CachedUserDirectoryResolver.api_key_state."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.protocol import ApiKeyStateReader
from keystone_mcp.user_directory.resolver import CachedUserDirectoryResolver
from keystone_mcp.users import service
from keystone_mcp.users.db import make_session_factory, session_scope
from keystone_mcp.users.models import utcnow
from support.users_store import make_users_store


@pytest.mark.asyncio
async def test_api_key_state_active_revoked_expired(tmp_path) -> None:
    store, revision = await make_users_store(tmp_path)
    directory = LocalUserDirectory(store)
    from keystone_mcp.config import Settings
    from keystone_mcp.user_directory.factory import build_user_directory_resolver

    resolver = build_user_directory_resolver(
        Settings(users_backend="local"),
        directory=directory,
        revision_reader=revision,
    )
    assert isinstance(resolver, ApiKeyStateReader)

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
        row_active, _ = service.issue_api_key(
            session,
            subject="alice@example.com",
            label=None,
            expires_in_days=90,
            created_by="test",
        )
        row_revoked, _ = service.issue_api_key(
            session,
            subject="alice@example.com",
            label=None,
            expires_in_days=90,
            created_by="test",
        )
        service.revoke_api_key(session, key_id=row_revoked.key_id, actor="test")
        row_expired, _ = service.issue_api_key(
            session,
            subject="alice@example.com",
            label=None,
            expires_in_days=1,
            created_by="test",
        )
        row_expired.expires_at = utcnow() - timedelta(seconds=1)
        session.add(row_expired)

    assert await resolver.api_key_state(row_active.key_id, subject="alice@example.com") == "active"
    assert (
        await resolver.api_key_state(row_revoked.key_id, subject="alice@example.com") == "revoked"
    )
    assert (
        await resolver.api_key_state(row_expired.key_id, subject="alice@example.com") == "expired"
    )


@pytest.mark.asyncio
async def test_api_key_state_unknown_wrong_subject_or_missing(tmp_path) -> None:
    store, revision = await make_users_store(tmp_path)
    directory = LocalUserDirectory(store)
    from keystone_mcp.config import Settings
    from keystone_mcp.user_directory.factory import build_user_directory_resolver

    resolver = build_user_directory_resolver(
        Settings(users_backend="local"),
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
        row, _ = service.issue_api_key(
            session,
            subject="alice@example.com",
            label=None,
            expires_in_days=90,
            created_by="test",
        )

    assert await resolver.api_key_state("000000000000", subject="alice@example.com") == "unknown"
    assert await resolver.api_key_state(row.key_id, subject="bob@example.com") == "unknown"


@pytest.mark.asyncio
async def test_api_key_state_without_api_keys_capability() -> None:
    from keystone_mcp.user_directory.memory import InMemoryUserDirectoryBackend

    backend = InMemoryUserDirectoryBackend()
    backend.seed("u@example.com", roles=("member",))
    resolver = CachedUserDirectoryResolver(
        backend,
        revision_reader=__import__(
            "keystone_mcp.user_directory.revision", fromlist=["InMemoryRevisionReader"]
        ).InMemoryRevisionReader(),
        cache=__import__(
            "keystone_mcp.user_directory.cache", fromlist=["ResolutionCache"]
        ).ResolutionCache(allow_ttl_seconds=60, deny_ttl_seconds=60),
        circuit_breaker=__import__(
            "keystone_mcp.user_directory.circuit_breaker", fromlist=["CircuitBreaker"]
        ).CircuitBreaker(failure_threshold=3, recovery_seconds=30),
    )
    assert await resolver.api_key_state("abc", subject="u@example.com") == "unknown"


@pytest.mark.asyncio
async def test_api_key_state_directory_failure_opens_circuit(tmp_path) -> None:
    store, revision = await make_users_store(tmp_path)

    from keystone_mcp.user_directory.cache import ResolutionCache
    from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker

    class _BrokenDirectory(LocalUserDirectory):
        async def list_api_keys(self, **kwargs):  # noqa: ANN003
            raise httpx.ConnectError("down")

    broken = _BrokenDirectory(store)
    resolver2 = CachedUserDirectoryResolver(
        broken,
        revision_reader=revision,
        cache=ResolutionCache(allow_ttl_seconds=60, deny_ttl_seconds=60),
        circuit_breaker=CircuitBreaker(failure_threshold=1, recovery_seconds=30),
    )
    with pytest.raises(UserDirectoryUnavailableError) as exc:
        await resolver2.api_key_state("x", subject="a@example.com")
    assert exc.value.code == "catalog_unavailable"
    assert resolver2._circuit.is_open()  # noqa: SLF001
