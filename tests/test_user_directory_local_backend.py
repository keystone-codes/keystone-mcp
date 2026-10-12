"""Tests for the built-in (local) users directory backend and its wiring."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from keystone_mcp.config import Settings
from keystone_mcp.user_directory.cache import ResolutionCache
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker
from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.factory import build_user_directory_resolver
from keystone_mcp.user_directory.http import HttpUserDirectory
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.resolver import CachedUserDirectoryResolver
from keystone_mcp.user_directory.revision import InMemoryRevisionReader, RedisRevisionReader
from keystone_mcp.users.db import create_users_engine
from keystone_mcp.users.revision import NullRevisionWriter, RedisRevisionWriter
from keystone_mcp.users.store import UsersStore
from support.users_store import make_users_store


def test_factory_builds_local_backend_by_default(monkeypatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "local")
    settings = Settings()
    resolver = build_user_directory_resolver(settings, revision_reader=InMemoryRevisionReader())
    assert isinstance(resolver, CachedUserDirectoryResolver)
    assert isinstance(resolver._backend, LocalUserDirectory)


def test_factory_builds_http_backend_when_configured(monkeypatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "http")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_URL", "http://mcp-users:8080")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_TOKEN", "token")
    settings = Settings()
    resolver = build_user_directory_resolver(settings, revision_reader=InMemoryRevisionReader())
    assert isinstance(resolver._backend, HttpUserDirectory)


@pytest.mark.asyncio
async def test_local_backend_resolves_existing_and_unknown_user(tmp_path: Path) -> None:
    store, _ = await make_users_store(tmp_path)
    await store.create_user(
        email="user@example.com",
        full_name="User",
        roles=["operator"],
        note=None,
        created_by=None,
        allowed_roles=None,
    )
    backend = LocalUserDirectory(store)

    known = await backend.resolve_user("user@example.com")
    assert known.exists is True
    assert known.roles == ("operator",)
    assert known.is_blocked is False

    unknown = await backend.resolve_user("nobody@example.com")
    assert unknown.exists is False
    assert unknown.roles == ()

    await backend.aclose()
    store.dispose()


def _resolver_for(store: UsersStore, revision) -> CachedUserDirectoryResolver:  # noqa: ANN001
    return CachedUserDirectoryResolver(
        LocalUserDirectory(store),
        revision_reader=revision,
        cache=ResolutionCache(allow_ttl_seconds=60.0, deny_ttl_seconds=30.0),
        circuit_breaker=CircuitBreaker(failure_threshold=3, recovery_seconds=30.0),
    )


@pytest.mark.asyncio
async def test_block_through_store_is_visible_immediately(tmp_path: Path) -> None:
    store, revision = await make_users_store(tmp_path)
    await store.create_user(
        email="user@example.com",
        full_name="User",
        roles=["operator"],
        note=None,
        created_by=None,
        allowed_roles=None,
    )
    resolver = _resolver_for(store, revision)

    allowed = await resolver.resolve("user@example.com")
    assert allowed.is_allow_decision is True
    assert allowed.from_cache is False

    cached = await resolver.resolve("user@example.com")
    assert cached.from_cache is True

    await store.set_blocked(
        email="user@example.com", blocked=True, actor_email="someone@example.com"
    )

    refreshed = await resolver.resolve("user@example.com")
    assert refreshed.is_blocked is True
    assert refreshed.from_cache is False

    store.dispose()


@pytest.mark.asyncio
async def test_block_visible_through_redis_revision(tmp_path: Path) -> None:
    redis_url = os.environ.get("KEYSTONE_MCP_REDIS_URL")
    if not redis_url:
        pytest.skip("KEYSTONE_MCP_REDIS_URL is not set; skipping Redis-backed revision test")

    from redis.asyncio import Redis

    key = f"km:users:revision:test:{uuid.uuid4()}"
    engine = create_users_engine(f"sqlite:///{tmp_path}/keystone-users.db")
    store = UsersStore(engine, revision=RedisRevisionWriter(redis_url, key=key))
    await store.migrate()
    await store.create_user(
        email="user@example.com",
        full_name="User",
        roles=["operator"],
        note=None,
        created_by=None,
        allowed_roles=None,
    )

    redis_client = Redis.from_url(redis_url, decode_responses=True)
    reader = RedisRevisionReader(redis_client, key=key, owns_client=True)
    resolver = _resolver_for(store, reader)

    allowed = await resolver.resolve("user@example.com")
    assert allowed.is_allow_decision is True

    await store.set_blocked(
        email="user@example.com", blocked=True, actor_email="someone@example.com"
    )

    refreshed = await resolver.resolve("user@example.com")
    assert refreshed.is_blocked is True
    assert refreshed.from_cache is False

    await resolver.aclose()
    store.dispose()


@pytest.mark.asyncio
async def test_database_failure_is_fail_closed() -> None:
    engine = create_users_engine("postgresql+psycopg://u:pass@127.0.0.1:1/db")
    store = UsersStore(engine, revision=NullRevisionWriter())
    resolver = CachedUserDirectoryResolver(
        LocalUserDirectory(store),
        revision_reader=InMemoryRevisionReader(),
        cache=ResolutionCache(allow_ttl_seconds=60.0, deny_ttl_seconds=30.0),
        circuit_breaker=CircuitBreaker(failure_threshold=1, recovery_seconds=30.0),
    )

    with pytest.raises(UserDirectoryUnavailableError) as first:
        await resolver.resolve("user@example.com")
    assert first.value.code == "catalog_unavailable"

    with pytest.raises(UserDirectoryUnavailableError) as second:
        await resolver.resolve("user@example.com")
    assert second.value.code == "circuit_open"

    store.dispose()
