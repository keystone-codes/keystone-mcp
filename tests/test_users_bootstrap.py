"""Tests for keystone_mcp.users.bootstrap: migrate + seed on startup."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from keystone_mcp.config import Settings
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from keystone_mcp.server import bootstrap_platform
from keystone_mcp.users.bootstrap import UsersBootstrapError, bootstrap_users_store
from keystone_mcp.users.db import create_users_engine
from keystone_mcp.users.revision import NullRevisionWriter
from keystone_mcp.users.store import UsersStore
from support.users_store import make_users_store


def _settings(*, tmp_path: Path, superadmin_email: str = "") -> Settings:
    return Settings(
        users_db_url=f"sqlite:///{tmp_path}/keystone-users.db",
        superadmin_email=superadmin_email,
    )


@pytest.mark.asyncio
async def test_start_on_empty_database_creates_first_administrator(tmp_path: Path) -> None:
    store, revision = await make_users_store(tmp_path)
    settings = _settings(tmp_path=tmp_path, superadmin_email="Admin@Example.com")

    await bootstrap_users_store(store, settings)

    resolved = await store.resolve("admin@example.com")
    assert resolved.exists is True
    assert resolved.roles == ("administrator",)
    assert await revision.current() == 1
    store.dispose()


@pytest.mark.asyncio
async def test_second_start_is_idempotent(tmp_path: Path) -> None:
    store, revision = await make_users_store(tmp_path)
    settings = _settings(tmp_path=tmp_path, superadmin_email="admin@example.com")

    await bootstrap_users_store(store, settings)
    assert await revision.current() == 1

    await bootstrap_users_store(store, settings)
    assert await revision.current() == 1

    users = await store.list_users(is_blocked=None)
    assert len(users) == 1
    store.dispose()


@pytest.mark.asyncio
async def test_start_without_superadmin_on_empty_database_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store, _ = await make_users_store(tmp_path)
    settings = _settings(tmp_path=tmp_path, superadmin_email="")

    with caplog.at_level(logging.WARNING):
        await bootstrap_users_store(store, settings)

    assert any("no active administrator" in record.message for record in caplog.records)
    store.dispose()


@pytest.mark.asyncio
async def test_blocked_superadmin_is_not_unblocked_and_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store, _ = await make_users_store(tmp_path)
    settings = _settings(tmp_path=tmp_path, superadmin_email="admin@example.com")
    await bootstrap_users_store(store, settings)
    # A second administrator so blocking the seeded one does not trip the
    # last-administrator guard (that invariant is covered elsewhere).
    await store.create_user(
        email="other@example.com",
        full_name="Other Admin",
        roles=["administrator"],
        note=None,
        created_by=None,
        allowed_roles=None,
    )
    await store.set_blocked(
        email="admin@example.com", blocked=True, actor_email="other@example.com"
    )

    with caplog.at_level(logging.WARNING):
        await bootstrap_users_store(store, settings)

    resolved = await store.resolve("admin@example.com")
    assert resolved.is_blocked is True
    assert any("is blocked" in record.message for record in caplog.records)
    store.dispose()


@pytest.mark.asyncio
async def test_unreachable_database_fails_with_redacted_url() -> None:
    engine = create_users_engine("postgresql+psycopg://u:secret@127.0.0.1:1/db")
    store = UsersStore(engine, revision=NullRevisionWriter())
    settings = Settings(
        users_db_url="postgresql+psycopg://u:secret@127.0.0.1:1/db",
        superadmin_email="",
    )

    with pytest.raises(UsersBootstrapError) as exc_info:
        await bootstrap_users_store(store, settings)

    message = str(exc_info.value)
    assert "***" in message
    assert "secret" not in message
    store.dispose()


@pytest.mark.asyncio
async def test_bootstrap_platform_runs_users_bootstrap(tmp_path: Path) -> None:
    store, revision = await make_users_store(tmp_path)
    settings = _settings(tmp_path=tmp_path, superadmin_email="admin@example.com")
    registry = RouterRegistry(RouterEngine(settings))
    upstreams = UpstreamRegistry(
        main_mcp=None,
        registry=registry,
        tool_timeout_seconds=5.0,
        discovery_timeout_seconds=5.0,
    )

    await bootstrap_platform(upstreams, registry, settings, None, users_store=store)

    resolved = await store.resolve("admin@example.com")
    assert resolved.exists is True
    assert await revision.current() == 1
    store.dispose()
