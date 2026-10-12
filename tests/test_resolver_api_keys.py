"""Cached resolver behaviour for directory API keys."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from keystone_mcp.config import Settings
from keystone_mcp.user_directory.factory import build_user_directory_resolver
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from keystone_mcp.users import service
from keystone_mcp.users.db import make_session_factory, session_scope
from support.users_store import make_users_store


@pytest.mark.asyncio
async def test_positive_verification_is_cached(tmp_path) -> None:
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
        _row, key = service.issue_api_key(
            session,
            subject="alice@example.com",
            label=None,
            expires_in_days=90,
            created_by="test",
        )

    backend_verify = AsyncMock(wraps=directory.verify_api_key)
    with patch.object(directory, "verify_api_key", backend_verify):
        first = await resolver.verify_api_key(key)
        second = await resolver.verify_api_key(key)

    assert first is not None
    assert second is not None
    assert second.subject == "alice@example.com"
    assert backend_verify.await_count == 1


@pytest.mark.asyncio
async def test_revoked_key_returns_none_after_revision_bump(tmp_path) -> None:
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
        row, key = service.issue_api_key(
            session,
            subject="alice@example.com",
            label=None,
            expires_in_days=90,
            created_by="test",
        )
    assert await resolver.verify_api_key(key) is not None
    await store.revoke_api_key(key_id=row.key_id, actor="admin")
    assert await resolver.verify_api_key(key) is None


@pytest.mark.asyncio
async def test_raw_key_not_stored_in_resolver_dict(tmp_path) -> None:
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
        _row, key = service.issue_api_key(
            session,
            subject="alice@example.com",
            label=None,
            expires_in_days=90,
            created_by="test",
        )

    await resolver.verify_api_key(key)
    secret = key.split("_", 2)[-1]
    for value in resolver.__dict__.values():
        if isinstance(value, str) and secret in value:
            pytest.fail("raw API key secret found in resolver state")
        if isinstance(value, dict):
            for entry_key, entry_val in value.items():
                assert secret not in str(entry_key)
                if entry_val is not None and secret in repr(entry_val):
                    pytest.fail("raw API key secret found in resolver cache")


@pytest.mark.asyncio
async def test_directory_without_api_keys_capability_returns_none() -> None:
    directory = InMemoryUserDirectory()
    settings = Settings(base_url="http://localhost:8080", redis_url="")
    resolver = build_user_directory_resolver(settings, directory=directory)
    assert await resolver.verify_api_key("ksk_" + "a" * 12 + "_" + "B" * 43) is None
