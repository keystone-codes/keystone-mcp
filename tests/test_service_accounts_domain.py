"""Service account business rules in the built-in users database."""

from __future__ import annotations

from pathlib import Path

import pytest

from keystone_mcp.users.errors import (
    InvalidRoleError,
    InvalidUserFieldError,
    UserAlreadyExistsError,
)
from keystone_mcp.users.migrate import upgrade_to_head
from keystone_mcp.users.revision import NullRevisionWriter
from keystone_mcp.users.store import UsersStore
from support.users_db import POSTGRES_URL_ENV_VAR
from support.users_store import make_users_store


@pytest.fixture
async def store(tmp_path: Path) -> UsersStore:
    st, _revision = await make_users_store(tmp_path, revision=NullRevisionWriter())
    yield st
    st.dispose()


async def test_name_must_match_pattern(store: UsersStore) -> None:
    with pytest.raises(InvalidUserFieldError):
        await store.create_service_account(
            name="Bad_Name",
            description=None,
            roles=[],
            created_by="system:test",
        )


async def test_duplicate_name_is_conflict(store: UsersStore) -> None:
    await store.create_service_account(
        name="ci",
        description=None,
        roles=["member"],
        created_by="system:test",
    )
    with pytest.raises(UserAlreadyExistsError):
        await store.create_service_account(
            name="ci",
            description=None,
            roles=[],
            created_by="system:test",
        )


async def test_administrator_role_is_reserved(store: UsersStore) -> None:
    with pytest.raises(InvalidRoleError) as exc:
        await store.create_service_account(
            name="ci",
            description=None,
            roles=["administrator"],
            created_by="system:test",
        )
    assert exc.value.reason == "reserved"


async def test_update_without_changes_is_unchanged(store: UsersStore) -> None:
    await store.create_service_account(
        name="ci",
        description="bot",
        roles=["member"],
        created_by="system:test",
    )
    mutation = await store.update_service_account(
        name="ci",
        description="bot",
        actor="system:test",
    )
    assert mutation.changed is False


async def test_resolve_service_account(store: UsersStore) -> None:
    await store.create_service_account(
        name="ci",
        description=None,
        roles=["robot"],
        created_by="system:test",
    )
    resolved = await store.resolve("svc:ci")
    assert resolved.exists is True
    assert resolved.subject_type == "service"
    assert resolved.roles == ("robot",)


async def test_resolve_unknown_service_account(store: UsersStore) -> None:
    resolved = await store.resolve("svc:nope")
    assert resolved.exists is False
    assert resolved.subject_type == "service"


async def test_block_and_revision_bump(store: UsersStore) -> None:
    await store.create_service_account(
        name="ci",
        description=None,
        roles=["member"],
        created_by="system:test",
    )
    mutation = await store.update_service_account(name="ci", is_blocked=True, actor="admin")
    assert mutation.changed is True
    resolved = await store.resolve("svc:ci")
    assert resolved.is_blocked is True


def test_postgres_migration_from_0001(tmp_path: Path) -> None:
    postgres_url = __import__("os").environ.get(POSTGRES_URL_ENV_VAR)
    if not postgres_url:
        pytest.skip(f"{POSTGRES_URL_ENV_VAR} is not set")
    from keystone_mcp.users.db import create_users_engine

    engine = create_users_engine(postgres_url)
    upgrade_to_head(engine)
    engine.dispose()
