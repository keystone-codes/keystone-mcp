"""Tests for keystone_mcp.users.store.UsersStore."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from sqlalchemy.orm import Session

from keystone_mcp.users.db import create_users_engine
from keystone_mcp.users.errors import LastAdministratorError, UsersStoreUnavailableError
from keystone_mcp.users.models import UserRow
from keystone_mcp.users.revision import NullRevisionWriter, RevisionWriter
from keystone_mcp.users.store import UsersStore
from support.users_store import make_users_store


@pytest.mark.asyncio
async def test_changed_mutation_bumps_revision_once(tmp_path: Path) -> None:
    store, revision = await make_users_store(tmp_path)
    assert await revision.current() == 0

    await store.create_user(
        email="user@example.com",
        full_name="User",
        roles=[],
        note=None,
        created_by=None,
        allowed_roles=None,
    )

    assert await revision.current() == 1
    store.dispose()


@pytest.mark.asyncio
async def test_unchanged_mutation_does_not_bump(tmp_path: Path) -> None:
    store, revision = await make_users_store(tmp_path)
    await store.create_user(
        email="user@example.com",
        full_name="User",
        roles=[],
        note=None,
        created_by=None,
        allowed_roles=None,
    )
    assert await revision.current() == 1

    result = await store.update_profile(email="user@example.com", full_name=None, note=None)

    assert result.changed is False
    assert await revision.current() == 1
    store.dispose()


@pytest.mark.asyncio
async def test_revision_bumped_after_commit(tmp_path: Path) -> None:
    """The revision writer must see data already committed by the mutation."""
    engine = create_users_engine(f"sqlite:///{tmp_path}/keystone-users.db")

    seen_in_separate_session: dict[str, bool] = {"value": False}

    class _AssertingWriter:
        async def bump(self) -> int:
            with Session(engine) as session:
                row = session.get(UserRow, "user@example.com")
                seen_in_separate_session["value"] = row is not None
            return 1

    store = UsersStore(engine, revision=_AssertingWriter())
    await store.migrate()

    await store.create_user(
        email="user@example.com",
        full_name="User",
        roles=[],
        note=None,
        created_by=None,
        allowed_roles=None,
    )

    assert seen_in_separate_session["value"] is True
    store.dispose()


@pytest.mark.asyncio
async def test_revision_bump_failure_keeps_mutation(tmp_path: Path, caplog) -> None:
    from redis.exceptions import RedisError

    class _FailingWriter:
        async def bump(self) -> int:
            raise RedisError("boom")

    engine = create_users_engine(f"sqlite:///{tmp_path}/keystone-users.db")
    store = UsersStore(engine, revision=_FailingWriter())
    await store.migrate()

    import logging

    with caplog.at_level(logging.WARNING):
        result = await store.create_user(
            email="user@example.com",
            full_name="User",
            roles=[],
            note=None,
            created_by=None,
            allowed_roles=None,
        )

    assert result.created is True
    assert result.user.email == "user@example.com"
    assert any("revision bump failed" in record.message for record in caplog.records)

    resolved = await store.resolve("user@example.com")
    assert resolved.exists is True
    store.dispose()


@pytest.mark.asyncio
async def test_sqlite_concurrent_admin_revokes_leave_one_admin(tmp_path: Path) -> None:
    store, _ = await make_users_store(tmp_path)
    for email in ("admin1@example.com", "admin2@example.com"):
        await store.create_user(
            email=email,
            full_name=email,
            roles=["administrator"],
            note=None,
            created_by=None,
            allowed_roles=None,
        )

    results = await asyncio.gather(
        store.revoke_role(
            email="admin1@example.com",
            role="administrator",
            actor_email="admin2@example.com",
        ),
        store.revoke_role(
            email="admin2@example.com",
            role="administrator",
            actor_email="admin1@example.com",
        ),
        return_exceptions=True,
    )

    successes = [r for r in results if not isinstance(r, Exception)]
    failures = [r for r in results if isinstance(r, Exception)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], LastAdministratorError)

    assert await store.count_active_administrators() == 1
    store.dispose()


@pytest.mark.asyncio
async def test_database_error_becomes_unavailable_without_password() -> None:
    engine = create_users_engine("postgresql+psycopg://u:secret@127.0.0.1:1/db")
    store = UsersStore(engine, revision=NullRevisionWriter())

    with pytest.raises(UsersStoreUnavailableError) as exc_info:
        await store.resolve("user@example.com")

    assert exc_info.value.code == "service_unavailable"
    assert "secret" not in str(exc_info.value)
    store.dispose()


@pytest.mark.asyncio
async def test_ping_ok_on_migrated_sqlite(tmp_path: Path) -> None:
    store, _ = await make_users_store(tmp_path)
    await store.ping()
    store.dispose()


def test_revision_writer_protocol_is_satisfied() -> None:
    assert isinstance(NullRevisionWriter(), RevisionWriter)
