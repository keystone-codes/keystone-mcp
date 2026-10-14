"""Concurrency tests for the users directory: exactly one administrator
survives when the last two administrators are revoked/blocked at the same
instant.

Ported from the legacy standalone users-directory service's
``tests/integration/test_concurrency.py``. The first pair of tests exercises
``keystone_mcp.users.service`` directly against two sessions sharing one
``SELECT ... FOR UPDATE`` row lock — meaningful only on PostgreSQL, since
SQLite's ``FOR UPDATE`` is a no-op (see ``keystone_mcp.users.store.UsersStore``
docstring). The second pair exercises the same scenario through
``UsersStore`` with ``asyncio.gather``, on both backends: SQLite is protected
by the store's own process-wide write lock, PostgreSQL by the row lock.
"""

from __future__ import annotations

import asyncio
import multiprocessing as mp
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Literal

import pytest
from sqlalchemy.exc import IntegrityError

from keystone_mcp.user_directory.errors import UserAlreadyExistsError
from keystone_mcp.users import service
from keystone_mcp.users.db import create_users_engine, make_session_factory
from keystone_mcp.users.errors import LastAdministratorError, UsersStoreUnavailableError
from keystone_mcp.users.migrate import upgrade_to_head
from keystone_mcp.users.revision import NullRevisionWriter
from keystone_mcp.users.store import UsersStore
from support.users_db import postgres_engine, postgres_test_url  # noqa: F401 -- fixture import

ADMIN_A = "admin-a@example.com"
ADMIN_B = "admin-b@example.com"


def _seed_two_administrators(session_factory) -> None:  # noqa: ANN001
    session = session_factory()
    try:
        service.create_user(
            session,
            email=ADMIN_A,
            full_name="Admin A",
            roles=["administrator"],
            note=None,
            created_by=None,
            allowed_roles=None,
        )
        service.create_user(
            session,
            email=ADMIN_B,
            full_name="Admin B",
            roles=["administrator"],
            note=None,
            created_by=None,
            allowed_roles=None,
        )
        session.commit()
    finally:
        session.close()


def test_concurrent_admin_revoke_only_one_succeeds_postgres(postgres_engine) -> None:  # noqa: ANN001, F811
    session_factory = make_session_factory(postgres_engine)
    _seed_two_administrators(session_factory)

    barrier = threading.Barrier(2)
    outcomes: dict[str, tuple[str, Exception | None]] = {}

    def _revoke(target_email: str, actor_email: str) -> None:
        session = session_factory()
        try:
            barrier.wait(timeout=10)
            try:
                service.revoke_role(
                    session, email=target_email, role="administrator", actor_email=actor_email
                )
                session.commit()
                outcomes[target_email] = ("ok", None)
            except Exception as exc:  # noqa: BLE001 -- recorded, not raised, in the worker
                session.rollback()
                outcomes[target_email] = ("error", exc)
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_revoke, ADMIN_A, ADMIN_B),
            pool.submit(_revoke, ADMIN_B, ADMIN_A),
        ]
        for future in futures:
            future.result(timeout=10)

    statuses = {email: status for email, (status, _exc) in outcomes.items()}
    errors = [exc for _status, exc in outcomes.values() if exc is not None]

    assert sorted(statuses.values()) == ["error", "ok"]
    assert len(errors) == 1
    assert isinstance(errors[0], LastAdministratorError)

    with session_factory() as session:
        remaining = service.count_active_administrators(session)
    assert remaining == 1


def test_concurrent_admin_block_only_one_succeeds_postgres(postgres_engine) -> None:  # noqa: ANN001, F811
    session_factory = make_session_factory(postgres_engine)
    _seed_two_administrators(session_factory)

    barrier = threading.Barrier(2)
    outcomes: dict[str, tuple[str, Exception | None]] = {}

    def _block(target_email: str, actor_email: str) -> None:
        session = session_factory()
        try:
            barrier.wait(timeout=10)
            try:
                service.set_blocked(
                    session, email=target_email, blocked=True, actor_email=actor_email
                )
                session.commit()
                outcomes[target_email] = ("ok", None)
            except Exception as exc:  # noqa: BLE001 -- recorded, not raised, in the worker
                session.rollback()
                outcomes[target_email] = ("error", exc)
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(_block, ADMIN_A, ADMIN_B),
            pool.submit(_block, ADMIN_B, ADMIN_A),
        ]
        for future in futures:
            future.result(timeout=10)

    statuses = {email: status for email, (status, _exc) in outcomes.items()}
    errors = [exc for _status, exc in outcomes.values() if exc is not None]

    assert sorted(statuses.values()) == ["error", "ok"]
    assert len(errors) == 1
    assert isinstance(errors[0], LastAdministratorError)

    with session_factory() as session:
        remaining = service.count_active_administrators(session)
    assert remaining == 1


async def _seed_two_administrators_via_store(store: UsersStore) -> None:
    await store.create_user(
        email=ADMIN_A,
        full_name="Admin A",
        roles=["administrator"],
        note=None,
        created_by=None,
        allowed_roles=None,
    )
    await store.create_user(
        email=ADMIN_B,
        full_name="Admin B",
        roles=["administrator"],
        note=None,
        created_by=None,
        allowed_roles=None,
    )


async def _revoke_both_concurrently(store: UsersStore) -> list[str]:
    results = await asyncio.gather(
        store.revoke_role(email=ADMIN_A, role="administrator", actor_email=ADMIN_B),
        store.revoke_role(email=ADMIN_B, role="administrator", actor_email=ADMIN_A),
        return_exceptions=True,
    )
    statuses = []
    for result in results:
        if isinstance(result, LastAdministratorError):
            statuses.append("error")
        elif isinstance(result, BaseException):
            raise result
        else:
            statuses.append("ok")
    return statuses


async def test_concurrent_admin_revoke_through_store_sqlite(tmp_path: Path) -> None:
    engine = create_users_engine(f"sqlite:///{tmp_path}/keystone-users.db")
    upgrade_to_head(engine)
    store = UsersStore(engine, revision=NullRevisionWriter())
    try:
        await _seed_two_administrators_via_store(store)
        statuses = await _revoke_both_concurrently(store)

        assert sorted(statuses) == ["error", "ok"]
        remaining = await store.count_active_administrators()
        assert remaining == 1
    finally:
        store.dispose()


async def test_concurrent_admin_revoke_through_store_postgres(postgres_engine) -> None:  # noqa: ANN001, F811
    store = UsersStore(postgres_engine, revision=NullRevisionWriter())
    await _seed_two_administrators_via_store(store)
    statuses = await _revoke_both_concurrently(store)

    assert sorted(statuses) == ["error", "ok"]
    remaining = await store.count_active_administrators()
    assert remaining == 1


def _sqlite_demote_worker(
    db_url: str,
    target_email: str,
    actor_email: str,
    barrier: mp.Barrier,
    outcomes: mp.Queue,
) -> None:
    async def _run() -> Literal["ok", "error"]:
        engine = create_users_engine(db_url)
        store = UsersStore(engine, revision=NullRevisionWriter())
        try:
            barrier.wait(timeout=30)
            try:
                await store.revoke_role(
                    email=target_email,
                    role="administrator",
                    actor_email=actor_email,
                )
                return "ok"
            except LastAdministratorError:
                return "error"
        finally:
            store.dispose()

    outcomes.put(asyncio.run(_run()))


def test_sqlite_two_processes_cannot_both_demote_admins(tmp_path: Path) -> None:
    ctx = mp.get_context("spawn")
    for attempt in range(20):
        db_path = tmp_path / f"admins-{attempt}.db"
        db_url = f"sqlite:///{db_path}"
        engine = create_users_engine(db_url)
        upgrade_to_head(engine)
        session_factory = make_session_factory(engine)
        _seed_two_administrators(session_factory)
        engine.dispose()

        barrier = ctx.Barrier(2)
        outcomes: mp.Queue = ctx.Queue()
        p_a = ctx.Process(
            target=_sqlite_demote_worker,
            args=(db_url, ADMIN_A, ADMIN_B, barrier, outcomes),
        )
        p_b = ctx.Process(
            target=_sqlite_demote_worker,
            args=(db_url, ADMIN_B, ADMIN_A, barrier, outcomes),
        )
        p_a.start()
        p_b.start()
        p_a.join(timeout=30)
        p_b.join(timeout=30)
        assert p_a.exitcode == 0
        assert p_b.exitcode == 0
        assert sorted([outcomes.get(), outcomes.get()]) == ["error", "ok"]

        check_engine = create_users_engine(db_url)
        check_store = UsersStore(check_engine, revision=NullRevisionWriter())
        try:
            remaining = asyncio.run(check_store.count_active_administrators())
            assert remaining == 1
        finally:
            check_store.dispose()


@pytest.mark.asyncio
async def test_concurrent_create_user_returns_conflict(postgres_engine) -> None:  # noqa: ANN001, F811
    if postgres_test_url() is None:
        pytest.skip("KEYSTONE_TEST_POSTGRES_URL is not set")
    store = UsersStore(postgres_engine, revision=NullRevisionWriter())
    email = "race-create@example.com"

    results = await asyncio.gather(
        store.create_user(
            email=email,
            full_name="Race A",
            roles=[],
            note=None,
            created_by=None,
            allowed_roles=None,
        ),
        store.create_user(
            email=email,
            full_name="Race B",
            roles=[],
            note=None,
            created_by=None,
            allowed_roles=None,
        ),
        return_exceptions=True,
    )
    successes = [r for r in results if not isinstance(r, BaseException)]
    errors = [r for r in results if isinstance(r, BaseException)]
    assert len(successes) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], UserAlreadyExistsError)
    assert errors[0].code == "conflict"


@pytest.mark.asyncio
async def test_concurrent_grant_role_returns_changed_false(postgres_engine) -> None:  # noqa: ANN001, F811
    if postgres_test_url() is None:
        pytest.skip("KEYSTONE_TEST_POSTGRES_URL is not set")
    store = UsersStore(postgres_engine, revision=NullRevisionWriter())
    await store.create_user(
        email="grant-race@example.com",
        full_name="Grant Race",
        roles=[],
        note=None,
        created_by=None,
        allowed_roles=None,
    )

    results = await asyncio.gather(
        store.grant_role(email="grant-race@example.com", role="member", allowed_roles=None),
        store.grant_role(email="grant-race@example.com", role="member", allowed_roles=None),
        return_exceptions=True,
    )
    changed_flags = sorted(
        r.changed for r in results if not isinstance(r, BaseException)  # type: ignore[union-attr]
    )
    assert changed_flags == [False, True]


@pytest.mark.asyncio
async def test_second_integrity_error_is_store_unavailable(tmp_path: Path) -> None:
    engine = create_users_engine(f"sqlite:///{tmp_path}/keystone-users.db")
    upgrade_to_head(engine)
    store = UsersStore(engine, revision=NullRevisionWriter())

    def _always_integrity(session, **kwargs):  # noqa: ANN001, ARG001
        raise IntegrityError("INSERT", {}, Exception("duplicate"))

    original = service.create_user
    service.create_user = _always_integrity  # type: ignore[assignment]
    try:
        with pytest.raises(UsersStoreUnavailableError):
            await store.create_user(
                email="dup@example.com",
                full_name="Dup",
                roles=[],
                note=None,
                created_by=None,
                allowed_roles=None,
            )
    finally:
        service.create_user = original  # type: ignore[assignment]
        store.dispose()
