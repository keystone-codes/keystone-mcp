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
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from keystone_mcp.users import service
from keystone_mcp.users.db import create_users_engine, make_session_factory
from keystone_mcp.users.errors import LastAdministratorError
from keystone_mcp.users.migrate import upgrade_to_head
from keystone_mcp.users.revision import NullRevisionWriter
from keystone_mcp.users.store import UsersStore
from support.users_db import postgres_engine  # noqa: F401 -- fixture import

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
