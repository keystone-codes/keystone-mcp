"""Shared fixtures for testing the users directory against SQLite and Postgres."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import text

from keystone_mcp.users.db import create_users_engine
from keystone_mcp.users.migrate import upgrade_to_head

POSTGRES_URL_ENV_VAR = "KEYSTONE_TEST_POSTGRES_URL"


def sqlite_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path}/keystone-users.db"


def _reset_postgres(engine) -> None:  # noqa: ANN001
    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS keystone_user_role CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS keystone_user CASCADE"))
        conn.execute(text("DROP TABLE IF EXISTS keystone_users_alembic_version CASCADE"))


@pytest.fixture(params=["sqlite", "postgres"])
def users_engine(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator:
    backend = request.param
    if backend == "sqlite":
        engine = create_users_engine(sqlite_url(tmp_path))
        upgrade_to_head(engine)
        try:
            yield engine
        finally:
            engine.dispose()
        return

    postgres_url = os.environ.get(POSTGRES_URL_ENV_VAR)
    if not postgres_url:
        pytest.skip(f"{POSTGRES_URL_ENV_VAR} is not set; skipping Postgres users-directory tests")

    engine = create_users_engine(postgres_url)
    _reset_postgres(engine)
    upgrade_to_head(engine)
    try:
        yield engine
    finally:
        _reset_postgres(engine)
        engine.dispose()


@pytest.fixture
def postgres_engine() -> Iterator:
    """A migrated engine against ``KEYSTONE_TEST_POSTGRES_URL`` only.

    Unlike ``users_engine`` (parametrized over SQLite and Postgres), this is
    for tests that are meaningful on Postgres alone — e.g. concurrency tests
    relying on ``SELECT ... FOR UPDATE`` row locks, which SQLite does not
    provide.
    """
    postgres_url = os.environ.get(POSTGRES_URL_ENV_VAR)
    if not postgres_url:
        pytest.skip(
            f"{POSTGRES_URL_ENV_VAR} is not set; skipping Postgres-only users-directory test"
        )

    engine = create_users_engine(postgres_url)
    _reset_postgres(engine)
    upgrade_to_head(engine)
    try:
        yield engine
    finally:
        _reset_postgres(engine)
        engine.dispose()
