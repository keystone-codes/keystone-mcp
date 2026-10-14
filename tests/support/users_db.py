"""Shared fixtures for testing the users directory against SQLite and Postgres."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import quote

import pytest
from sqlalchemy import text
from sqlalchemy.engine import make_url

from keystone_mcp.users.db import create_users_engine
from keystone_mcp.users.migrate import upgrade_to_head
from support.test_env import RUN_ID

POSTGRES_URL_ENV_VAR = "KEYSTONE_TEST_POSTGRES_URL"


def sqlite_url(tmp_path: Path) -> str:
    return f"sqlite:///{tmp_path}/keystone-users.db"


def _postgres_schema_name() -> str:
    safe = RUN_ID.replace("-", "_")
    return f"ks_test_{safe}"


def postgres_test_url() -> str | None:
    raw = os.environ.get(POSTGRES_URL_ENV_VAR)
    if not raw:
        return None
    url = make_url(raw)
    db_name = url.database or ""
    if "test" not in db_name.lower():
        pytest.fail(
            f"refusing to drop tables in database {db_name!r}: "
            f"{POSTGRES_URL_ENV_VAR} must point at a database whose name contains 'test'"
        )
    return raw


def postgres_connection_url() -> str:
    """Postgres URL with ``search_path`` for ``Settings`` / subprocess env."""
    base = postgres_test_url()
    if base is None:
        pytest.skip(f"{POSTGRES_URL_ENV_VAR} is not set; skipping Postgres users-directory tests")
    return _postgres_engine_url(base)


_POSTGRES_SCHEMA_READY: set[str] = set()


def _ensure_postgres_schema(base_url: str) -> str:
    schema = _postgres_schema_name()
    if schema in _POSTGRES_SCHEMA_READY:
        return schema
    bootstrap = create_users_engine(base_url)
    try:
        with bootstrap.begin() as conn:
            conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
    finally:
        bootstrap.dispose()
    _POSTGRES_SCHEMA_READY.add(schema)
    return schema


def _postgres_engine_url(base: str) -> str:
    schema = _postgres_schema_name()
    option = quote(f"-csearch_path={schema}", safe="")
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}options={option}"


def _postgres_engine():
    base = postgres_test_url()
    if base is None:
        return None
    _ensure_postgres_schema(base)
    return create_users_engine(_postgres_engine_url(base))


# Every table the users-directory migrations create, children first.
_POSTGRES_TABLES = (
    "keystone_api_key",
    "keystone_service_account_role",
    "keystone_service_account",
    "keystone_user_role",
    "keystone_user",
    "keystone_users_alembic_version",
)


def reset_postgres_schema(engine) -> None:  # noqa: ANN001
    with engine.begin() as conn:
        for table in _POSTGRES_TABLES:
            conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))


def _reset_postgres(engine) -> None:  # noqa: ANN001
    reset_postgres_schema(engine)


def _drop_postgres_schema(base_url: str) -> None:
    schema = _postgres_schema_name()
    engine = create_users_engine(base_url)
    try:
        with engine.begin() as conn:
            conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
    finally:
        engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def _postgres_schema_teardown():
    yield
    base = os.environ.get(POSTGRES_URL_ENV_VAR)
    if base:
        _drop_postgres_schema(base)


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

    engine = _postgres_engine()
    if engine is None:
        pytest.skip(f"{POSTGRES_URL_ENV_VAR} is not set; skipping Postgres users-directory tests")

    _reset_postgres(engine)
    upgrade_to_head(engine)
    try:
        yield engine
    finally:
        _reset_postgres(engine)
        engine.dispose()


@pytest.fixture
def postgres_engine() -> Iterator:
    """A migrated engine against ``KEYSTONE_TEST_POSTGRES_URL`` only."""
    engine = _postgres_engine()
    if engine is None:
        pytest.skip(
            f"{POSTGRES_URL_ENV_VAR} is not set; skipping Postgres-only users-directory test"
        )

    _reset_postgres(engine)
    upgrade_to_head(engine)
    try:
        yield engine
    finally:
        _reset_postgres(engine)
        engine.dispose()
