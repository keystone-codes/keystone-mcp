"""Tests for keystone_mcp.users.db and keystone_mcp.users.migrate."""

from __future__ import annotations

import importlib.resources
import os
import threading
from pathlib import Path

import pytest
from sqlalchemy import inspect, text

from keystone_mcp.users.db import (
    UsersConfigError,
    check_users_db_url,
    create_users_engine,
    redact_db_url,
)
from keystone_mcp.users.migrate import (
    HEAD_REVISION,
    current_revision,
    downgrade_one_step,
    ordered_revisions,
    upgrade_to_head,
)
from support.users_db import POSTGRES_URL_ENV_VAR, reset_postgres_schema, sqlite_url


def test_upgrade_on_empty_database_creates_tables(tmp_path: Path) -> None:
    engine = create_users_engine(sqlite_url(tmp_path))
    upgrade_to_head(engine)

    inspector = inspect(engine)
    assert "keystone_user" in inspector.get_table_names()
    assert "keystone_user_role" in inspector.get_table_names()
    assert current_revision(engine) == HEAD_REVISION


def test_upgrade_is_idempotent(tmp_path: Path) -> None:
    engine = create_users_engine(sqlite_url(tmp_path))
    upgrade_to_head(engine)
    upgrade_to_head(engine)
    assert current_revision(engine) == HEAD_REVISION


def test_concurrent_upgrades_on_postgres() -> None:
    postgres_url = os.environ.get(POSTGRES_URL_ENV_VAR)
    if not postgres_url:
        pytest.skip(f"{POSTGRES_URL_ENV_VAR} is not set; skipping Postgres migration test")

    engine = create_users_engine(postgres_url)
    reset_postgres_schema(engine)

    errors: list[BaseException] = []

    def _upgrade() -> None:
        try:
            upgrade_to_head(engine)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_upgrade) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT version_num FROM keystone_users_alembic_version")).all()
    assert len(rows) == 1

    reset_postgres_schema(engine)
    engine.dispose()


def test_migration_files_are_packaged() -> None:
    path = (
        importlib.resources.files("keystone_mcp.users")
        / "migrations"
        / "versions"
        / "0001_initial.py"
    )
    assert path.is_file()


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///./x.db",
        "sqlite:////tmp/x.db",
        "postgresql+psycopg://u:p@h/db",
    ],
)
def test_db_url_validation_accepts(url: str) -> None:
    check_users_db_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "sqlite://",
        "sqlite:///:memory:",
        "postgresql://u:p@h/db",
        "postgresql+asyncpg://u:p@h/db",
        "mysql://u:p@h/db",
    ],
)
def test_db_url_validation_rejects(url: str) -> None:
    with pytest.raises(UsersConfigError):
        check_users_db_url(url)


def test_sqlite_missing_directory_is_refused(tmp_path: Path) -> None:
    missing_dir = tmp_path / "does-not-exist"
    with pytest.raises(UsersConfigError, match="directory does not exist"):
        create_users_engine(f"sqlite:///{missing_dir}/keystone-users.db")


def test_redact_db_url_hides_password() -> None:
    redacted = redact_db_url("postgresql+psycopg://user:supersecret@host:5432/db")
    assert "supersecret" not in redacted
    assert "***" in redacted


def test_upgrade_to_0002_from_0001(tmp_path: Path) -> None:
    import alembic.command
    import alembic.config

    from keystone_mcp.users.db import create_users_engine

    engine = create_users_engine(sqlite_url(tmp_path))
    cfg = alembic.config.Config()
    cfg.set_main_option("script_location", "keystone_mcp.users:migrations")
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        alembic.command.upgrade(cfg, "0001_initial")
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO keystone_user "
                "(email, full_name, is_blocked, created_at, updated_at) "
                "VALUES ('keep@example.com', 'Keep', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO keystone_user_role (email, role) VALUES ('keep@example.com', 'member')"
            )
        )
    upgrade_to_head(engine)
    inspector = inspect(engine)
    assert "keystone_service_account" in inspector.get_table_names()
    assert "keystone_user" in inspector.get_table_names()
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT email FROM keystone_user WHERE email = 'keep@example.com'")
        ).first()
    assert row is not None
    assert current_revision(engine) == HEAD_REVISION


def test_upgrade_to_0004_adds_identity_binding_columns(tmp_path: Path) -> None:
    engine = create_users_engine(sqlite_url(tmp_path))
    upgrade_to_head(engine)
    inspector = inspect(engine)
    columns = {col["name"] for col in inspector.get_columns("keystone_user")}
    assert {"idp_issuer", "idp_subject", "idp_bound_at"}.issubset(columns)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO keystone_user "
                "(email, full_name, is_blocked, created_at, updated_at) "
                "VALUES ('legacy@example.com', 'Legacy', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
    upgrade_to_head(engine)
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT idp_issuer, idp_subject FROM keystone_user "
                "WHERE email = 'legacy@example.com'"
            )
        ).first()
    assert row == (None, None)
    assert current_revision(engine) == HEAD_REVISION


def test_null_identity_pairs_do_not_conflict_on_sqlite(tmp_path: Path) -> None:
    engine = create_users_engine(sqlite_url(tmp_path))
    upgrade_to_head(engine)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO keystone_user "
                "(email, full_name, is_blocked, created_at, updated_at) "
                "VALUES ('a@example.com', 'A', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP), "
                "('b@example.com', 'B', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
    assert current_revision(engine) == HEAD_REVISION


def test_upgrade_to_0003_from_0002(tmp_path: Path) -> None:
    import alembic.command
    import alembic.config

    engine = create_users_engine(sqlite_url(tmp_path))
    cfg = alembic.config.Config()
    cfg.set_main_option("script_location", "keystone_mcp.users:migrations")
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        alembic.command.upgrade(cfg, "0002_service_accounts")
    upgrade_to_head(engine)
    inspector = inspect(engine)
    assert "keystone_api_key" in inspector.get_table_names()
    assert current_revision(engine) == HEAD_REVISION


def _seed_keep_user(engine) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO keystone_user "
                "(email, full_name, is_blocked, created_at, updated_at) "
                "VALUES ('keep@example.com', 'Keep', FALSE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )


def _downgrade_each_revision_round_trip(engine_factory) -> None:
    import alembic.command
    import alembic.config

    revisions = ordered_revisions()
    assert revisions[-1] == HEAD_REVISION
    for idx in range(1, len(revisions)):
        parent = revisions[idx - 1]
        engine = engine_factory()
        try:
            cfg = alembic.config.Config()
            cfg.set_main_option("script_location", "keystone_mcp.users:migrations")
            with engine.begin() as conn:
                cfg.attributes["connection"] = conn
                alembic.command.upgrade(cfg, parent)
            _seed_keep_user(engine)
            upgrade_to_head(engine)
            downgrade_one_step(engine)
            upgrade_to_head(engine)
            with engine.connect() as conn:
                row = conn.execute(
                    text("SELECT email FROM keystone_user WHERE email = 'keep@example.com'")
                ).first()
            assert row is not None, revisions[idx]
        finally:
            engine.dispose()


def test_downgrade_each_revision_round_trip_sqlite(tmp_path: Path) -> None:
    counter = {"n": 0}

    def _factory():
        counter["n"] += 1
        sub = tmp_path / f"roundtrip-{counter['n']}"
        sub.mkdir()
        return create_users_engine(sqlite_url(sub))

    _downgrade_each_revision_round_trip(_factory)


def test_downgrade_each_revision_round_trip_postgres() -> None:
    postgres_url = os.environ.get(POSTGRES_URL_ENV_VAR)
    if not postgres_url:
        pytest.skip(f"{POSTGRES_URL_ENV_VAR} is not set; skipping Postgres migration test")

    def _factory():
        engine = create_users_engine(postgres_url)
        reset_postgres_schema(engine)
        return engine

    _downgrade_each_revision_round_trip(_factory)
    engine = create_users_engine(postgres_url)
    reset_postgres_schema(engine)
    engine.dispose()


def test_postgres_is_configured_in_ci() -> None:
    """The Postgres-backed users-directory tests must not silently skip in CI.

    Outside CI, missing ``KEYSTONE_TEST_POSTGRES_URL`` is a normal
    "no local Postgres" skip. Inside CI (``CI=true``), the workflow's
    "Users directory on PostgreSQL" step is expected to have set it; if it
    did not, that is a CI configuration regression, not a skip.
    """
    if os.environ.get("CI") == "true" and not os.environ.get(POSTGRES_URL_ENV_VAR):
        pytest.fail("PostgreSQL tests must run in CI")
    if not os.environ.get(POSTGRES_URL_ENV_VAR):
        pytest.skip(f"{POSTGRES_URL_ENV_VAR} is not set outside CI")
