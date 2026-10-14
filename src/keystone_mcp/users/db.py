"""Engine and session management for the users directory database.

No module-level globals: every caller builds and owns its own engine and
session factory. ``keystone_mcp.users`` as a whole has no side effects at
import time.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

_ALLOWED_SQLITE_FORM = "sqlite:///path/to/file.db"
_ALLOWED_POSTGRES_FORM = "postgresql+psycopg://user:pass@host:5432/db"


class UsersConfigError(ValueError):
    """The configured users database URL is not acceptable."""


def redact_db_url(url: str) -> str:
    """Return ``url`` with any password replaced by ``***``, for logs and errors."""
    return make_url(url).render_as_string(hide_password=True)


def sqlite_file_path(url: str) -> Path | None:
    """Return the absolute file path a ``sqlite:///`` URL points at, or ``None``.

    ``None`` is also returned for a non-SQLite URL (PostgreSQL has no local
    file to report). Relative to the current working directory, same as
    SQLAlchemy's own ``sqlite:///relative/path.db`` resolution — which is
    exactly the ambiguity :func:`describe_db_url` exists to make visible: a
    command run from the wrong directory would otherwise open a different,
    silently-created database without any indication that it did.
    """
    parsed = make_url(url)
    if parsed.drivername != "sqlite":
        return None
    database = parsed.database or ""
    return Path(database).resolve()


def describe_db_url(url: str) -> str:
    """Return ``url`` for display: an absolute path for SQLite, else the redacted form.

    A relative ``KEYSTONE_MCP_USERS_DB_URL`` (the default is
    ``sqlite:///./keystone-users.db``) resolves against whatever the current
    working directory happens to be, which a human reading ``Users
    directory: sqlite:///./keystone-users.db`` cannot tell apart from a
    different database down the hall. Printing the absolute path makes a
    wrong working directory obvious immediately instead of silently writing
    into (or creating) an unrelated file.
    """
    path = sqlite_file_path(url)
    if path is None:
        return redact_db_url(url)
    return f"sqlite:///{path}"


def check_users_db_url(url: str) -> None:
    """Reject anything that is not a SQLite file path or a psycopg Postgres URL."""
    if not url:
        raise UsersConfigError("users database URL must not be empty")
    try:
        parsed = make_url(url)
    except Exception as exc:  # noqa: BLE001 - re-raised with our own type
        raise UsersConfigError(f"cannot parse users database URL: {exc}") from exc

    driver = parsed.drivername

    if driver == "sqlite":
        database = parsed.database
        if not database or database == ":memory:":
            raise UsersConfigError(
                "in-memory SQLite is not supported for the users database "
                f"(each connection would see its own database); use a file path, "
                f"e.g. {_ALLOWED_SQLITE_FORM}"
            )
        return

    if driver == "postgresql+psycopg":
        return

    if driver.startswith("postgresql"):
        raise UsersConfigError(
            f"unsupported PostgreSQL driver {driver!r}; use {_ALLOWED_POSTGRES_FORM}"
        )

    raise UsersConfigError(
        f"unsupported users database URL {redact_db_url(url)!r}; "
        f"use {_ALLOWED_SQLITE_FORM} or {_ALLOWED_POSTGRES_FORM}"
    )


def create_users_engine(url: str) -> Engine:
    """Build the SQLAlchemy engine for the users directory database."""
    check_users_db_url(url)
    parsed = make_url(url)

    if parsed.drivername == "sqlite":
        database = parsed.database or ""
        directory = os.path.dirname(database)
        if directory and not os.path.isdir(directory):
            raise UsersConfigError(f"directory does not exist: {directory}")

        engine = create_engine(
            url,
            connect_args={"check_same_thread": False, "timeout": 5},
        )

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_connection, _connection_record) -> None:  # noqa: ANN001
            dbapi_connection.isolation_level = None
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

        @event.listens_for(engine, "begin")
        def _begin_immediate(conn) -> None:  # noqa: ANN001
            conn.exec_driver_sql("BEGIN IMMEDIATE")

        return engine

    return create_engine(
        url,
        pool_pre_ping=True,
        connect_args={"connect_timeout": 5},
    )


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Commit on success, rollback on error, always close."""
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
