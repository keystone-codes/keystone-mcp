"""Apply and inspect Alembic migrations for the users directory.

Migrations run in-process via ``upgrade_to_head(engine)`` rather than the
``alembic`` CLI, so a server can migrate its own database on startup. On
PostgreSQL, several replicas may start at once; a transactional advisory lock
serializes them so only one actually runs the DDL.
"""

from __future__ import annotations

import alembic.command
import alembic.config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import text
from sqlalchemy.engine import Engine

HEAD_REVISION = "0004_identity_binding"
# First 8 bytes of sha256(b"keystone-mcp:users:migrations"), interpreted as a
# signed bigint (what pg_advisory_xact_lock expects).
MIGRATION_LOCK_KEY = -1105817870462558087
VERSION_TABLE = "keystone_users_alembic_version"


def upgrade_to_head(engine: Engine) -> None:
    """Migrate the users directory database to ``HEAD_REVISION``."""
    cfg = alembic.config.Config()
    cfg.set_main_option("script_location", "keystone_mcp.users:migrations")
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK_KEY})
        cfg.attributes["connection"] = conn
        alembic.command.upgrade(cfg, "head")


def current_revision(engine: Engine) -> str | None:
    """Return the revision the database is currently stamped at, if any."""
    with engine.connect() as conn:
        context = MigrationContext.configure(conn, opts={"version_table": VERSION_TABLE})
        return context.get_current_revision()
