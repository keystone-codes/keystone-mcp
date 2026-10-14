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
from alembic.script import ScriptDirectory
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


def _alembic_config() -> alembic.config.Config:
    cfg = alembic.config.Config()
    cfg.set_main_option("script_location", "keystone_mcp.users:migrations")
    return cfg


def _script_directory() -> ScriptDirectory:
    return ScriptDirectory.from_config(_alembic_config())


def ordered_revisions() -> tuple[str, ...]:
    """Return migration revision ids from oldest to newest."""
    script = _script_directory()
    heads = script.get_heads()
    if len(heads) != 1:
        raise RuntimeError(f"expected a single migration head, got {heads!r}")
    revisions: list[str] = []
    for rev in script.walk_revisions(base="base", head=heads[0]):
        revisions.append(rev.revision)
    revisions.reverse()
    return tuple(revisions)


def db_revision_status(db_revision: str | None) -> str:
    """Compare the database revision to ``HEAD_REVISION`` for this binary."""
    if db_revision == HEAD_REVISION:
        return "match"
    order = ordered_revisions()
    if db_revision is None:
        return "older"
    if db_revision not in order:
        return "newer"
    if order.index(db_revision) < order.index(HEAD_REVISION):
        return "older"
    return "newer"


def downgrade_to(engine: Engine, revision: str) -> None:
    """Roll the users directory database back to ``revision``."""
    cfg = _alembic_config()
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK_KEY})
        cfg.attributes["connection"] = conn
        alembic.command.downgrade(cfg, revision)


def downgrade_one_step(engine: Engine) -> None:
    """Downgrade one revision from the database's current stamp."""
    order = ordered_revisions()
    current = current_revision(engine)
    if current is None:
        raise RuntimeError("no revision to downgrade from")
    if current not in order:
        raise RuntimeError(f"unknown revision {current!r}")
    idx = order.index(current)
    if idx == 0:
        raise RuntimeError("already at the first revision")
    downgrade_to(engine, order[idx - 1])
