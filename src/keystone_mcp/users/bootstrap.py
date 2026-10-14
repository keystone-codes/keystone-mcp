"""Startup sequence for the built-in users directory: migrate, then seed.

Called once from :func:`keystone_mcp.server.bootstrap_platform`, before
upstream discovery and RBAC policy loading.
"""

from __future__ import annotations

import logging

from keystone_mcp.config import Settings
from keystone_mcp.users.store import UsersStore

logger = logging.getLogger(__name__)


class UsersBootstrapError(RuntimeError):
    """The users directory database could not be migrated or seeded."""


async def bootstrap_users_store(store: UsersStore, settings: Settings) -> None:
    """Migrate the users database and ensure the configured administrator.

    Raises :class:`UsersBootstrapError` (with the database address redacted)
    when migration fails. Seeding a missing or blocked superadmin never
    raises: it logs instead, since neither case should stop the server from
    starting.
    """
    try:
        await store.migrate()
    except Exception as exc:
        raise UsersBootstrapError(
            f"users directory database is not ready ({store.db_url_redacted}): {type(exc).__name__}"
        ) from exc

    superadmin_email = settings.superadmin_email.strip()
    if superadmin_email:
        result = await store.seed_superadmin(superadmin_email)
        # "created" clashes with LogRecord's own timestamp attribute of that
        # name; the JSON formatter would reject it as a duplicate key.
        logger.info(
            "initial administrator %s: %s",
            "created" if result.created else "already present",
            result.user.email,
            extra={"administrator_created": result.created},
        )
        if result.user.is_blocked:
            logger.warning(
                "the initial administrator (%s) is blocked; seeding does not lift a "
                "block, restore access with 'keystone-mcp users grant-admin'",
                result.user.email,
            )
    else:
        active_admins = await store.count_active_administrators()
        if active_admins == 0:
            logger.warning(
                "users directory has no active administrator; set "
                "KEYSTONE_MCP_SUPERADMIN_EMAIL or run "
                "'keystone-mcp users grant-admin --email ...'"
            )

    logger.info(
        "users directory ready",
        extra={"backend": "local", "db": store.db_url_redacted},
    )
