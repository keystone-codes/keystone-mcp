"""Builds a :class:`~keystone_mcp.users.store.UsersStore` from ``Settings``.

This module may import :mod:`keystone_mcp.config` (the reverse is not true:
``config.py`` only reaches into ``keystone_mcp.users`` from inside
``validate_settings``, importing locally, so that importing ``config`` alone
never pulls in SQLAlchemy).
"""

from __future__ import annotations

import logging

from keystone_mcp.config import Settings
from keystone_mcp.users.db import create_users_engine
from keystone_mcp.users.revision import NullRevisionWriter, RedisRevisionWriter, RevisionWriter
from keystone_mcp.users.store import UsersStore

logger = logging.getLogger(__name__)


def build_users_store(
    settings: Settings,
    *,
    revision_writer: RevisionWriter | None = None,
) -> UsersStore:
    """Construct the store for the built-in users directory.

    The engine is lazy: no file is created and no connection is opened until
    the first query. ``revision_writer`` lets a caller share one writer across
    several stores (or substitute a test double); otherwise one is chosen
    from ``settings.redis_url``.
    """
    engine = create_users_engine(settings.users_db_url)

    writer = revision_writer
    if writer is None:
        if settings.redis_url.strip():
            writer = RedisRevisionWriter(settings.redis_url, key=settings.users_redis_revision_key)
        else:
            logger.warning(
                "KEYSTONE_MCP_REDIS_URL is unset; users directory revision writer "
                "is a no-op (cache invalidation across replicas disabled)"
            )
            writer = NullRevisionWriter()

    return UsersStore(engine, revision=writer)
