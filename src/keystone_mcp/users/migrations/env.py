"""Alembic environment for the users directory.

Online mode only: the connection always comes in through
``config.attributes["connection"]``, set up by ``keystone_mcp.users.migrate``.
There is no offline (``--sql``) mode and no CLI-driven ``alembic.ini``.

Does not call ``logging.config.fileConfig`` — that would overwrite Keystone's
own logging configuration.
"""

from __future__ import annotations

from alembic import context

from keystone_mcp.users.migrate import VERSION_TABLE
from keystone_mcp.users.models import Base

config = context.config
target_metadata = Base.metadata


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")
    if connection is None:
        raise RuntimeError(
            "offline migrations are not supported; call keystone_mcp.users.migrate."
            "upgrade_to_head(engine) instead"
        )

    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        version_table=VERSION_TABLE,
        render_as_batch=(connection.dialect.name == "sqlite"),
    )

    with context.begin_transaction():
        context.run_migrations()


run_migrations_online()
