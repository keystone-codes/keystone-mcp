"""Test helper: a migrated UsersStore over a temporary SQLite file."""

from __future__ import annotations

from pathlib import Path

from keystone_mcp.user_directory.revision import InMemoryRevisionReader
from keystone_mcp.users.db import create_users_engine
from keystone_mcp.users.revision import InProcessRevisionWriter, RevisionWriter
from keystone_mcp.users.store import UsersStore


async def make_users_store(
    tmp_path: Path,
    *,
    revision: RevisionWriter | None = None,
) -> tuple[UsersStore, InMemoryRevisionReader]:
    """Build and migrate a ``UsersStore`` backed by a temp-dir SQLite file.

    Returns the store alongside an ``InMemoryRevisionReader`` whose counter
    the store's writer bumps (unless a different ``revision`` writer was
    passed in, in which case the reader is a standalone, unlinked counter
    callers can ignore).
    """
    engine = create_users_engine(f"sqlite:///{tmp_path}/keystone-users.db")
    shared_revision = InMemoryRevisionReader()
    writer = revision or InProcessRevisionWriter(shared_revision.bump)
    store = UsersStore(engine, revision=writer)
    await store.migrate()
    return store, shared_revision
