"""Immutable, serializable records returned by the users directory service.

``UserRecord`` itself lives in :mod:`keystone_mcp.user_directory.types` (X06):
it is shared by every ``UserDirectory`` implementation, not just this
database-backed one. :func:`user_record_from_row` is what used to be
``UserRecord.from_row`` -- the one piece of that conversion that is specific
to this package's own ORM row.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from keystone_mcp.user_directory.types import UserRecord
from keystone_mcp.users.models import UserRow

__all__ = ["ImportedUser", "ResolvedUser", "UserRecord", "user_record_from_row"]


def user_record_from_row(row: UserRow) -> UserRecord:
    return UserRecord(
        email=row.email,
        full_name=row.full_name,
        roles=tuple(sorted({assignment.role for assignment in row.roles})),
        is_blocked=row.is_blocked,
        created_at=row.created_at,
        updated_at=row.updated_at,
        created_by=row.created_by,
        note=row.note,
    )


@dataclass(frozen=True, slots=True)
class ResolvedUser:
    """The answer to "does this user exist, and what can they do"."""

    exists: bool
    roles: tuple[str, ...]
    is_blocked: bool


@dataclass(frozen=True, slots=True)
class ImportedUser:
    """One user record as read from an external users directory.

    Produced by :func:`keystone_mcp.users.importer.fetch_source_users`; roles
    here are exactly what the source reported, unfiltered by any policy — role
    filtering happens in :func:`keystone_mcp.users.service.upsert_imported_user`.
    """

    email: str
    full_name: str
    roles: tuple[str, ...]
    is_blocked: bool
    note: str | None
    created_by: str | None
    created_at: datetime | None
    updated_at: datetime | None
