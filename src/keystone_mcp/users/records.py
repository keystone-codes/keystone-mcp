"""Immutable, serializable records returned by the users directory service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from keystone_mcp.users.models import UserRow


def _iso_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class UserRecord:
    """A user row shaped for tool and API responses."""

    email: str
    full_name: str
    roles: tuple[str, ...]
    is_blocked: bool
    created_at: datetime
    updated_at: datetime
    created_by: str | None
    note: str | None

    @classmethod
    def from_row(cls, row: UserRow) -> UserRecord:
        return cls(
            email=row.email,
            full_name=row.full_name,
            roles=tuple(sorted({assignment.role for assignment in row.roles})),
            is_blocked=row.is_blocked,
            created_at=row.created_at,
            updated_at=row.updated_at,
            created_by=row.created_by,
            note=row.note,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "full_name": self.full_name,
            "roles": list(self.roles),
            "is_blocked": self.is_blocked,
            "created_at": _iso_utc(self.created_at),
            "updated_at": _iso_utc(self.updated_at),
            "created_by": self.created_by,
            "note": self.note,
        }


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
