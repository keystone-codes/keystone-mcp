"""Dependency-free data types shared by every ``UserDirectory`` implementation.

This module imports nothing from ``keystone_mcp`` beyond the standard library:
a directory implementation (built-in, HTTP, or a third-party plugin) depends
on these types, never the other way around, and nothing here should ever pull
in ``fastmcp``, ``mcp``, ``httpx``, ``sqlalchemy`` or ``redis`` transitively
(see ``tests/test_user_directory_protocol.py::test_protocol_and_types_are_dependency_free``).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


def _iso_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class UserRecord:
    """A directory entry shaped for tool and API responses.

    Produced by every ``UserDirectory`` implementation's ``resolve_user``,
    ``list_users``, and (when supported) ``UserDirectoryAdmin`` methods. The
    built-in directory builds one from its own database row through
    :func:`keystone_mcp.users.records.user_record_from_row`; an HTTP or
    plugin-supplied directory builds one directly.
    """

    email: str
    full_name: str
    roles: tuple[str, ...]
    is_blocked: bool
    created_at: datetime
    updated_at: datetime
    created_by: str | None
    note: str | None

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
class MutationResult:
    """The outcome of one ``UserDirectoryAdmin`` write.

    ``roles_before`` and ``blocked_before`` are ``None`` when the directory
    cannot report the prior state (for example, the HTTP contract's responses
    carry no "before" snapshot) -- this is a normal case, not a missing value
    to be treated as empty: callers building an audit record must read
    ``None`` as "unknown", not as "no roles"/"was not blocked".
    """

    user: UserRecord
    changed: bool
    created: bool = False
    roles_before: tuple[str, ...] | None = None
    blocked_before: bool | None = None


@dataclass(frozen=True, slots=True)
class UserResolveResult:
    """Effective roles and block state for a verified subject."""

    exists: bool
    roles: tuple[str, ...]
    is_blocked: bool
    from_cache: bool = False
    revision: int | None = None

    @property
    def is_allow_decision(self) -> bool:
        """Whether the outcome permits RBAC evaluation (known, active, has roles)."""
        return self.exists and not self.is_blocked and bool(self.roles)
