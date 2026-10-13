"""Deprecated location of the users domain errors -- re-exported (X06).

These error classes moved to :mod:`keystone_mcp.user_directory.errors`
alongside the read-path's ``UserDirectoryUnavailableError`` (X06), since both
are "classes from ``keystone_mcp.user_directory.errors``" per the
``UserDirectory`` protocol's error rule. This module is kept only so existing
imports of ``keystone_mcp.users.errors.*`` keep working; new code should
import from ``keystone_mcp.user_directory.errors`` directly.

Error codes follow ``skills/keystone-user-admin/SKILL.md`` (table "Errors"),
which is what the ``users_*`` tool adapter promises its callers.
"""

from __future__ import annotations

from keystone_mcp.user_directory.errors import (
    ActorEmailRequiredError,
    DirectoryTimeoutError,
    InvalidRoleError,
    InvalidUserFieldError,
    LastAdministratorError,
    SelfAdminMutationError,
    UserAlreadyExistsError,
    UserNotFoundError,
    UsersError,
    UsersStoreUnavailableError,
)

__all__ = [
    "ActorEmailRequiredError",
    "DirectoryTimeoutError",
    "InvalidRoleError",
    "InvalidUserFieldError",
    "LastAdministratorError",
    "SelfAdminMutationError",
    "UserAlreadyExistsError",
    "UserNotFoundError",
    "UsersError",
    "UsersStoreUnavailableError",
]
