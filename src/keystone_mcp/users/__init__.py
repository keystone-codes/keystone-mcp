"""Built-in users directory: domain rules and storage.

This package owns the people and role data Keystone used to fetch over HTTP
from a separate directory service. It has no side effects at import time and
does not import ``keystone_mcp.user_directory``, ``keystone_mcp.server``,
``keystone_mcp.adapters`` or ``keystone_mcp.config`` — those layers (reading
through a cache, wiring into the server, the HTTP admin adapter) depend on
this package, not the other way around.
"""

from __future__ import annotations

from keystone_mcp.users.db import (
    UsersConfigError,
    check_users_db_url,
    create_users_engine,
    make_session_factory,
    redact_db_url,
    session_scope,
)
from keystone_mcp.users.emails import normalize_email, require_valid_email
from keystone_mcp.users.errors import (
    ActorEmailRequiredError,
    InvalidRoleError,
    InvalidUserFieldError,
    LastAdministratorError,
    SelfAdminMutationError,
    UserAlreadyExistsError,
    UserNotFoundError,
    UsersError,
    UsersStoreUnavailableError,
)
from keystone_mcp.users.migrate import HEAD_REVISION, current_revision, upgrade_to_head
from keystone_mcp.users.records import ResolvedUser, UserRecord
from keystone_mcp.users.roles import ROLE_ADMINISTRATOR, check_role_name, normalize_roles

__all__ = [
    "ROLE_ADMINISTRATOR",
    "HEAD_REVISION",
    "ActorEmailRequiredError",
    "InvalidRoleError",
    "InvalidUserFieldError",
    "LastAdministratorError",
    "ResolvedUser",
    "SelfAdminMutationError",
    "UserAlreadyExistsError",
    "UserNotFoundError",
    "UserRecord",
    "UsersConfigError",
    "UsersError",
    "UsersStoreUnavailableError",
    "check_role_name",
    "check_users_db_url",
    "create_users_engine",
    "current_revision",
    "make_session_factory",
    "normalize_email",
    "normalize_roles",
    "redact_db_url",
    "require_valid_email",
    "session_scope",
    "upgrade_to_head",
]
