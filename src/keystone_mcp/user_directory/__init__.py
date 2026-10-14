"""Fail-closed user-directory resolver and the ``UserDirectory`` protocol.

Importing this package eagerly loads only ``protocol``, ``types``, ``errors``,
and ``critical`` -- none of which import ``fastmcp``, ``mcp``, ``starlette``,
``httpx``, ``sqlalchemy``, or ``redis`` (see
``tests/test_user_directory_protocol.py::test_protocol_and_types_are_dependency_free``,
which imports ``keystone_mcp.user_directory.protocol`` directly and therefore
always runs this file first). Concrete implementations (``local``, ``http``,
``memory``), the cached resolver, and the factory functions pull in httpx,
redis, and (for ``local``) SQLAlchemy, so they are exposed lazily through
``__getattr__`` below instead of being imported at module scope: accessing
``keystone_mcp.user_directory.build_user_directory_resolver`` (for example)
still works exactly as a normal import, just deferred to first use.
"""

from __future__ import annotations

from typing import Any

from keystone_mcp.user_directory.critical import (
    CORE_CRITICAL_PATTERNS,
    CriticalToolMatcher,
    is_critical_tool,
)
from keystone_mcp.user_directory.errors import (
    ActorEmailRequiredError,
    DirectoryTimeoutError,
    InvalidRoleError,
    InvalidUserFieldError,
    LastAdministratorError,
    SelfAdminMutationError,
    UserAlreadyExistsError,
    UserDirectoryError,
    UserDirectoryUnavailableError,
    UserNotFoundError,
    UsersError,
    UsersStoreUnavailableError,
)
from keystone_mcp.user_directory.protocol import (
    ApiKeyIdIndex,
    Capability,
    UserDirectory,
    UserDirectoryAdmin,
    UserDirectoryBackend,
    UserDirectoryResolver,
)
from keystone_mcp.user_directory.types import MutationResult, UserRecord, UserResolveResult

__all__ = [
    "ActorEmailRequiredError",
    "ApiKeyIdIndex",
    "CORE_CRITICAL_PATTERNS",
    "CachedUserDirectoryResolver",
    "Capability",
    "CriticalToolMatcher",
    "DirectoryTimeoutError",
    "InvalidRoleError",
    "InvalidUserFieldError",
    "LastAdministratorError",
    "MutationResult",
    "SelfAdminMutationError",
    "UserAlreadyExistsError",
    "UserDirectory",
    "UserDirectoryAdmin",
    "UserDirectoryBackend",
    "UserDirectoryError",
    "UserDirectoryResolver",
    "UserDirectoryUnavailableError",
    "UserNotFoundError",
    "UserRecord",
    "UserResolveResult",
    "UsersError",
    "UsersStoreUnavailableError",
    "build_in_memory_user_directory_resolver",
    "build_user_directory",
    "build_user_directory_resolver",
    "is_critical_tool",
    "validate_directory_capabilities",
]

#: Names only available through the lazy factory/resolver modules (httpx, redis).
_LAZY_FACTORY_NAMES = frozenset(
    {
        "build_in_memory_user_directory_resolver",
        "build_user_directory",
        "build_user_directory_resolver",
        "validate_directory_capabilities",
    }
)


def __getattr__(name: str) -> Any:
    if name == "CachedUserDirectoryResolver":
        from keystone_mcp.user_directory.resolver import CachedUserDirectoryResolver

        return CachedUserDirectoryResolver
    if name in _LAZY_FACTORY_NAMES:
        from keystone_mcp.user_directory import factory

        return getattr(factory, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
