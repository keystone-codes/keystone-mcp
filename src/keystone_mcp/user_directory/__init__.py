"""Fail-closed user-directory resolver client."""

from keystone_mcp.user_directory.critical import (
    CORE_CRITICAL_PATTERNS,
    CriticalToolMatcher,
    is_critical_tool,
)
from keystone_mcp.user_directory.errors import (
    UserDirectoryError,
    UserDirectoryUnavailableError,
)
from keystone_mcp.user_directory.factory import (
    build_in_memory_user_directory_resolver,
    build_user_directory_resolver,
)
from keystone_mcp.user_directory.http import HttpUserDirectoryBackend
from keystone_mcp.user_directory.local import LocalUserDirectoryBackend
from keystone_mcp.user_directory.memory import InMemoryUserDirectoryBackend
from keystone_mcp.user_directory.models import UserResolveResult
from keystone_mcp.user_directory.protocol import UserDirectoryBackend, UserDirectoryResolver

__all__ = [
    "CORE_CRITICAL_PATTERNS",
    "CriticalToolMatcher",
    "HttpUserDirectoryBackend",
    "InMemoryUserDirectoryBackend",
    "LocalUserDirectoryBackend",
    "UserDirectoryBackend",
    "UserDirectoryError",
    "UserDirectoryResolver",
    "UserDirectoryUnavailableError",
    "UserResolveResult",
    "build_in_memory_user_directory_resolver",
    "build_user_directory_resolver",
    "is_critical_tool",
]
