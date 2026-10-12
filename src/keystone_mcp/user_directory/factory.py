"""Factory wiring Settings, Redis, and directory implementations.

``local`` and ``http`` (and the legacy ``UserDirectoryBackend`` wrapper) are
imported lazily, inside the functions below, so that ``import
keystone_mcp.user_directory`` alone never pulls in SQLAlchemy or httpx (see
``tests/test_user_directory_protocol.py::test_protocol_and_types_are_dependency_free``).
"""

from __future__ import annotations

import logging
import warnings
from typing import TYPE_CHECKING

from redis.asyncio import Redis

from keystone_mcp.config import ConfigError, Settings
from keystone_mcp.user_directory.cache import ResolutionCache
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker
from keystone_mcp.user_directory.protocol import (
    ServiceAccountDirectory,
    UserDirectory,
    UserDirectoryAdmin,
    UserDirectoryBackend,
)
from keystone_mcp.user_directory.resolver import CachedUserDirectoryResolver
from keystone_mcp.user_directory.revision import (
    InMemoryRevisionReader,
    RedisRevisionReader,
    RevisionReader,
)

if TYPE_CHECKING:
    from keystone_mcp.users.store import UsersStore

logger = logging.getLogger(__name__)


def validate_directory_capabilities(directory: UserDirectory) -> UserDirectory:
    """Refuse a directory that declares ``"admin"`` without implementing it.

    Applied to every directory this module builds, and reusable by whatever
    builds one from elsewhere (a plugin loaded through an entry point, X09)
    so the same mistake is caught the same way everywhere.
    """
    if "admin" in directory.capabilities and not isinstance(directory, UserDirectoryAdmin):
        raise ConfigError(
            f"users directory {directory.name!r} declares 'admin' but does not "
            "implement UserDirectoryAdmin"
        )
    if "service_accounts" in directory.capabilities and not isinstance(
        directory, ServiceAccountDirectory
    ):
        raise ConfigError(
            f"users directory {directory.name!r} declares 'service_accounts' but does not "
            "implement ServiceAccountDirectory"
        )
    return directory


def build_user_directory(
    settings: Settings,
    *,
    users_store: UsersStore | None = None,
) -> UserDirectory:
    """Build the ``local`` or ``http`` directory named by ``settings.users_backend``.

    Raises :class:`~keystone_mcp.config.ConfigError` if a directory declares
    the ``"admin"`` capability without actually implementing
    :class:`~keystone_mcp.user_directory.protocol.UserDirectoryAdmin` -- a
    configuration mistake caught at startup rather than on the first
    ``users_*`` call.
    """
    directory: UserDirectory
    if settings.users_backend == "http":
        from keystone_mcp.user_directory.http import HttpUserDirectory

        directory = HttpUserDirectory(
            base_url=settings.users_service_url,
            service_token=settings.users_service_token,
            timeout_seconds=settings.users_service_timeout_seconds,
        )
    else:
        from keystone_mcp.user_directory.local import LocalUserDirectory
        from keystone_mcp.users.factory import build_users_store

        directory = LocalUserDirectory(users_store or build_users_store(settings))
    return validate_directory_capabilities(directory)


def build_user_directory_resolver(
    settings: Settings,
    *,
    directory: UserDirectory | None = None,
    backend: UserDirectoryBackend | None = None,
    revision_reader: RevisionReader | None = None,
    redis_client: Redis | None = None,
    users_store: UsersStore | None = None,
) -> CachedUserDirectoryResolver:
    """Construct the cached resolver from platform settings.

    ``backend`` is the deprecated 0.4.0 keyword (a single-method
    ``UserDirectoryBackend``): passing it wraps it in
    :class:`~keystone_mcp.user_directory.compat.ReadOnlyBackendDirectory` and
    emits a :class:`DeprecationWarning`. Prefer ``directory=``.
    """
    resolved_directory = directory
    if resolved_directory is None and backend is not None:
        warnings.warn(
            "UserDirectoryBackend is deprecated; implement "
            "keystone_mcp.user_directory.UserDirectory. Deprecated since "
            "0.5.0, removed in 2.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        from keystone_mcp.user_directory.compat import ReadOnlyBackendDirectory

        resolved_directory = ReadOnlyBackendDirectory(backend)
    if resolved_directory is None:
        resolved_directory = build_user_directory(settings, users_store=users_store)

    resolved_revision = revision_reader
    if resolved_revision is None:
        if redis_client is not None:
            resolved_revision = RedisRevisionReader(
                redis_client,
                key=settings.users_redis_revision_key,
            )
        elif settings.redis_url.strip():
            client = Redis.from_url(settings.redis_url, decode_responses=True)
            resolved_revision = RedisRevisionReader(
                client,
                key=settings.users_redis_revision_key,
                owns_client=True,
            )
        else:
            logger.warning(
                "KEYSTONE_MCP_REDIS_URL is unset; user-directory revision reader "
                "uses in-memory stub (cache invalidation across processes disabled)"
            )
            if settings.rbac_mode in ("observe", "enforce"):
                logger.warning(
                    "RBAC mode %s without KEYSTONE_MCP_REDIS_URL; "
                    "revision-based cache invalidation will not work in production",
                    settings.rbac_mode,
                )
            resolved_revision = InMemoryRevisionReader()

    cache = ResolutionCache(
        allow_ttl_seconds=settings.users_cache_allow_ttl_seconds,
        deny_ttl_seconds=settings.users_cache_deny_ttl_seconds,
    )
    circuit = CircuitBreaker(
        failure_threshold=settings.users_circuit_failure_threshold,
        recovery_seconds=float(settings.users_circuit_recovery_seconds),
    )
    return CachedUserDirectoryResolver(
        resolved_directory,
        revision_reader=resolved_revision,
        cache=cache,
        circuit_breaker=circuit,
    )


def build_in_memory_user_directory_resolver(
    *,
    allow_ttl_seconds: float = 60.0,
    deny_ttl_seconds: float = 30.0,
    failure_threshold: int = 3,
    recovery_seconds: float = 30.0,
):
    """Convenience helper for unit tests and local development."""
    from keystone_mcp.user_directory.memory import InMemoryUserDirectory

    directory = InMemoryUserDirectory()
    revision_reader = InMemoryRevisionReader()
    resolver = CachedUserDirectoryResolver(
        directory,
        revision_reader=revision_reader,
        cache=ResolutionCache(
            allow_ttl_seconds=allow_ttl_seconds,
            deny_ttl_seconds=deny_ttl_seconds,
        ),
        circuit_breaker=CircuitBreaker(
            failure_threshold=failure_threshold,
            recovery_seconds=recovery_seconds,
        ),
    )
    return resolver, directory, revision_reader
