"""Factory wiring Settings, Redis, and directory implementations."""

from __future__ import annotations

import logging
import warnings
from typing import TYPE_CHECKING

from redis.asyncio import Redis

from keystone_mcp.config import ConfigError, Settings
from keystone_mcp.plugins import (
    USER_DIRECTORIES_GROUP,
    UserDirectoryFactory,
    build_plugin_context,
    discover,
    entry_point_label,
    load_factory,
)
from keystone_mcp.redis_client import redis_from_url
from keystone_mcp.user_directory.backend_config import load_users_backend_config
from keystone_mcp.user_directory.cache import ApiKeyVerificationCache, ResolutionCache
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker
from keystone_mcp.user_directory.protocol import (
    ApiKeyDirectory,
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
    """Refuse a directory that declares ``"admin"`` without implementing it."""
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
    if "api_keys" in directory.capabilities and not isinstance(directory, ApiKeyDirectory):
        raise ConfigError(
            f"users directory {directory.name!r} declares 'api_keys' but does not "
            "implement ApiKeyDirectory"
        )
    return directory


def build_user_directory(
    settings: Settings,
    *,
    users_store: UsersStore | None = None,
) -> UserDirectory:
    """Build the users directory named by ``settings.users_backend``."""
    backend_name = settings.users_backend
    context = build_plugin_context(settings)
    options: dict = {}
    config_path = settings.users_backend_config.strip()
    if config_path:
        options = load_users_backend_config(config_path)

    factory_obj = load_factory(USER_DIRECTORIES_GROUP, backend_name)
    if not callable(factory_obj):
        raise ConfigError(
            f"{USER_DIRECTORIES_GROUP} '{backend_name}' did not resolve to a callable factory"
        )
    factory: UserDirectoryFactory = factory_obj
    try:
        directory = factory(context, options)
    except ValueError as exc:
        raise ConfigError(f"users directory {backend_name!r}: {exc}") from exc

    if users_store is not None and backend_name == "local":
        from keystone_mcp.user_directory.local import LocalUserDirectory

        if isinstance(directory, LocalUserDirectory):
            directory = LocalUserDirectory(users_store)

    directory = validate_directory_capabilities(directory)
    ep = discover(USER_DIRECTORIES_GROUP)[backend_name]
    dist, version, _target = entry_point_label(ep)
    caps = ", ".join(sorted(directory.capabilities))
    logger.info(
        "users directory: %s from %s %s, capabilities [%s]",
        directory.name,
        dist,
        version,
        caps,
    )
    return directory


def build_user_directory_resolver(
    settings: Settings,
    *,
    directory: UserDirectory | None = None,
    backend: UserDirectoryBackend | None = None,
    revision_reader: RevisionReader | None = None,
    redis_client: Redis | None = None,
    users_store: UsersStore | None = None,
) -> CachedUserDirectoryResolver:
    """Construct the cached resolver from platform settings."""
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
            client = redis_from_url(settings.redis_url)
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

    allow_ttl = settings.users_cache_allow_ttl_seconds
    deny_ttl = settings.users_cache_deny_ttl_seconds
    cache = ResolutionCache(allow_ttl_seconds=allow_ttl, deny_ttl_seconds=deny_ttl)
    api_key_cache = ApiKeyVerificationCache(allow_ttl_seconds=allow_ttl, deny_ttl_seconds=deny_ttl)
    circuit = CircuitBreaker(
        failure_threshold=settings.users_circuit_failure_threshold,
        recovery_seconds=float(settings.users_circuit_recovery_seconds),
    )
    return CachedUserDirectoryResolver(
        resolved_directory,
        revision_reader=resolved_revision,
        cache=cache,
        circuit_breaker=circuit,
        api_key_cache=api_key_cache,
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
    resolution_cache = ResolutionCache(
        allow_ttl_seconds=allow_ttl_seconds,
        deny_ttl_seconds=deny_ttl_seconds,
    )
    resolver = CachedUserDirectoryResolver(
        directory,
        revision_reader=revision_reader,
        cache=resolution_cache,
        circuit_breaker=CircuitBreaker(
            failure_threshold=failure_threshold,
            recovery_seconds=recovery_seconds,
        ),
        api_key_cache=ApiKeyVerificationCache(
            allow_ttl_seconds=allow_ttl_seconds,
            deny_ttl_seconds=deny_ttl_seconds,
        ),
    )
    return resolver, directory, revision_reader
