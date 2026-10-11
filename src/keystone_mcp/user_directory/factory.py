"""Factory wiring Settings, Redis, and directory backends."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from redis.asyncio import Redis

from keystone_mcp.config import Settings
from keystone_mcp.user_directory.cache import ResolutionCache
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker
from keystone_mcp.user_directory.http import HttpUserDirectoryBackend
from keystone_mcp.user_directory.local import LocalUserDirectoryBackend
from keystone_mcp.user_directory.memory import InMemoryUserDirectoryBackend
from keystone_mcp.user_directory.protocol import UserDirectoryBackend
from keystone_mcp.user_directory.resolver import CachedUserDirectoryResolver
from keystone_mcp.user_directory.revision import (
    InMemoryRevisionReader,
    RedisRevisionReader,
    RevisionReader,
)

if TYPE_CHECKING:
    from keystone_mcp.users.store import UsersStore

logger = logging.getLogger(__name__)


def build_user_directory_resolver(
    settings: Settings,
    *,
    backend: UserDirectoryBackend | None = None,
    revision_reader: RevisionReader | None = None,
    redis_client: Redis | None = None,
    users_store: UsersStore | None = None,
) -> CachedUserDirectoryResolver:
    """Construct the cached resolver from platform settings."""
    resolved_backend = backend
    if resolved_backend is None:
        if settings.users_backend == "http":
            resolved_backend = HttpUserDirectoryBackend(
                base_url=settings.users_service_url,
                service_token=settings.users_service_token,
                timeout_seconds=settings.users_service_timeout_seconds,
            )
        else:
            from keystone_mcp.users.factory import build_users_store

            resolved_backend = LocalUserDirectoryBackend(users_store or build_users_store(settings))
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
        resolved_backend,
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
) -> tuple[CachedUserDirectoryResolver, InMemoryUserDirectoryBackend, InMemoryRevisionReader]:
    """Convenience helper for unit tests and local development."""
    backend = InMemoryUserDirectoryBackend()
    revision_reader = InMemoryRevisionReader()
    resolver = CachedUserDirectoryResolver(
        backend,
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
    return resolver, backend, revision_reader
