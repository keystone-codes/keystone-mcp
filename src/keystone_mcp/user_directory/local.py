"""Built-in users directory backend: reads from the server's own database."""

from __future__ import annotations

from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.models import UserResolveResult
from keystone_mcp.user_directory.util import normalize_email
from keystone_mcp.users.errors import UsersStoreUnavailableError
from keystone_mcp.users.store import UsersStore


class LocalUserDirectoryBackend:
    """Adapts :class:`~keystone_mcp.users.store.UsersStore` to ``UserDirectoryBackend``.

    A thin translation layer: the cache, circuit breaker, and revision-based
    invalidation in :class:`~keystone_mcp.user_directory.resolver.CachedUserDirectoryResolver`
    work exactly as they do with the HTTP backend, because an unavailable
    store raises the same kind of error an unreachable HTTP service would.
    """

    def __init__(self, store: UsersStore) -> None:
        self._store = store

    async def ping(self) -> None:
        """Delegate to :meth:`UsersStore.ping` (``SELECT 1``) for readiness checks."""
        await self._store.ping()

    async def resolve_user(self, email: str) -> UserResolveResult:
        try:
            resolved = await self._store.resolve(normalize_email(email))
        except UsersStoreUnavailableError as exc:
            raise UserDirectoryUnavailableError(
                "users directory is unavailable",
                code="catalog_unavailable",
            ) from exc
        return UserResolveResult(
            exists=resolved.exists,
            roles=resolved.roles,
            is_blocked=resolved.is_blocked,
        )

    async def aclose(self) -> None:
        # The store's engine is owned by whoever built it (the server), not
        # by this backend, so there is nothing to close here.
        return None
