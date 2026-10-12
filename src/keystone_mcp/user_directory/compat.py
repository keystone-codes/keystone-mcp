"""Wraps the deprecated 0.4.0 ``UserDirectoryBackend`` as a read-only ``UserDirectory``.

A fork that implemented ``UserDirectoryBackend`` (one method, ``resolve_user``)
against ``docs/adding-routes.md`` (0.4.0, C10) keeps working in 0.5.0 without
changes to its own code: :func:`keystone_mcp.user_directory.factory.build_user_directory_resolver`
wraps whatever it is given in :class:`ReadOnlyBackendDirectory` and warns once.
Removed in 0.6.0 -- new directories should implement
:class:`~keystone_mcp.user_directory.protocol.UserDirectory` directly.
"""

from __future__ import annotations

import logging

from keystone_mcp.user_directory.protocol import UserDirectoryBackend
from keystone_mcp.user_directory.types import UserRecord, UserResolveResult

logger = logging.getLogger(__name__)


class ReadOnlyBackendDirectory:
    """Adapts a legacy :class:`UserDirectoryBackend` to :class:`UserDirectory`.

    Declares no capabilities: Keystone publishes only ``users_list`` for it,
    and even that comes back empty, since the wrapped backend never exposed a
    listing endpoint (a warning is logged once, not on every call).
    """

    def __init__(self, backend: UserDirectoryBackend) -> None:
        self._backend = backend
        self._warned_list = False

    @property
    def name(self) -> str:
        return type(self._backend).__name__

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset()

    async def resolve_user(self, subject: str) -> UserResolveResult:
        return await self._backend.resolve_user(subject)

    async def list_users(
        self,
        *,
        is_blocked: bool | None = False,
        role: str | None = None,
        email_contains: str | None = None,
    ) -> list[UserRecord]:
        if not self._warned_list:
            logger.warning(
                "legacy UserDirectoryBackend %s cannot list users; users_list "
                "will always return an empty list for it",
                self.name,
            )
            self._warned_list = True
        return []

    async def ping(self) -> None:
        return None

    async def aclose(self) -> None:
        await self._backend.aclose()
