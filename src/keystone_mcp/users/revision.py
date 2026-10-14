"""Revision-marker writers for the built-in users directory.

A mutation bumps a monotonic counter after it commits, so every cached
resolver (``keystone_mcp.user_directory``) notices the change once it next
reads the marker, rather than waiting out its TTL. This module only *writes*
the marker; ``keystone_mcp.user_directory.revision`` reads it. The two sides
share the same key (``settings.users_redis_revision_key``) but not any code,
because ``keystone_mcp.users`` must not import ``keystone_mcp.user_directory``
(that would create an import cycle: user_directory -> users -> user_directory).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class RevisionWriter(Protocol):
    """Bumps the shared users-directory revision marker."""

    async def bump(self) -> int: ...


class RedisRevisionWriter:
    """``INCR`` the shared revision key, opening a fresh client per call.

    A server process runs ``bootstrap_platform`` inside one ``asyncio.run``
    call and then serves requests on a different event loop; a client opened
    once at construction time would be bound to whichever loop happened to be
    running then. Mutations are rare (an administrator action), so paying for
    a new connection each time is cheap compared to that failure mode.
    """

    def __init__(self, redis_url: str, *, key: str) -> None:
        self._redis_url = redis_url
        self._key = key

    async def bump(self) -> int:
        from keystone_mcp.redis_client import redis_from_url

        client = redis_from_url(self._redis_url)
        try:
            return await client.incr(self._key)
        finally:
            await client.aclose()


class InProcessRevisionWriter:
    """Bumps an in-process counter, for running without Redis.

    Takes a plain callable rather than ``InMemoryRevisionReader`` itself,
    since ``keystone_mcp.users`` does not import ``keystone_mcp.user_directory``
    (see module docstring); the caller wires the two together.
    """

    def __init__(self, bump: Callable[[], int]) -> None:
        self._bump = bump

    async def bump(self) -> int:
        return self._bump()


class NullRevisionWriter:
    """Does nothing; used when there is no shared state to invalidate."""

    async def bump(self) -> int:
        return 0
