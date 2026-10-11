"""Revision marker reader backed by shared platform Redis."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from redis.asyncio import Redis
from redis.exceptions import RedisError

from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError


@runtime_checkable
class RevisionReader(Protocol):
    async def current(self) -> int: ...

    async def aclose(self) -> None: ...


class InMemoryRevisionReader:
    """Test double for the shared km:users:revision marker."""

    def __init__(self, *, initial: int = 0) -> None:
        self._revision = initial

    async def current(self) -> int:
        return self._revision

    def bump(self) -> int:
        self._revision += 1
        return self._revision

    def set(self, value: int) -> None:
        self._revision = value

    async def aclose(self) -> None:
        return None


def _parse_revision_value(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise UserDirectoryUnavailableError(
            "users directory revision marker is invalid",
            code="revision_unavailable",
        ) from exc


class RedisRevisionReader:
    """Reads the monotonic users-directory revision from shared Redis."""

    def __init__(
        self,
        client: Redis,
        *,
        key: str,
        owns_client: bool = False,
    ) -> None:
        self._client = client
        self._key = key
        self._owns_client = owns_client

    async def current(self) -> int:
        try:
            value = await self._client.get(self._key)
        except RedisError as exc:
            raise UserDirectoryUnavailableError(
                "users directory revision marker is unavailable",
                code="revision_unavailable",
            ) from exc
        if value is None:
            return 0
        return _parse_revision_value(value)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
