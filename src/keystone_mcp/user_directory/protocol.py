"""Protocols for user-directory backends and cached resolvers."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from keystone_mcp.user_directory.models import UserResolveResult


@runtime_checkable
class UserDirectoryBackend(Protocol):
    """Low-level S2S client for GET /v1/users/resolve."""

    async def resolve_user(self, email: str) -> UserResolveResult: ...

    async def aclose(self) -> None: ...


@runtime_checkable
class UserDirectoryResolver(Protocol):
    """Cached fail-closed resolver used by login and RBAC enforcement."""

    async def resolve(self, email: str, *, critical: bool = False) -> UserResolveResult: ...

    async def aclose(self) -> None: ...
