"""In-memory users-directory backend for local development and tests."""

from __future__ import annotations

from dataclasses import dataclass, field

from keystone_mcp.user_directory.models import UserResolveResult
from keystone_mcp.user_directory.util import normalize_email


@dataclass
class InMemoryUserDirectoryBackend:
    """Dev stub implementing GET /v1/users/resolve semantics."""

    _users: dict[str, tuple[tuple[str, ...], bool]] = field(default_factory=dict)
    unavailable: bool = False

    def seed(
        self,
        email: str,
        *,
        roles: tuple[str, ...] | list[str] = (),
        is_blocked: bool = False,
    ) -> None:
        normalized = normalize_email(email)
        self._users[normalized] = (tuple(roles), is_blocked)

    def block(self, email: str) -> None:
        normalized = normalize_email(email)
        if normalized not in self._users:
            raise KeyError(email)
        roles, _ = self._users[normalized]
        self._users[normalized] = (roles, True)

    def set_roles(self, email: str, roles: tuple[str, ...] | list[str]) -> None:
        normalized = normalize_email(email)
        if normalized not in self._users:
            raise KeyError(email)
        _, blocked = self._users[normalized]
        self._users[normalized] = (tuple(roles), blocked)

    async def resolve_user(self, email: str) -> UserResolveResult:
        if self.unavailable:
            raise OSError("users directory unavailable")
        normalized = normalize_email(email)
        record = self._users.get(normalized)
        if record is None:
            return UserResolveResult(exists=False, roles=(), is_blocked=False)
        roles, is_blocked = record
        return UserResolveResult(
            exists=True,
            roles=roles,
            is_blocked=is_blocked,
        )

    async def aclose(self) -> None:
        return None
