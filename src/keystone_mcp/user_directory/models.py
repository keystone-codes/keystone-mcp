"""Resolved user state returned by the directory client."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class UserResolveResult:
    """Effective roles and block state for a verified email."""

    exists: bool
    roles: tuple[str, ...]
    is_blocked: bool
    from_cache: bool = False
    revision: int | None = None

    @property
    def is_allow_decision(self) -> bool:
        """Whether the outcome permits RBAC evaluation (known, active, has roles)."""
        return self.exists and not self.is_blocked and bool(self.roles)
