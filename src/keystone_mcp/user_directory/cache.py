"""In-memory TTL cache with separate allow/deny lifetimes."""

from __future__ import annotations

import time
from dataclasses import dataclass

from keystone_mcp.user_directory.models import UserResolveResult


@dataclass(slots=True)
class _CacheEntry:
    result: UserResolveResult
    expires_at: float
    revision: int


class ResolutionCache:
    """Per-email cache keyed by normalized email."""

    def __init__(self, *, allow_ttl_seconds: float, deny_ttl_seconds: float) -> None:
        self._allow_ttl = allow_ttl_seconds
        self._deny_ttl = deny_ttl_seconds
        self._entries: dict[str, _CacheEntry] = {}

    def clear(self) -> None:
        self._entries.clear()

    def get(
        self,
        email: str,
        *,
        revision: int,
        bypass_allow_cache: bool = False,
    ) -> UserResolveResult | None:
        entry = self._entries.get(email)
        if entry is None:
            return None
        if entry.revision != revision:
            self._entries.pop(email, None)
            return None
        if time.monotonic() >= entry.expires_at:
            self._entries.pop(email, None)
            return None
        if bypass_allow_cache and entry.result.is_allow_decision:
            return None
        cached = UserResolveResult(
            exists=entry.result.exists,
            roles=entry.result.roles,
            is_blocked=entry.result.is_blocked,
            subject_type=entry.result.subject_type,
            from_cache=True,
            revision=entry.revision,
        )
        return cached

    def put(self, email: str, result: UserResolveResult, *, revision: int) -> None:
        ttl = self._allow_ttl if result.is_allow_decision else self._deny_ttl
        self._entries[email] = _CacheEntry(
            result=result,
            expires_at=time.monotonic() + ttl,
            revision=revision,
        )
