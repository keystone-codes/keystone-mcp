"""Cached fail-closed user-directory resolver."""

from __future__ import annotations

import httpx

from keystone_mcp.user_directory.cache import ResolutionCache
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker
from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.protocol import UserDirectory
from keystone_mcp.user_directory.revision import RevisionReader
from keystone_mcp.user_directory.types import UserResolveResult, parse_service_subject
from keystone_mcp.user_directory.util import normalize_email


def _normalize_subject(subject: str) -> str:
    if parse_service_subject(subject) is not None:
        return subject.strip().lower()
    return normalize_email(subject)


class CachedUserDirectoryResolver:
    """Fail-closed resolver with revision-aware cache and circuit breaker."""

    def __init__(
        self,
        backend: UserDirectory,
        *,
        revision_reader: RevisionReader,
        cache: ResolutionCache,
        circuit_breaker: CircuitBreaker,
    ) -> None:
        self._backend = backend
        self._revision_reader = revision_reader
        self._cache = cache
        self._circuit = circuit_breaker
        self._seen_revision: int | None = None

    @property
    def backend(self) -> UserDirectory:
        """The wrapped backend, for callers that need it (e.g. readiness checks)."""
        return self._backend

    async def resolve(self, email: str, *, critical: bool = False) -> UserResolveResult:
        normalized = _normalize_subject(email)
        revision = await self._revision_reader.current()
        await self._sync_revision(revision)

        cached = self._cache.get(
            normalized,
            revision=revision,
            bypass_allow_cache=critical,
        )
        if cached is not None:
            return cached

        if self._circuit.is_open():
            raise UserDirectoryUnavailableError(
                "users directory circuit breaker is open",
                code="circuit_open",
            )

        try:
            result = await self._backend.resolve_user(normalized)
        except UserDirectoryUnavailableError:
            self._circuit.record_failure()
            raise
        except (httpx.HTTPError, OSError) as exc:
            self._circuit.record_failure()
            raise UserDirectoryUnavailableError(
                "users directory is unavailable",
                code="catalog_unavailable",
            ) from exc

        self._circuit.record_success()
        fresh = UserResolveResult(
            exists=result.exists,
            roles=result.roles,
            is_blocked=result.is_blocked,
            subject_type=result.subject_type,
            from_cache=False,
            revision=revision,
        )
        self._cache.put(normalized, fresh, revision=revision)
        return fresh

    async def _sync_revision(self, revision: int) -> None:
        if self._seen_revision is None:
            self._seen_revision = revision
            return
        if revision != self._seen_revision:
            self._cache.clear()
            self._seen_revision = revision

    async def aclose(self) -> None:
        await self._backend.aclose()
        await self._revision_reader.aclose()
