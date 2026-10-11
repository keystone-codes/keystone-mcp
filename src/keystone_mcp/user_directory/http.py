"""HTTP service-to-service client for the mcp-users directory."""

from __future__ import annotations

from typing import Any

import httpx

from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.models import UserResolveResult
from keystone_mcp.user_directory.util import normalize_email


def _parse_resolve_payload(payload: Any) -> UserResolveResult:
    if not isinstance(payload, dict):
        raise UserDirectoryUnavailableError(
            "users directory returned an invalid resolve response",
            code="catalog_unavailable",
        )
    roles_raw = payload.get("roles")
    if roles_raw is None:
        roles: tuple[str, ...] = ()
    elif isinstance(roles_raw, list):
        roles = tuple(str(role) for role in roles_raw)
    else:
        raise UserDirectoryUnavailableError(
            "users directory returned an invalid resolve response",
            code="catalog_unavailable",
        )
    return UserResolveResult(
        exists=bool(payload.get("exists")),
        roles=roles,
        is_blocked=bool(payload.get("is_blocked")),
    )


class HttpUserDirectoryBackend:
    """Calls GET /v1/users/resolve with Bearer service token."""

    def __init__(
        self,
        *,
        base_url: str,
        service_token: str,
        timeout_seconds: float,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(timeout_seconds),
            headers={"Authorization": f"Bearer {service_token}"},
        )

    async def resolve_user(self, email: str) -> UserResolveResult:
        try:
            response = await self._client.get(
                "/v1/users/resolve",
                params={"email": normalize_email(email)},
            )
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise UserDirectoryUnavailableError(
                "users directory request timed out",
                code="catalog_timeout",
            ) from exc
        except httpx.HTTPError as exc:
            raise UserDirectoryUnavailableError(
                "users directory is unavailable",
                code="catalog_unavailable",
            ) from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise UserDirectoryUnavailableError(
                "users directory returned an invalid resolve response",
                code="catalog_unavailable",
            ) from exc
        return _parse_resolve_payload(payload)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
