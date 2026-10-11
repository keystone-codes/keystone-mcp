"""file_ref adapter — mint a signed download link for a stored file.

Synchronous: the object is already in the object store by the time a link is
requested. The adapter resolves a ``file_id`` to its object key and asks the
backend to mint a signed, credential-free download URL
(``POST /api/v1/files/{key}/download-link``), carrying the verified identity.

There is no async pending state: a missing object surfaces as the backend's
``404``, mapped to an error result here.

Only ``eph:`` file_ids (user uploads) and bare object keys are resolvable here.
Any other prefix names a domain-specific id space this domain-neutral tool
cannot resolve, and is rejected.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import httpx

from keystone_mcp.adapters.base import http_error_result
from keystone_mcp.identity import AUTHOR_EMAIL_HEADER
from keystone_mcp.storage.eph_codec import EPH_PREFIX, unwrap_file_id

if TYPE_CHECKING:
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route

_FILE_ID_PREFIX = re.compile(r"^[a-z]+:")


class UnresolvableFileId(ValueError):
    """Raised for a file_id whose prefix this layer cannot resolve to a key."""


class FileRefAdapter:
    def __init__(
        self,
        base_url: str,
        path: str = "/api/v1/files",
        client_factory: Any | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._path = path
        self._client_factory = client_factory

    def _client(self) -> httpx.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory()
        return httpx.AsyncClient(base_url=self._base_url, timeout=httpx.Timeout(30.0))

    @staticmethod
    def _resolve_key(file_id: str | None) -> str:
        if not file_id:
            raise UnresolvableFileId("file_id_required")
        if file_id.startswith(EPH_PREFIX):
            return unwrap_file_id(file_id)
        # A bare object key (already resolved by the domain) is passed through;
        # any other prefix is rejected — it needs domain-specific resolution.
        if _FILE_ID_PREFIX.match(file_id):
            raise UnresolvableFileId("file_id_requires_domain_resolution")
        return file_id

    async def execute(
        self, route: "Route", ctx: "RouteContext", args: dict[str, Any], request: Any
    ) -> dict[str, Any]:
        spec = request if isinstance(request, dict) else dict(args)
        file_id = spec.get("file_id") or spec.get("key")
        try:
            object_key = self._resolve_key(file_id)
        except UnresolvableFileId as exc:
            return {
                "state": "error",
                "tool": route.name,
                "task_id": ctx.task_id,
                "code": "invalid_file_id",
                "message": str(exc),
            }

        headers = {AUTHOR_EMAIL_HEADER: ctx.verified_identity.email}
        if ctx.settings.webhook_api_token:
            headers["Authorization"] = ctx.settings.webhook_api_token

        client = self._client()
        try:
            resp = await client.post(
                f"{self._path}/{object_key}/download-link", json={}, headers=headers
            )
            if resp.status_code == 404:
                return {
                    "state": "error",
                    "tool": route.name,
                    "task_id": ctx.task_id,
                    "code": "file_not_found",
                    "message": "object not found",
                }
            resp.raise_for_status()
            body = resp.json() if resp.content else {}
            return {
                "state": "done",
                "tool": route.name,
                "task_id": ctx.task_id,
                "file_url": body.get("url"),
                "expires_at": body.get("expires_at"),
            }
        except httpx.HTTPError as exc:
            return http_error_result(route, ctx, exc)
        finally:
            await client.aclose()
