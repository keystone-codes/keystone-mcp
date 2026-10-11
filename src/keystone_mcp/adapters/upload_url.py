"""upload_url adapter — mint a signed PUT link for a two-phase upload.

Synchronous: returns a short-lived, credential-free URL the caller PUTs file
bytes to directly (e.g. ``curl`` inside a code-execution sandbox), so the bytes
never traverse a tool argument and never enter the model's context. The minted
``file_id`` (``eph:{key}``) is then handed to domain import tools.

This is the companion to ``file_ref`` (download): both keep large binaries out
of MCP tool-call JSON. The server reserves the object key, so the token can
never target an existing snapshot or arbitrary key.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from keystone_mcp.adapters.base import http_error_result
from keystone_mcp.identity import AUTHOR_EMAIL_HEADER

if TYPE_CHECKING:
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route


class UploadUrlAdapter:
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

    async def execute(
        self, route: "Route", ctx: "RouteContext", args: dict[str, Any], request: Any
    ) -> dict[str, Any]:
        spec = request if isinstance(request, dict) else dict(args)
        payload: dict[str, Any] = {}
        filename = spec.get("filename")
        if filename:
            payload["filename"] = filename
        content_type = spec.get("content_type")
        if content_type:
            payload["content_type"] = content_type

        headers = {AUTHOR_EMAIL_HEADER: ctx.verified_identity.email}
        if ctx.settings.webhook_api_token:
            headers["Authorization"] = ctx.settings.webhook_api_token

        client = self._client()
        try:
            resp = await client.post(f"{self._path}/upload-link", json=payload, headers=headers)
            resp.raise_for_status()
            body = resp.json() if resp.content else {}
            return {
                "state": "done",
                "tool": route.name,
                "task_id": ctx.task_id,
                "upload_url": body.get("upload_url"),
                "file_id": body.get("file_id"),
                "expires_at": body.get("expires_at"),
                "max_bytes": body.get("max_bytes"),
            }
        except httpx.HTTPError as exc:
            return http_error_result(route, ctx, exc)
        finally:
            await client.aclose()
