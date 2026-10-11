"""chat_attachment adapter — signal that a stored file should be delivered to
the chat.

Keystone-MCP does not track chat sessions: it checks that the object exists
(the same download-link probe as file_ref) and returns a done result.
Delivery is done by a component outside Keystone-MCP that watches tool
events. Not registered by default.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import httpx

from keystone_mcp.adapters.file_ref import FileRefAdapter, UnresolvableFileId
from keystone_mcp.identity import AUTHOR_EMAIL_HEADER

if TYPE_CHECKING:
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route

_FILE_ID_PREFIX = re.compile(r"^[a-z]+:")


class ChatAttachmentAdapter:
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
        return FileRefAdapter._resolve_key(file_id)

    async def execute(
        self, route: "Route", ctx: "RouteContext", args: dict[str, Any], request: Any
    ) -> dict[str, Any]:
        spec = request if isinstance(request, dict) else dict(args)
        file_id = spec.get("file_id") or spec.get("key")
        caption = str(spec.get("caption") or "")

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
                f"{self._path}/{object_key}/download-link",
                json={},
                headers=headers,
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
            return {
                "state": "done",
                "tool": route.name,
                "task_id": ctx.task_id,
                "file_id": file_id,
                "caption": caption,
            }
        finally:
            await client.aclose()
