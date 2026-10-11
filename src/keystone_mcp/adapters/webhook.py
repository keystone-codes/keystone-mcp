"""Webhook adapter.

Async submit to a webhook API, with a deterministic peek and a long-poll
against the tasks registry. Flow per call:

  1. peek  GET  {base}/tasks/{task_id}/result  -> if done/error, short-circuit
     (the webhook is NOT sent and the handler is not re-run).
  2. submit POST {base}/api/v1/webhooks/{client}/{project} with the built payload,
     carrying the verified identity as ``X-Author-Email`` and the service api_token.
  3. long-poll GET {base}/tasks/{task_id}/result until done/error or timeout.

The ``transform`` callable owns the payload-build business logic; without one
the raw args are posted 1:1. Both route segments come from settings and have no
default, so a deployment must name its own webhook target.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import httpx

from keystone_mcp.adapters.base import http_error_result
from keystone_mcp.identity import AUTHOR_EMAIL_HEADER

if TYPE_CHECKING:
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route


class WebhookAdapter:
    def __init__(
        self,
        client_factory: Any | None = None,
        poll_interval: float = 1.0,
    ) -> None:
        # client_factory: zero-arg callable returning an httpx.AsyncClient
        # (injected in tests). Defaults to a fresh client per call.
        self._client_factory = client_factory
        self._poll_interval = poll_interval

    def _client(self, base_url: str) -> httpx.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory()
        return httpx.AsyncClient(base_url=base_url, timeout=httpx.Timeout(60.0))

    async def execute(
        self, route: "Route", ctx: "RouteContext", args: dict[str, Any], request: Any
    ) -> dict[str, Any]:
        cfg = ctx.settings
        client_id = cfg.webhook_client_id.strip()
        project_id = cfg.webhook_project_id.strip()
        if not client_id or not project_id:
            # Both segments are deployment-supplied and have no sensible default;
            # refuse rather than POST to a malformed path.
            return {
                "state": "error",
                "tool": route.name,
                "task_id": ctx.task_id,
                "code": "webhook_target_unconfigured",
                "message": (
                    "KEYSTONE_MCP_WEBHOOK_CLIENT and KEYSTONE_MCP_WEBHOOK_PROJECT "
                    "must be set to use webhook routes"
                ),
            }

        payload = request if request is not None else dict(args)
        headers = {AUTHOR_EMAIL_HEADER: ctx.verified_identity.email}
        if cfg.webhook_api_token:
            headers["Authorization"] = cfg.webhook_api_token

        result_path = f"/tasks/{ctx.task_id}/result"
        webhook_path = f"/api/v1/webhooks/{client_id}/{project_id}"

        client = self._client(cfg.webhook_base_url)
        try:
            # 1. peek — short-circuit on a previously published result
            peek = await client.get(result_path, headers=headers)
            if peek.status_code == 200:
                state = peek.json().get("state")
                if state in ("done", "error", "file_ready"):
                    return self._normalize(peek.json(), ctx)

            # 2. submit
            submit = await client.post(webhook_path, json=payload, headers=headers)
            submit.raise_for_status()

            # 3. long-poll
            deadline = time.monotonic() + cfg.long_poll_seconds
            while time.monotonic() < deadline:
                poll = await client.get(result_path, headers=headers)
                if poll.status_code == 200:
                    body = poll.json()
                    if body.get("state") in ("done", "error", "awaiting_user", "file_ready"):
                        return self._normalize(body, ctx)
                await self._sleep(self._poll_interval)

            return {"state": "pending", "task_id": ctx.task_id, "tool": route.name}
        except httpx.HTTPError as exc:
            return http_error_result(route, ctx, exc)
        finally:
            await client.aclose()

    @staticmethod
    def _normalize(body: dict[str, Any], ctx: "RouteContext") -> dict[str, Any]:
        body.setdefault("task_id", ctx.task_id)
        return body

    @staticmethod
    async def _sleep(seconds: float) -> None:
        import asyncio

        await asyncio.sleep(seconds)
