"""Webhook adapter.

Async submit to a webhook API, with a deterministic peek and a long-poll
against the tasks registry. Flow per call:

  1. peek  GET  {base}/tasks/{task_id}/result  -> if done/error, short-circuit
     (the webhook is NOT sent and the handler is not re-run).
  2. submit POST {base}/api/v1/webhooks/{client}/{project} with the built payload,
     carrying the verified identity as ``X-Author-Email`` and the service api_token.
  3. long-poll GET {base}/tasks/{task_id}/result until done/error or timeout.

The ``transform`` callable owns the payload-build business logic; without one
the raw args are posted 1:1. Both route segments come from ``WebhookSettings``
and have no default, so a fork that registers a webhook route must name its
own target.

This is reference code for forks: Keystone-MCP never registers this adapter
itself, and it is not covered by ``docs/compatibility.md``. Its settings are
read from ``KEYSTONE_MCP_CONTRIB_WEBHOOK_*`` environment variables, only by
``WebhookSettings.from_env()``, and only when a fork constructs the adapter —
see ``docs/contrib/adapters.md``.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx

from keystone_mcp.adapters.base import http_error_result
from keystone_mcp.identity import AUTHOR_EMAIL_HEADER

if TYPE_CHECKING:
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route


@dataclass(frozen=True)
class WebhookSettings:
    """Target configuration for :class:`WebhookAdapter`.

    Read from ``KEYSTONE_MCP_CONTRIB_WEBHOOK_*`` by :meth:`from_env`, only
    when a fork calls it (normally from ``WebhookAdapter.__init__``). There is
    no default base URL: an empty one is a configuration error, the same as
    an empty ``client``/``project``.
    """

    base_url: str = ""
    client: str = ""
    project: str = ""
    api_token: str = ""
    long_poll_seconds: int = 40

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> WebhookSettings:
        # Literal os.environ.get(...) calls (one branch per variable, not a
        # loop over a list of names) so tests/support/env_vars.py's regex scan
        # — the same one used for every KEYSTONE_MCP_* variable in config.py —
        # finds these five names and treats them as a separate, contrib-only
        # namespace (tests/test_env_docs_sync.py::test_contrib_variables_*).
        import os

        if environ is not None:
            base_url = environ.get("KEYSTONE_MCP_CONTRIB_WEBHOOK_BASE_URL", "")
            client = environ.get("KEYSTONE_MCP_CONTRIB_WEBHOOK_CLIENT", "")
            project = environ.get("KEYSTONE_MCP_CONTRIB_WEBHOOK_PROJECT", "")
            api_token = environ.get("KEYSTONE_MCP_CONTRIB_WEBHOOK_API_TOKEN", "")
            raw_long_poll = environ.get("KEYSTONE_MCP_CONTRIB_WEBHOOK_LONG_POLL_SECONDS")
        else:
            base_url = os.environ.get("KEYSTONE_MCP_CONTRIB_WEBHOOK_BASE_URL", "")
            client = os.environ.get("KEYSTONE_MCP_CONTRIB_WEBHOOK_CLIENT", "")
            project = os.environ.get("KEYSTONE_MCP_CONTRIB_WEBHOOK_PROJECT", "")
            api_token = os.environ.get("KEYSTONE_MCP_CONTRIB_WEBHOOK_API_TOKEN", "")
            raw_long_poll = os.environ.get("KEYSTONE_MCP_CONTRIB_WEBHOOK_LONG_POLL_SECONDS")

        if raw_long_poll is None:
            long_poll_seconds = 40
        else:
            try:
                long_poll_seconds = int(raw_long_poll.strip())
            except ValueError as exc:
                raise ValueError(
                    "KEYSTONE_MCP_CONTRIB_WEBHOOK_LONG_POLL_SECONDS must be an integer; "
                    f"got {raw_long_poll!r}"
                ) from exc

        return cls(
            base_url=base_url,
            client=client,
            project=project,
            api_token=api_token,
            long_poll_seconds=long_poll_seconds,
        )


class WebhookAdapter:
    def __init__(
        self,
        settings: WebhookSettings | None = None,
        client_factory: Any | None = None,
        poll_interval: float = 1.0,
    ) -> None:
        # Settings are read here, at construction time, not lazily in
        # execute(): a fork that constructs the adapter once at startup gets
        # the same environment a server process would see.
        self._settings = settings if settings is not None else WebhookSettings.from_env()
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
        cfg = self._settings
        base_url = cfg.base_url.strip()
        client_id = cfg.client.strip()
        project_id = cfg.project.strip()
        if not base_url or not client_id or not project_id:
            # All three are deployment-supplied and have no sensible default;
            # refuse rather than POST to a malformed path.
            return {
                "state": "error",
                "tool": route.name,
                "task_id": ctx.task_id,
                "code": "webhook_target_unconfigured",
                "message": (
                    "KEYSTONE_MCP_CONTRIB_WEBHOOK_BASE_URL, KEYSTONE_MCP_CONTRIB_WEBHOOK_CLIENT "
                    "and KEYSTONE_MCP_CONTRIB_WEBHOOK_PROJECT must be set to use webhook routes"
                ),
            }

        payload = request if request is not None else dict(args)
        headers = {AUTHOR_EMAIL_HEADER: ctx.verified_identity.email}
        if cfg.api_token:
            headers["Authorization"] = cfg.api_token

        result_path = f"/tasks/{ctx.task_id}/result"
        webhook_path = f"/api/v1/webhooks/{client_id}/{project_id}"

        client = self._client(base_url)
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
