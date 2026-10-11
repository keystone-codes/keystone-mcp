"""External HTTP adapter.

Routes a tool call to an arbitrary external API. The ``transform`` prepares the
payload and may switch the HTTP method (GET|POST); the verified identity is
carried downstream as ``X-Author-Email`` so the target can validate it against
the shared auth service — this adapter is not an auth bypass. Server secrets
stay on the hosting side, never on the client.

``transform`` may return either a plain payload dict or a dict shaped as
``{"method": "GET"|"POST", "path": "/...", "params": {...}, "json": {...},
"headers": {...}}`` to fully control the request.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import httpx

from keystone_mcp.adapters.base import http_error_result
from keystone_mcp.identity import AUTHOR_EMAIL_HEADER

if TYPE_CHECKING:
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route

#: Headers a caller may never set on an outbound request. ``x-author-email``
#: names the identity the target authorizes against, and ``authorization``
#: carries server-held credentials; both are decided here, not by the client.
_CALLER_FORBIDDEN_HEADERS = frozenset({"x-author-email", "authorization"})


def _build_headers(extra_headers: dict[str, str], email: str) -> dict[str, str]:
    """Merge transform/caller headers under the verified identity.

    The identity header is applied last so it cannot be overridden, and any
    caller-supplied spelling of a forbidden header is dropped case-insensitively
    (HTTP header names are case-insensitive, so ``X-Author-Email`` and
    ``x-author-email`` are the same header).
    """
    safe = {
        name: value
        for name, value in extra_headers.items()
        if name.strip().lower() not in _CALLER_FORBIDDEN_HEADERS
    }
    return {**safe, AUTHOR_EMAIL_HEADER: email}


class ExternalHttpAdapter:
    def __init__(
        self,
        base_url: str,
        method: str = "POST",
        path: str = "",
        client_factory: Any | None = None,
    ) -> None:
        self._base_url = base_url
        self._default_method = method.upper()
        self._default_path = path
        self._client_factory = client_factory

    def _client(self) -> httpx.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory()
        return httpx.AsyncClient(base_url=self._base_url, timeout=httpx.Timeout(30.0))

    async def execute(
        self, route: "Route", ctx: "RouteContext", args: dict[str, Any], request: Any
    ) -> dict[str, Any]:
        spec = request if isinstance(request, dict) else dict(args)

        # A transform may return a full request spec, otherwise treat it as payload.
        if spec.get("method") or spec.get("path") or "params" in spec or "json" in spec:
            method = str(spec.get("method", self._default_method)).upper()
            path = str(spec.get("path", self._default_path))
            params = spec.get("params")
            json_body = spec.get("json")
            extra_headers = dict(spec.get("headers") or {})
        else:
            method = self._default_method
            path = self._default_path
            if method == "GET":
                params, json_body = spec, None
            else:
                params, json_body = None, spec
            extra_headers = {}

        headers = _build_headers(extra_headers, ctx.verified_identity.email)

        client = self._client()
        try:
            resp = await client.request(
                method, path, params=params, json=json_body, headers=headers
            )
            resp.raise_for_status()
            data = resp.json() if resp.content else {}
            return {"state": "done", "tool": route.name, "task_id": ctx.task_id, "result": data}
        except httpx.HTTPError as exc:
            return http_error_result(route, ctx, exc)
        finally:
            await client.aclose()
