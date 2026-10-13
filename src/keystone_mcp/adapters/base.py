"""Adapter protocol, status-envelope stubs, and canonical stub responses."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from fastmcp.tools.base import ToolResult

    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route


class Pattern(str, Enum):
    """Response shape a route promises. Selects the canonical stub answer while the route is in stub mode."""

    SYNC = "sync"  # the call returns its result directly
    CONTINUATION = "continuation"  # the call waits for the user (awaiting_user)


@runtime_checkable
class Adapter(Protocol):
    """A router target. Receives the transformed *request* (or raw args on
    passthrough) plus the transport context and returns a status-envelope dict,
    or a ``ToolResult`` for transparent proxies (see
    ``keystone_mcp.adapters.mcp_proxy.McpProxyAdapter``).

    The status envelope is the dict every built-in route returns: ``state``
    (``done``, ``error``, ``pending``, ``awaiting_user``, ``file_ready``),
    ``tool``, ``task_id``, plus route-specific fields. Proxied upstream tools
    return it only when ``KEYSTONE_MCP_PROXY_STATUS_ENVELOPE=true``.
    """

    async def execute(
        self,
        route: "Route",
        ctx: "RouteContext",
        args: dict[str, Any],
        request: Any,
    ) -> "dict[str, Any] | ToolResult": ...


def http_error_result(
    route: "Route",
    ctx: "RouteContext",
    exc: Exception,
) -> dict[str, Any]:
    """Map a failed downstream HTTP call to the status-envelope error shape.

    Without this, a non-2xx ``raise_for_status()`` or a connect/read failure
    escaped the adapter as an exception, surfacing to the client as an opaque
    internal tool error instead of the ``{"state": "error", ...}`` shape every
    other outcome uses. The mapping mirrors ``users_admin``: a timeout is
    distinguished from other transport failures, and an HTTP status response
    carries its code so a caller can tell 404 from 503.

    The message deliberately carries no response body: a downstream error page
    may echo request headers, which include the service credential.
    """
    import httpx

    if isinstance(exc, httpx.TimeoutException):
        code, message = "downstream_timeout", "downstream request timed out"
    elif isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        code = f"downstream_http_{status}"
        message = f"downstream returned HTTP {status}"
    else:
        code, message = "downstream_unavailable", "downstream request failed"

    return {
        "state": "error",
        "tool": route.name,
        "task_id": ctx.task_id,
        "code": code,
        "message": message,
    }


def stub_response(pattern: Pattern, task_id: str, tool_name: str) -> dict[str, Any]:
    """Canonical stub response by pattern (default 'until live')."""
    if pattern is Pattern.CONTINUATION:
        return {
            "state": "awaiting_user",
            "stub": True,
            "tool": tool_name,
            "task_id": task_id,
            "prompt": "stub continuation",
        }
    return {"state": "done", "stub": True, "tool": tool_name, "task_id": task_id, "result": None}
