"""MCP proxy adapter — forwards tool calls to a downstream MCP server over HTTP.

Used by upstream ``proxy_1to1`` routes. The verified identity is propagated to
the upstream as ``X-Author-Email``. When the upstream's registry entry sets
``auth.bearer_env``, an ``Authorization: Bearer <token>`` header (read from
that environment variable by :meth:`keystone_mcp.router.upstream.
UpstreamRegistry.add_upstream`) is sent alongside it on every call.

By default (``status_envelope=False``) the adapter is transparent: the
upstream's answer — every content block, ``structuredContent``, ``_meta`` and
``isError`` — reaches the client unchanged, as a :class:`fastmcp.tools.base.
ToolResult`. With ``status_envelope=True`` (``KEYSTONE_MCP_PROXY_STATUS_ENVELOPE=
true``) the adapter instead reproduces the 0.3.x behaviour: the response is
wrapped in the Model M ``{"state", "tool", "task_id", "result"}`` envelope and
a ``status`` field of ``error``/``refused``/``accepted`` is mapped to an
error, a rate-limit error, or a pending task.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Callable

import httpx
import pydantic_core
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.tools.base import ToolResult

from keystone_mcp.identity import AUTHOR_EMAIL_HEADER

if TYPE_CHECKING:
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route

logger = logging.getLogger(__name__)


def _http_client_factory(tool_timeout_seconds: float):
    """Build the transport's HTTP client with the per-tool timeout applied.

    The transport's own ``sse_read_timeout`` argument is deprecated and ignored
    by the current client, so the read timeout has to be set on the HTTP client
    instead. Without this the per-tool budget bounded only the MCP request and
    not the underlying socket.

    Matches the MCP HTTP client factory protocol ``(headers, timeout, auth)``;
    the caller's ``timeout`` is deliberately replaced by the per-tool budget.
    """

    def factory(
        headers: dict[str, str] | None = None,
        timeout: Any = None,  # noqa: ARG001 — superseded by the per-tool budget
        auth: Any = None,
        **_kwargs: Any,
    ) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(tool_timeout_seconds),
            auth=auth,
            follow_redirects=False,
        )

    return factory


#: Builds the client used for one upstream call. It receives the same
#: ``headers`` (carrying the verified identity) and ``timeout`` the default
#: transport would be built with, so an injected client is subject to both
#: rather than silently dropping them.
ClientFactory = Callable[..., Client]

#: ``StreamableHttpTransport`` httpx factory for a resolved per-tool timeout.
HttpClientFactoryBuilder = Callable[[float], Callable[..., httpx.AsyncClient]]


class McpProxyAdapter:
    """Proxy a tool call to another MCP server (streamable HTTP)."""

    def __init__(
        self,
        url: str,
        *,
        tool_timeout_seconds: float = 180.0,
        tool_timeout_overrides: dict[str, float] | None = None,
        client_factory: ClientFactory | None = None,
        http_client_factory: HttpClientFactoryBuilder | None = None,
        status_envelope: bool = False,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        self._url = url.rstrip("/")
        self._tool_timeout_seconds = tool_timeout_seconds
        self._tool_timeout_overrides = dict(tool_timeout_overrides or {})
        self._client_factory = client_factory
        self._http_client_factory = http_client_factory or _http_client_factory
        self._status_envelope = status_envelope
        # e.g. the upstream's ``Authorization: Bearer ...`` (auth.bearer_env).
        # Copied once at construction time, never logged as a whole.
        self._extra_headers = dict(extra_headers or {})

    @property
    def status_envelope(self) -> bool:
        """``True`` when this adapter wraps answers in the legacy envelope.

        ``False`` (the default) means it is transparent. Consulted by
        :meth:`keystone_mcp.router.proxy_tool.UpstreamProxyTool.for_route` to
        decide whether the upstream's own ``outputSchema`` can be published
        (only safe when the response actually matches it).
        """
        return self._status_envelope

    def _timeout_for(self, tool_name: str) -> float:
        return self._tool_timeout_overrides.get(tool_name, self._tool_timeout_seconds)

    async def execute(
        self,
        route: "Route",
        ctx: "RouteContext",
        args: dict[str, Any],
        request: Any,
    ) -> dict[str, Any] | ToolResult:
        if request is not None:
            payload = request
        else:
            from keystone_mcp.router.schema import omit_implicit_null_args

            payload = omit_implicit_null_args(dict(args), route.params)
        tool_name = route.upstream_tool or route.name
        # AUTHOR_EMAIL_HEADER last: extra_headers (e.g. a bearer token) must
        # not be able to override the verified identity header.
        headers = {**self._extra_headers, AUTHOR_EMAIL_HEADER: ctx.verified_identity.email}
        timeout = self._timeout_for(tool_name)

        if self._client_factory is not None:
            client = self._client_factory(headers=headers, timeout=timeout)
        else:
            client = Client(
                StreamableHttpTransport(
                    self._url,
                    headers=headers,
                    httpx_client_factory=self._http_client_factory(timeout),
                ),
                timeout=timeout,
            )
        async with client:
            result = await client.call_tool(tool_name, payload, raise_on_error=False)

        if self._status_envelope:
            return self._wrap_status_envelope(result, route, ctx)

        return ToolResult(
            content=list(result.content),
            structured_content=result.structured_content,
            meta=result.meta,
            is_error=result.is_error,
        )

    @staticmethod
    def _wrap_status_envelope(result: Any, route: "Route", ctx: "RouteContext") -> dict[str, Any]:
        """Reproduce the 0.3.x envelope: ``{state, tool, task_id, result}``.

        Raises :class:`fastmcp.exceptions.ToolError` on an upstream error —
        what the FastMCP client itself did in 0.3.x with its default
        ``raise_on_error=True`` — so the error handling further up the stack
        (observability, client-visible tool error) sees the same shape as
        before.
        """
        published = route.published_name
        tool_name = route.upstream_tool or route.name

        if result.is_error:
            content = list(result.content) or []
            text = content[0].text if content and hasattr(content[0], "text") else None
            raise ToolError(text or f"Tool '{tool_name}' returned an error")

        data = result.data
        if data is not None:
            data = pydantic_core.to_jsonable_python(data)
        else:
            content = list(result.content) or []
            text_blocks = [block.text for block in content if hasattr(block, "text")]
            dropped = len(content) - len(text_blocks)
            if dropped:
                logger.warning(
                    "proxy status envelope drops %d non-text content block(s) from %s",
                    dropped,
                    route.published_name,
                )
            raw = "\n".join(text_blocks)
            if not raw:
                data = {}
            else:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = raw

        if isinstance(data, dict):
            status = data.get("status")
            if status == "error":
                return {
                    "state": "error",
                    "tool": published,
                    "task_id": ctx.task_id,
                    "code": data.get("error_code") or "upstream_error",
                    "message": data.get("error_message") or "downstream error",
                }
            if status == "refused":
                return {
                    "state": "error",
                    "tool": published,
                    "task_id": ctx.task_id,
                    "code": "rate_limited",
                    "message": data.get("error_message") or "rate limit exceeded",
                }
            if status == "accepted":
                return {
                    "state": "pending",
                    "tool": published,
                    "task_id": ctx.task_id,
                    "result": data,
                }

        return {
            "state": "done",
            "tool": published,
            "task_id": ctx.task_id,
            "result": data,
        }
