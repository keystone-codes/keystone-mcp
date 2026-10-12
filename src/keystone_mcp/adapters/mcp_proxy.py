"""MCP proxy adapter — forwards tool calls to a downstream MCP server over HTTP.

Used by upstream ``proxy_1to1`` routes. The verified identity is propagated to
the upstream as ``X-Author-Email`` (unsigned, deprecated since 0.5.0). When
the upstream's registry entry sets ``auth.identity_secret_env``, a signed
``X-Keystone-Identity`` JWT (see :mod:`keystone_mcp.identity_assertion`) is
sent as well, carrying the subject, the roles RBAC used, and which tool was
called. When it sets ``auth.bearer_env``, an ``Authorization: Bearer <token>``
header (read from that environment variable by :meth:`keystone_mcp.router.
upstream.UpstreamRegistry.add_upstream`) is sent alongside it on every call.

By default (``status_envelope=False``) the adapter is transparent: the
upstream's answer — every content block, ``structuredContent``, ``_meta`` and
``isError`` — reaches the client unchanged, as a :class:`fastmcp.tools.base.
ToolResult`. With ``status_envelope=True`` (``KEYSTONE_MCP_PROXY_STATUS_ENVELOPE=
true``) the adapter instead reproduces the 0.3.x behaviour: the response is
wrapped in the Model M ``{"state", "tool", "task_id", "result"}`` envelope and
a ``status`` field of ``error``/``refused``/``accepted`` is mapped to an
error, a rate-limit error, or a pending task.

While the call runs, progress notifications the upstream sends are relayed to
the client, when the client asked for them -- the actual call to the upstream
and that relaying both go through :mod:`keystone_mcp.router.upstream_call`,
the one place Keystone talks to an upstream MCP server.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Callable

import httpx2
import pydantic_core
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.tools.base import ToolResult
from mcp.shared._httpx_utils import McpHttpClientFactory

from keystone_mcp.identity import upstream_identity_headers
from keystone_mcp.identity_assertion import IDENTITY_HEADER, IdentityAssertionSigner

if TYPE_CHECKING:
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route

logger = logging.getLogger(__name__)


def _http_client_factory(tool_timeout_seconds: float) -> McpHttpClientFactory:
    """Build the transport's HTTP client with the per-tool timeout applied.

    Without this the per-tool budget bounded only the MCP request and not the
    underlying socket. The transport hands this factory an ``auth`` object
    built for ``httpx2`` (``fastmcp.client.auth.bearer.BearerAuth``), so the
    returned client must be an ``httpx2.AsyncClient`` — an ``httpx.AsyncClient``
    rejects that ``auth`` argument with a ``TypeError``. Our own HTTP code
    elsewhere in Keystone stays on ``httpx``; only this fastmcp boundary moves.

    Matches the MCP HTTP client factory protocol ``(headers, timeout, auth)``;
    the caller's ``timeout`` is deliberately replaced by the per-tool budget.
    """

    def factory(
        headers: dict[str, str] | None = None,
        timeout: Any = None,  # noqa: ARG001 — superseded by the per-tool budget
        auth: Any = None,
        **_kwargs: Any,
    ) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(
            headers=headers,
            timeout=httpx2.Timeout(tool_timeout_seconds),
            auth=auth,
            follow_redirects=False,
        )

    return factory


#: Builds the client used for one upstream call. It receives the same
#: ``headers`` (carrying the verified identity) and ``timeout`` the default
#: transport would be built with, so an injected client is subject to both
#: rather than silently dropping them.
ClientFactory = Callable[..., Client]

#: ``StreamableHttpTransport`` http client factory for a resolved per-tool
#: timeout.
HttpClientFactoryBuilder = Callable[[float], McpHttpClientFactory]


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
        identity_signer: IdentityAssertionSigner | None = None,
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
        # Signs X-Keystone-Identity (Y01); None means this upstream has no
        # auth.identity_secret_env and gets only the unsigned X-Author-Email.
        self._identity_signer = identity_signer

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
        # Local import: keystone_mcp.router (via router/__init__.py ->
        # router.upstream) imports this module, so a module-level import here
        # would be circular (see the identity_assertion.py note on the same
        # problem). Captured first, in the request's own task: it is this
        # call's only chance to see the client request that is waiting on it
        # (DownstreamCall.current's docstring explains why that matters).
        from keystone_mcp.router.upstream_call import (
            DownstreamCall,
            call_upstream_tool,
            parse_for_status_envelope,
        )

        downstream = DownstreamCall.current()

        if request is not None:
            payload = request
        else:
            from keystone_mcp.router.schema import omit_implicit_null_args

            payload = omit_implicit_null_args(dict(args), route.params)
        tool_name = route.upstream_tool or route.name
        timeout = self._timeout_for(tool_name)
        # AUTHOR_EMAIL_HEADER last: extra_headers (e.g. a bearer token) must
        # not be able to override the verified identity header. The signed
        # assertion is built after extra_headers too, for the same reason —
        # neither can be overridden by a static header from the registry.
        headers = {**self._extra_headers}
        if self._identity_signer is not None:
            headers[IDENTITY_HEADER] = self._identity_signer.sign(
                identity=ctx.verified_identity,
                task_id=ctx.task_id,
                mcp_method="tools/call",
                mcp_target=tool_name,
                timeout_seconds=timeout,
                rbac_mode=ctx.settings.rbac_mode,
            )
        headers.update(upstream_identity_headers(ctx.verified_identity))

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
            raw = await call_upstream_tool(
                client, tool_name, payload, timeout=timeout, downstream=downstream
            )
            if self._status_envelope:
                # Parsed inside the ``async with`` block: _parse_call_tool_result
                # decodes against the upstream's output schema, cached on the
                # still-open session.
                parsed = await parse_for_status_envelope(client, tool_name, raw)

        if self._status_envelope:
            return self._wrap_status_envelope(parsed, route, ctx)

        return ToolResult.from_mcp_result(raw)

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
