"""A test upstream built on the low-level MCP SDK, not FastMCP.

FastMCP wraps every tool answer in ``structuredContent`` and builds a tidy
``inputSchema`` for its own tools, which hides two bugs in the proxy:

- an ``inputSchema`` with an optional property declared before a required one
  (perfectly valid JSON Schema) breaks route registration;
- a tool that answers with plain text (not JSON) cannot be parsed back by the
  proxy.

Servers built on the TypeScript SDK, the Go SDK, or this low-level Python SDK
all behave this way. This module stands in for one of them in proxy tests, so
it imports only ``mcp``, ``starlette``, and ``httpx`` — never that other
Python framework.
"""

from __future__ import annotations

import base64
import contextlib
import json
from collections.abc import AsyncIterator, Callable, Collection
from typing import Any

import httpx
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

#: In-process base URL used by :func:`asgi_http_client_factory` clients.
UPSTREAM_BASE_URL = "http://upstream.test"
UPSTREAM_MCP_URL = "http://upstream.test/mcp"

# Smallest possible PNG payload (just the file signature). Its bytes are
# opaque to the tests; only the content block's shape (type, mimeType) and
# that it survives the round trip matter.
_PNG_BYTES = b"\x89PNG\r\n\x1a\n"

GREET_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Who to greet"},
    },
    "required": ["name"],
}

#: Property order is deliberate: the optional ``limit`` sits before the
#: required ``filter``. Valid JSON Schema, and exactly what a foreign SDK may
#: emit — the proxy must not assume required properties come first.
SEARCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "description": "Search query text"},
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 50,
            "default": 10,
        },
        "filter": {"type": "string", "enum": ["all", "mine"]},
    },
    "required": ["query", "filter"],
}

_EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}

#: ``from`` is a Python keyword and ``max-results`` is not a legal Python
#: identifier. Before P07 the proxy built a handler's Python function
#: signature from the schema, so a tool like this could never be published at
#: all ("ghost tool", FX-proxy #1); publishing the upstream's own raw schema
#: sidesteps that -- there is no signature to build.
ODD_NAMES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "from": {"type": "string", "description": "Sender address"},
        "max-results": {"type": "integer", "default": 5},
    },
    "required": ["from"],
}

_TOOL_DEFINITIONS: dict[str, types.Tool] = {
    "greet": types.Tool(
        name="greet",
        description="Greet someone by name.",
        inputSchema=GREET_SCHEMA,
    ),
    "search": types.Tool(
        name="search",
        description="Search documents.",
        inputSchema=SEARCH_SCHEMA,
    ),
    "report": types.Tool(
        name="report",
        description="Build a short multi-block report.",
        inputSchema=_EMPTY_SCHEMA,
    ),
    "fail": types.Tool(
        name="fail",
        description="Always fails, to exercise upstream error propagation.",
        inputSchema=_EMPTY_SCHEMA,
    ),
    "whoami": types.Tool(
        name="whoami",
        description="Echo the request headers the upstream received.",
        inputSchema=_EMPTY_SCHEMA,
    ),
    "odd_names": types.Tool(
        name="odd_names",
        description="Echo arguments whose names are not Python identifiers.",
        inputSchema=ODD_NAMES_SCHEMA,
    ),
}

#: ``list_tools`` publishes tools in this order.
_TOOL_ORDER: tuple[str, ...] = ("greet", "search", "report", "fail", "whoami", "odd_names")


def build_lowlevel_upstream_app(
    *,
    tools: Collection[str] | None = None,
    observed: dict[str, Any] | None = None,
    require_bearer: str | None = None,
) -> Starlette:
    """Build a Starlette app around a low-level ``mcp.server.lowlevel.Server``.

    ``tools`` restricts which of the five tools are registered (default: all
    of them), so a test can target one tool without depending on fixes the
    others still need. ``observed``, when given, receives the last call's
    request headers (lower-cased keys) under ``observed["headers"]`` — written
    by the ``whoami`` tool.

    ``require_bearer``, when given, makes both ``list_tools`` and
    ``call_tool`` reject a request whose ``Authorization`` header is not
    exactly ``Bearer <require_bearer>`` — standing in for a real upstream that
    requires Keystone's ``auth.bearer_env`` token (P08). A ``list_tools``
    rejection surfaces to the caller as a failed discovery; a ``call_tool``
    rejection surfaces as an error ``CallToolResult`` (the low-level SDK's
    call-tool wrapper always turns a raised exception into one, the same way
    the ``fail`` tool below does).

    ``StreamableHTTPSessionManager.run()`` can only be entered once per
    instance, so call this again to get a fresh app for each test.
    """
    selected = set(_TOOL_ORDER) if tools is None else set(tools)
    unknown = selected - set(_TOOL_ORDER)
    if unknown:
        raise ValueError(f"unknown tool(s): {sorted(unknown)}")

    server: Server = Server("hello-upstream")

    def _check_bearer() -> None:
        if require_bearer is None:
            return
        request = server.request_context.request
        headers = {k.lower(): v for k, v in request.headers.items()} if request else {}
        if headers.get("authorization") != f"Bearer {require_bearer}":
            raise PermissionError("missing or invalid bearer token")

    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        _check_bearer()
        return [_TOOL_DEFINITIONS[name] for name in _TOOL_ORDER if name in selected]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict[str, Any]) -> list[types.ContentBlock]:
        _check_bearer()
        if name == "greet":
            return [types.TextContent(type="text", text=f"Hello, {arguments['name']}!")]

        if name == "search":
            query = arguments["query"]
            tool_filter = arguments["filter"]
            limit = arguments.get("limit")
            return [
                types.TextContent(
                    type="text",
                    text=f"Found 3 documents for '{query}' (filter={tool_filter}, limit={limit})",
                )
            ]

        if name == "report":
            return [
                types.TextContent(type="text", text="Summary: 2 items"),
                types.TextContent(type="text", text="Details: a, b"),
                types.ImageContent(
                    type="image",
                    data=base64.b64encode(_PNG_BYTES).decode("ascii"),
                    mimeType="image/png",
                ),
            ]

        if name == "fail":
            raise ValueError("upstream failure: quota exceeded")

        if name == "odd_names":
            sender = arguments["from"]
            max_results = arguments.get("max-results")
            return [
                types.TextContent(
                    type="text",
                    text=f"from={sender} max-results={max_results}",
                )
            ]

        if name == "whoami":
            request = server.request_context.request
            headers = {k.lower(): v for k, v in request.headers.items()} if request else {}
            if observed is not None:
                observed["headers"] = headers
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "x-author-email": headers.get("x-author-email"),
                            "authorization": headers.get("authorization"),
                        }
                    ),
                )
            ]

        raise ValueError(f"unknown tool: {name}")

    manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)

    class _McpEndpoint:
        """Raw ASGI endpoint handing the request straight to the session manager.

        Deliberately mounted via ``Route``, not ``Mount``: ``Mount`` redirects a
        bare ``/mcp`` request to ``/mcp/`` with a 307, and the MCP client does
        not follow it.
        """

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def _lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            yield

    return Starlette(
        routes=[Route("/mcp", endpoint=_McpEndpoint(), methods=["GET", "POST", "DELETE"])],
        lifespan=_lifespan,
    )


def asgi_http_client_factory(
    app: Starlette,
) -> Callable[[float], Callable[..., httpx.AsyncClient]]:
    """``HttpClientFactoryBuilder`` that routes every request into *app* in-process.

    Mirrors the shape of ``keystone_mcp.adapters.mcp_proxy._http_client_factory``:
    the returned builder is called with a resolved per-call timeout (seconds)
    and produces the actual httpx client factory, which always uses that
    timeout and ignores whatever timeout the caller passed in.
    """

    def builder(timeout_seconds: float) -> Callable[..., httpx.AsyncClient]:
        def factory(
            headers: dict[str, str] | None = None,
            timeout: Any = None,  # noqa: ARG001 — superseded by timeout_seconds
            auth: Any = None,
            **_kwargs: Any,
        ) -> httpx.AsyncClient:
            return httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url=UPSTREAM_BASE_URL,
                headers=headers,
                timeout=httpx.Timeout(timeout_seconds),
                auth=auth,
                follow_redirects=False,
            )

        return factory

    return builder
