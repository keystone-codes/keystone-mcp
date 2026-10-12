"""hello-upstream: a tiny demo MCP server for Keystone-MCP's docker-compose demo.

Built on the low-level ``mcp`` SDK, not FastMCP: FastMCP wraps every tool
answer in ``structuredContent`` and builds a tidy ``inputSchema``, which would
hide exactly the kind of server this demo wants to show -- one whose schema
puts an optional property before a required one (perfectly valid JSON Schema,
and something many non-Python MCP servers produce) and whose tools answer
with plain text. This module imports only ``mcp``, ``starlette``, ``uvicorn``
and ``pyjwt`` (via ``keystone_identity.py`` below) -- never that other Python
framework.

This file is a standalone copy of the two original demo tools (``greet``,
``search``) from ``tests/support/lowlevel_upstream.py`` (the proxy test
fixture), wired up as a real HTTP server instead of an in-process ASGI app,
plus a third tool (``whoami``) added to show ``X-Keystone-Identity``
verification. See that module for the test-only variant, and ``README.md``
here for what the tools are for.

The container (``Dockerfile``) pins MCP Python SDK 1.x on purpose, and this
file is written against that SDK's decorator-based ``Server`` API
(``@server.list_tools()``, ``@server.call_tool()``). Keystone-MCP's own test
suite imports this same file under its *own* dependencies, which are SDK 2.x
(``mcp>=2,<3``) -- a different, constructor-based API
(``on_list_tools=...``, ``on_call_tool=...``) with no decorators at all. Both
branches below share the same tool logic (``_run_tool``); ``_build_server``
just picks whichever registration style the installed SDK supports.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import uvicorn

# Copied verbatim from examples/keystone-identity/python/keystone_identity.py
# (not installed as a package -- tests/test_identity_examples.py pins this
# file byte-for-byte equal to that original so the two copies never drift
# apart). Verifies X-Keystone-Identity exactly the way any other upstream
# service would, following docs/connecting-services.md.
from keystone_identity import IdentityError, KeystoneIdentity, verify_keystone_identity
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

HOST = "0.0.0.0"
PORT = 8081

#: Set this to make the demo verify X-Keystone-Identity instead of trusting
#: the unsigned, deprecated X-Author-Email outright. Unset (the 0.4.0
#: behaviour) by default so the demo keeps working without it. Named without
#: the KEYSTONE_MCP_ prefix: this is hello-upstream's own setting, not
#: Keystone-MCP's.
HELLO_IDENTITY_SECRET = os.environ.get("HELLO_IDENTITY_SECRET", "").strip()

#: This upstream's own registry entry name -- the assertion's ``aud``.
HELLO_IDENTITY_AUDIENCE = os.environ.get("HELLO_IDENTITY_AUDIENCE", "hello").strip()

GREET_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Who to greet"},
    },
    "required": ["name"],
}

#: Property order is deliberate: the optional ``limit`` sits before the
#: required ``filter``. Valid JSON Schema, and exactly what a foreign SDK may
#: emit -- Keystone-MCP's proxy must not assume required properties come
#: first.
SEARCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "description": "Search query text"},
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 50,
            "default": 5,
            "description": "How many results to return",
        },
        "filter": {"type": "string", "enum": ["all", "mine"]},
    },
    "required": ["query", "filter"],
}

_EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}

_TOOLS: list[types.Tool] = [
    types.Tool(name="greet", description="Greet someone by name.", inputSchema=GREET_SCHEMA),
    types.Tool(name="search", description="Search documents.", inputSchema=SEARCH_SCHEMA),
    types.Tool(
        name="whoami",
        description="Return the verified caller identity, if X-Keystone-Identity checking is on.",
        inputSchema=_EMPTY_SCHEMA,
    ),
]


def _headers_from_request(request: Any) -> dict[str, str]:
    if request is None:
        return {}
    return {k.lower(): v for k, v in request.headers.items()}


def _verify_identity(headers: dict[str, str]) -> KeystoneIdentity | None:
    """Verify ``X-Keystone-Identity``, or ``None`` when no secret is configured.

    Raises ``ValueError`` when a secret *is* configured but the header is
    missing, forged, signed with a different secret, or signed for a
    different audience -- ``_run_tool`` lets this propagate, and both
    ``_build_server`` branches turn it into an error ``CallToolResult``
    (the SDK 1.x decorator path does this automatically; the SDK 2.x
    constructor path does it explicitly).
    """
    if not HELLO_IDENTITY_SECRET:
        return None
    token = headers.get("x-keystone-identity")
    try:
        return verify_keystone_identity(
            token, secrets=[HELLO_IDENTITY_SECRET], audience=HELLO_IDENTITY_AUDIENCE
        )
    except IdentityError as exc:
        raise ValueError(f"identity rejected: {exc}") from exc


def _greet(arguments: dict[str, Any], headers: dict[str, str]) -> str:
    """Greet by name; mention the caller when Keystone-MCP identified one.

    With ``HELLO_IDENTITY_SECRET`` set, this trusts only a verified
    ``X-Keystone-Identity``. Without it, this falls back to the unsigned,
    deprecated ``X-Author-Email`` -- trust it only on a private network you
    control; see ../../docs/connecting-services.md.
    """
    name = arguments["name"]
    identity = _verify_identity(headers)
    if identity is not None:
        roles = ", ".join(identity.roles)
        return f"Hello, {name}! You are {identity.email or identity.sub} (roles: {roles})."
    email = headers.get("x-author-email")
    if email:
        return f"Hello, {name}! You are {email}."
    return f"Hello, {name}!"


def _search(arguments: dict[str, Any]) -> str:
    query = arguments["query"]
    tool_filter = arguments["filter"]
    limit = arguments.get("limit") or 5
    lines = [f"{i + 1}. Result for '{query}' (filter={tool_filter})" for i in range(limit)]
    return "\n".join(lines)


def _whoami(headers: dict[str, str]) -> str:
    """Return the verified identity fields as JSON text.

    Without ``HELLO_IDENTITY_SECRET`` configured, answers
    ``{"verified": false, ...}`` with whatever (unverified) X-Author-Email
    was sent, exactly like ``greet``'s fallback.
    """
    identity = _verify_identity(headers)
    if identity is None:
        return json.dumps({"verified": False, "x-author-email": headers.get("x-author-email")})
    return json.dumps(
        {
            "verified": True,
            "sub": identity.sub,
            "sub_type": identity.sub_type,
            "roles": list(identity.roles),
            "auth_method": identity.auth_method,
            "interactive": identity.interactive,
            "client_id": identity.client_id,
            "mcp_target": identity.mcp_target,
        }
    )


def _run_tool(
    name: str, arguments: dict[str, Any], headers: dict[str, str]
) -> list[types.ContentBlock]:
    if name == "greet":
        return [types.TextContent(type="text", text=_greet(arguments, headers))]
    if name == "search":
        return [types.TextContent(type="text", text=_search(arguments))]
    if name == "whoami":
        return [types.TextContent(type="text", text=_whoami(headers))]
    raise ValueError(f"unknown tool: {name}")


def _build_server() -> Server:
    server: Server = Server("hello-upstream")

    if hasattr(server, "list_tools"):
        # MCP Python SDK 1.x (what the Dockerfile installs): tools are
        # registered via decorators, and a raised exception from
        # ``call_tool`` is wrapped into an error ``CallToolResult``
        # automatically.
        @server.list_tools()
        async def _list_tools() -> list[types.Tool]:
            return _TOOLS

        @server.call_tool()
        async def _call_tool(name: str, arguments: dict[str, Any]) -> list[types.ContentBlock]:
            request = server.request_context.request
            return _run_tool(name, arguments, _headers_from_request(request))

        return server

    # MCP Python SDK 2.x (what Keystone-MCP's own test suite installs):
    # ``Server`` takes ``on_list_tools``/``on_call_tool`` in its constructor
    # instead (the decorators were removed), and does not auto-wrap a raised
    # exception, so that is done here explicitly.
    async def _on_list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=_TOOLS)

    async def _on_call_tool(ctx: Any, params: Any) -> types.CallToolResult:
        headers = _headers_from_request(getattr(ctx, "request", None))
        try:
            content = _run_tool(params.name, params.arguments or {}, headers)
        except Exception as exc:  # noqa: BLE001 -- mirrors SDK 1.x's auto-wrap
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(exc))],
                is_error=True,
            )
        return types.CallToolResult(content=content)

    return Server("hello-upstream", on_list_tools=_on_list_tools, on_call_tool=_on_call_tool)


server = _build_server()

manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)


class _McpEndpoint:
    """Raw ASGI endpoint handing the request straight to the session manager.

    Deliberately mounted via ``Route``, not ``Mount``: ``Mount`` redirects a
    bare ``/mcp`` request to ``/mcp/`` with a 307, and the MCP client does not
    follow it.
    """

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await manager.handle_request(scope, receive, send)


async def _healthz(_request: Any) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@asynccontextmanager
async def _lifespan(_app: Starlette) -> AsyncIterator[None]:
    async with manager.run():
        yield


app = Starlette(
    routes=[
        Route("/mcp", endpoint=_McpEndpoint(), methods=["GET", "POST", "DELETE"]),
        Route("/healthz", endpoint=_healthz, methods=["GET"]),
    ],
    lifespan=_lifespan,
)


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)
