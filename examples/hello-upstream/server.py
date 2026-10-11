"""hello-upstream: a tiny demo MCP server for Keystone-MCP's docker-compose demo.

Built on the low-level ``mcp`` SDK, not FastMCP: FastMCP wraps every tool
answer in ``structuredContent`` and builds a tidy ``inputSchema``, which would
hide exactly the kind of server this demo wants to show -- one whose schema
puts an optional property before a required one (perfectly valid JSON Schema,
and something many non-Python MCP servers produce) and whose tools answer
with plain text. This module imports only ``mcp``, ``starlette``, and
``uvicorn`` -- never that other Python framework.

This file is a standalone copy of the two demo tools (``greet``, ``search``)
from ``tests/support/lowlevel_upstream.py`` (the proxy test fixture), wired up
as a real HTTP server instead of an in-process ASGI app. See that module for
the test-only variant, and ``README.md`` here for what the tools are for.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

HOST = "0.0.0.0"
PORT = 8081

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

_TOOLS: list[types.Tool] = [
    types.Tool(name="greet", description="Greet someone by name.", inputSchema=GREET_SCHEMA),
    types.Tool(name="search", description="Search documents.", inputSchema=SEARCH_SCHEMA),
]

server: Server = Server("hello-upstream")


@server.list_tools()
async def _list_tools() -> list[types.Tool]:
    return _TOOLS


@server.call_tool()
async def _call_tool(name: str, arguments: dict[str, Any]) -> list[types.ContentBlock]:
    if name == "greet":
        return [types.TextContent(type="text", text=_greet(arguments))]
    if name == "search":
        return [types.TextContent(type="text", text=_search(arguments))]
    raise ValueError(f"unknown tool: {name}")


def _greet(arguments: dict[str, Any]) -> str:
    """Greet by name; mention the caller's email when Keystone-MCP sent one.

    ``X-Author-Email`` is how this demo shows that an upstream service knows
    who is calling -- Keystone-MCP attaches it to every proxied request after
    verifying the caller's identity. Trust it only on a private network you
    control; see ../../docs/connecting-services.md.
    """
    request = server.request_context.request
    headers = {k.lower(): v for k, v in request.headers.items()} if request else {}
    email = headers.get("x-author-email")
    name = arguments["name"]
    if email:
        return f"Hello, {name}! You are {email}."
    return f"Hello, {name}!"


def _search(arguments: dict[str, Any]) -> str:
    query = arguments["query"]
    tool_filter = arguments["filter"]
    limit = arguments.get("limit") or 5
    lines = [f"{i + 1}. Result for '{query}' (filter={tool_filter})" for i in range(limit)]
    return "\n".join(lines)


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
