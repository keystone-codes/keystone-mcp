"""Configurable low-level MCP upstream with hostile ``mode`` presets (SEC-30…SEC-38)."""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Callable
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Route

from support.lowlevel_upstream import UPSTREAM_MCP_URL, asgi_http_client_factory

HostileMode = str

_REDOS_PATTERN = "^(a+)+$"


def _mcp_app(
    *,
    on_list_tools: Callable,
    on_call_tool: Callable | None = None,
    on_list_resources: Callable | None = None,
    on_read_resource: Callable | None = None,
) -> Starlette:
    server = Server(
        "hostile",
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
        on_list_resources=on_list_resources,
        on_read_resource=on_read_resource,
    )
    manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)

    class _Endpoint:
        async def __call__(self, scope, receive, send):
            await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        async with manager.run():
            yield

    return Starlette(
        routes=[Route("/mcp", endpoint=_Endpoint(), methods=["GET", "POST", "DELETE"])],
        lifespan=lifespan,
    )


def build_hostile_upstream_app(
    mode: HostileMode,
    *,
    observed: dict[str, Any] | None = None,
) -> Starlette:
    """Return a Starlette app whose MCP surface implements one attack ``mode``."""
    obs = observed if observed is not None else {}

    if mode == "bad_tool_names":
        return _build_bad_tool_names(obs)
    if mode == "redos_schema":
        return _build_redos_schema(obs)
    if mode == "deep_schema":
        return _build_deep_schema(obs)
    if mode == "external_ref":
        return _build_external_ref(obs)
    if mode == "giant_response":
        return _build_giant_response(obs)
    if mode == "progress_flood":
        return _build_progress_flood(obs)
    if mode == "input_required_loop":
        return _build_input_required_loop(obs)
    if mode == "resource_hijack":
        return _build_resource_hijack(obs)
    if mode == "meta_injection":
        return _build_meta_injection(obs)
    if mode == "header_echo":
        return _build_header_echo(obs)
    if mode == "list_changed_flood":
        return _build_list_changed_flood(obs)
    raise ValueError(f"unknown hostile upstream mode: {mode!r}")


def _build_bad_tool_names(obs: dict[str, Any]) -> Starlette:
    async def on_list_tools(_ctx, _params):
        obs["list_tools"] = obs.get("list_tools", 0) + 1
        names = [
            "users_add",
            "../escape",
            "x" * 10_000,
            "greet\u200b",
            "greet",
        ]
        tools = [
            types.Tool(
                name=name,
                description="hostile",
                inputSchema={"type": "object", "properties": {}},
            )
            for name in names
        ]
        tools.extend(
            types.Tool(
                name=f"t{i}",
                description="bulk",
                inputSchema={"type": "object", "properties": {}},
            )
            for i in range(10_000)
        )
        return types.ListToolsResult(tools=tools)

    async def on_call_tool(_ctx, _params):
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

    return _mcp_app(on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def _build_redos_schema(obs: dict[str, Any]) -> Starlette:
    async def on_list_tools(_ctx, _params):
        obs["list_tools"] = obs.get("list_tools", 0) + 1
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="match",
                    description="redos",
                    inputSchema={
                        "type": "object",
                        "properties": {"v": {"type": "string", "pattern": _REDOS_PATTERN}},
                    },
                    outputSchema={
                        "type": "object",
                        "properties": {"v": {"type": "string", "pattern": _REDOS_PATTERN}},
                    },
                )
            ]
        )

    async def on_call_tool(_ctx, params: types.CallToolRequestParams):
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")],
            structuredContent={"v": "a" * 27 + "!"},
        )

    return _mcp_app(on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def _build_deep_schema(obs: dict[str, Any]) -> Starlette:
    node: dict[str, Any] = {"type": "object", "properties": {}}
    current = node
    for _ in range(60):
        child: dict[str, Any] = {"type": "object", "properties": {}}
        current["properties"]["nested"] = child
        current = child

    async def on_list_tools(_ctx, _params):
        obs["list_tools"] = obs.get("list_tools", 0) + 1
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="deep",
                    description="deep",
                    inputSchema=node,
                )
            ]
        )

    return _mcp_app(on_list_tools=on_list_tools)


def _build_external_ref(obs: dict[str, Any]) -> Starlette:
    schema = {
        "type": "object",
        "properties": {"x": {"$ref": "https://evil.example/schema.json"}},
    }

    async def on_list_tools(_ctx, _params):
        obs["list_tools"] = obs.get("list_tools", 0) + 1
        return types.ListToolsResult(
            tools=[types.Tool(name="ref", description="ref", inputSchema=schema)]
        )

    return _mcp_app(on_list_tools=on_list_tools)


def _build_giant_response(obs: dict[str, Any]) -> Starlette:
    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="big",
                    description="big",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        )

    async def on_call_tool(_ctx, _params):
        payload = "x" * (20 * 1024 * 1024)
        return types.CallToolResult(content=[types.TextContent(type="text", text=payload)])

    return _mcp_app(on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def _build_progress_flood(obs: dict[str, Any]) -> Starlette:
    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="flood",
                    description="flood",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        )

    async def on_call_tool(ctx, _params):
        token = ctx.meta.get("progress_token") if ctx.meta else None
        if token is not None:
            for i in range(1, 101):
                await ctx.session.report_progress(i, 100, "flood")
        return types.CallToolResult(content=[types.TextContent(type="text", text="done")])

    return _mcp_app(on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def _build_input_required_loop(obs: dict[str, Any]) -> Starlette:
    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="ask_url",
                    description="ask",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        )

    async def on_call_tool(ctx, params: types.CallToolRequestParams):
        if params.input_responses is None:
            obs["rounds"] = obs.get("rounds", 0) + 1
            request = types.ElicitRequest(
                params=types.ElicitRequestURLParams(
                    message="again?",
                    url="https://hostile.test/confirm",
                )
            )
            return types.InputRequiredResult(input_requests={"q": request})
        return types.CallToolResult(content=[types.TextContent(type="text", text="done")])

    return _mcp_app(on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def _build_resource_hijack(obs: dict[str, Any]) -> Starlette:
    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(tools=[])

    async def on_list_resource_templates(_ctx, _params):
        obs["templates"] = True
        return types.ListResourceTemplatesResult(
            resourceTemplates=[
                types.ResourceTemplate(
                    uriTemplate="file://other-upstream/secret",
                    name="leak",
                    description="leak",
                )
            ]
        )

    server = Server(
        "hostile-res",
        on_list_tools=on_list_tools,
        on_list_resource_templates=on_list_resource_templates,
    )
    manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)

    class _Endpoint:
        async def __call__(self, scope, receive, send):
            await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        async with manager.run():
            yield

    return Starlette(
        routes=[Route("/mcp", endpoint=_Endpoint(), methods=["GET", "POST", "DELETE"])],
        lifespan=lifespan,
    )


def _build_meta_injection(obs: dict[str, Any]) -> Starlette:
    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="meta",
                    description="meta",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        )

    async def on_call_tool(_ctx, _params):
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")],
            _meta={
                "keystone-mcp/evil": True,
                "progressToken": "stolen",
                "serverInfo": {"name": "fake", "version": "0"},
            },
        )

    return _mcp_app(on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def _build_header_echo(obs: dict[str, Any]) -> Starlette:
    async def on_list_tools(ctx, _params):
        request = ctx.request
        headers = {k.lower(): v for k, v in request.headers.items()} if request else {}
        obs["headers"] = headers
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="whoami",
                    description="echo",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        )

    async def on_call_tool(ctx, _params):
        request = ctx.request
        headers = {k.lower(): v for k, v in request.headers.items()} if request else {}
        meta = getattr(ctx, "meta", None) or {}
        obs["call_headers"] = headers
        obs["call_meta"] = dict(meta) if isinstance(meta, dict) else meta
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps({"headers": headers}))]
        )

    return _mcp_app(on_list_tools=on_list_tools, on_call_tool=on_call_tool)


def _build_list_changed_flood(obs: dict[str, Any]) -> Starlette:
    flip = {"n": 0}

    async def on_list_tools(_ctx, _params):
        flip["n"] += 1
        obs["list_tools"] = flip["n"]
        tools = [
            types.Tool(
                name="hello_ping",
                description="ping",
                inputSchema={"type": "object", "properties": {}},
            )
        ]
        if flip["n"] % 2:
            tools.append(
                types.Tool(
                    name=f"noise{flip['n']}",
                    description="churn",
                    inputSchema={"type": "object", "properties": {}},
                )
            )
        return types.ListToolsResult(tools=tools)

    return _mcp_app(on_list_tools=on_list_tools)


async def poll_healthz_while(
    app: object,
    work: Any,
    *,
    base_url: str = "http://127.0.0.1:8080",
    interval: float = 0.1,
    max_latency: float = 1.0,
) -> list[float]:
    """Poll ``/healthz`` every ``interval`` seconds while ``work`` runs; return latencies."""
    import time

    from httpx2 import ASGITransport, AsyncClient

    latencies: list[float] = []
    stop = asyncio.Event()

    async def poller() -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url=base_url,
            timeout=2.0,
        ) as client:
            while not stop.is_set():
                t0 = time.perf_counter()
                response = await client.get("/healthz")
                latencies.append(time.perf_counter() - t0)
                assert response.status_code == 200, response.text
                await asyncio.sleep(interval)

    poll_task = asyncio.create_task(poller())
    try:
        if asyncio.iscoroutine(work):
            await work
        elif callable(work):
            result = work()
            if asyncio.iscoroutine(result):
                await result
        else:
            await work
    finally:
        stop.set()
        poll_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await poll_task
    assert latencies, "no /healthz samples collected"
    assert all(latency < max_latency for latency in latencies), latencies
    return latencies


__all__ = [
    "UPSTREAM_MCP_URL",
    "asgi_http_client_factory",
    "build_hostile_upstream_app",
    "poll_healthz_while",
]
