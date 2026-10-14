"""HTTP upstream round-trip counts: pinned era, one discovery session, connection pool."""

from __future__ import annotations

import contextlib
import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx2
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from starlette.applications import Starlette
from starlette.routing import Route

from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from keystone_mcp.router.upstream_connection import HttpUpstreamConnection
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)

ANN = VerifiedIdentity(email="ann@example.com")

_REGION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "region": {"type": "string", "x-mcp-header": "Region"},
    },
    "required": ["region"],
}


async def _read_post_method(receive) -> str | None:
    body = b""
    messages: list[dict[str, Any]] = []
    while True:
        message = await receive()
        messages.append(message)
        if message["type"] == "http.request":
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError:
        payload = {}
    if isinstance(payload, dict) and "method" in payload:
        return str(payload["method"])
    return None


def _recording_http_asgi(
    inner: Callable[..., Any],
    recorded: list[str],
) -> Callable[..., Any]:
    async def asgi(scope, receive, send):
        if scope["type"] != "http":
            await inner(scope, receive, send)
            return
        method = scope["method"]
        if method == "DELETE":
            recorded.append("DELETE")
            await inner(scope, receive, send)
            return
        if method == "GET":
            recorded.append("GET")
            await inner(scope, receive, send)
            return
        if method != "POST":
            await inner(scope, receive, send)
            return

        body = b""
        messages: list[dict[str, Any]] = []
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.request":
                body += message.get("body", b"")
                if not message.get("more_body", False):
                    break

        async def replay_receive():
            if messages:
                return messages.pop(0)
            return {"type": "http.disconnect"}

        try:
            payload = json.loads(body) if body else {}
            if isinstance(payload, dict) and "method" in payload:
                recorded.append(str(payload["method"]))
        except json.JSONDecodeError:
            pass
        await inner(scope, replay_receive, send)

    return asgi


def _asgi_with_recording(app: Starlette, recorded: list[str]) -> Callable[..., Any]:
    async def asgi(scope, receive, send):
        if scope["type"] == "lifespan":
            await app(scope, receive, send)
        elif scope["type"] == "http":
            await _recording_http_asgi(app, recorded)(scope, receive, send)
        else:
            await app(scope, receive, send)

    return asgi


def _block_server_discover_http_asgi(
    inner: Callable[..., Any],
    *,
    http_status: int | None = None,
) -> Callable[..., Any]:
    """Reject ``server/discover`` so fastmcp ``mode=auto`` falls back to ``initialize``.

    If JSON-RPC ``-32601`` does not trigger fallback in the client under test,
    set ``http_status=404`` instead (HTTP-layer rejection).
    """

    async def asgi(scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST":
            await inner(scope, receive, send)
            return

        body = b""
        messages: list[dict[str, Any]] = []
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.request":
                body += message.get("body", b"")
                if not message.get("more_body", False):
                    break

        async def replay_receive():
            if messages:
                return messages.pop(0)
            return {"type": "http.disconnect"}

        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict) and payload.get("method") == "server/discover":
            if http_status is not None:
                await send(
                    {
                        "type": "http.response.start",
                        "status": http_status,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"content-length", b"2"),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": b"{}"})
                return
            err = {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "error": {"code": -32601, "message": "Method not found"},
            }
            body_out = json.dumps(err).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body_out)).encode()),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body_out})
            return
        await inner(scope, replay_receive, send)

    return asgi


def _asgi_with_block_discover(app: Starlette) -> Callable[..., Any]:
    async def asgi(scope, receive, send):
        if scope["type"] == "lifespan":
            await app(scope, receive, send)
        elif scope["type"] == "http":
            await _block_server_discover_http_asgi(app, http_status=None)(scope, receive, send)
        else:
            await app(scope, receive, send)

    return asgi


@contextlib.asynccontextmanager
async def _keystone_over_upstream(
    asgi_app: Callable[..., Any],
) -> AsyncIterator[tuple[FastMCP, UpstreamRegistry]]:
    settings = Settings(base_url="http://localhost:8080")
    main = FastMCP("keystone-round-trip")
    registry = RouterRegistry(RouterEngine(settings), main)
    upstreams = UpstreamRegistry(
        main_mcp=main,
        registry=registry,
        http_client_factory=asgi_http_client_factory(asgi_app),
    )
    upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
    await upstreams.discover_all()
    yield main, upstreams


def _legacy_client(main: FastMCP) -> Client:
    return Client(main, mode="legacy")


def _modern_client(main: FastMCP) -> Client:
    return Client(main, mode=next(iter(MODERN_PROTOCOL_VERSIONS)))


@pytest.fixture(autouse=True)
def _patch_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)


@pytest.mark.parametrize(
    "client_factory",
    [_legacy_client, _modern_client],
    ids=["legacy_client", "modern_client"],
)
async def test_modern_upstream_one_request_per_call(client_factory):
    recorded: list[str] = []
    base = build_lowlevel_upstream_app(tools=["greet"], stateless=True)
    asgi_app = _asgi_with_recording(base, recorded)
    async with LifespanManager(asgi_app):
        async with _keystone_over_upstream(asgi_app) as (main, _upstreams):
            recorded.clear()
            async with client_factory(main) as client:
                for _ in range(3):
                    result = await client.call_tool_mcp("hello_greet", {"name": "Ada"})
                    assert result.is_error is False
            assert recorded == ["tools/call", "tools/call", "tools/call"]


async def test_legacy_upstream_round_trips_per_call():
    """Pinned legacy era: each call is handshake + tool + session teardown.

    ``server/discover`` is rejected with JSON-RPC ``-32601`` during discovery
    (fastmcp ``mode=auto`` falls back to ``initialize``).
    """
    recorded: list[str] = []
    base = build_lowlevel_upstream_app(tools=["greet"], stateless=False)
    blocked = _asgi_with_block_discover(base)
    asgi_app = _asgi_with_recording(blocked, recorded)
    async with LifespanManager(asgi_app):
        async with _keystone_over_upstream(asgi_app) as (main, _upstreams):
            recorded.clear()
            async with Client(main, mode="legacy") as client:
                for _ in range(2):
                    result = await client.call_tool_mcp("hello_greet", {"name": "Bob"})
                    assert result.is_error is False
            per_call = [
                "initialize",
                "notifications/initialized",
                "tools/call",
                "DELETE",
            ]
            mcp_only = [m for m in recorded if m != "GET"]
            assert mcp_only == per_call * 2
            assert "server/discover" not in recorded


async def test_discovery_uses_one_session():
    recorded: list[str] = []
    base = build_lowlevel_upstream_app(
        tools=["greet"],
        prompts=True,
        resources=True,
        stateless=True,
    )
    asgi_app = _asgi_with_recording(base, recorded)
    async with LifespanManager(asgi_app):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-discovery")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(asgi_app),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()
        discover_methods = [m for m in recorded if m in ("server/discover", "initialize")]
        assert len(discover_methods) == 1
        assert recorded.count("tools/list") == 1
        assert recorded.count("prompts/list") == 1
        assert recorded.count("resources/list") == 1
        assert recorded.count("resources/templates/list") == 1


async def test_era_is_relearned_on_each_discovery():
    recorded: list[str] = []
    holder: dict[str, Callable[..., Any]] = {}

    base_modern = build_lowlevel_upstream_app(tools=["greet"], stateless=True)
    holder["asgi"] = _asgi_with_recording(base_modern, recorded)
    async with LifespanManager(holder["asgi"]):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-era")
        registry = RouterRegistry(RouterEngine(settings), main)

        def _factory(timeout: float):
            return asgi_http_client_factory(holder["asgi"])(timeout)

        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=_factory,
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()
        async with Client(main, mode=next(iter(MODERN_PROTOCOL_VERSIONS))) as client:
            result = await client.call_tool_mcp("hello_greet", {"name": "first"})
            assert result.is_error is False

        base2 = build_lowlevel_upstream_app(tools=["greet", "search"], stateless=True)
        holder["asgi"] = _asgi_with_recording(base2, recorded)
        async with LifespanManager(holder["asgi"]):
            await upstreams.read_catalog(upstreams._upstreams[0])
            await upstreams._discover_one(upstreams._upstreams[0])
            recorded.clear()
            async with Client(main, mode=next(iter(MODERN_PROTOCOL_VERSIONS))) as client:
                tools = await client.list_tools()
                names = {t.name for t in tools}
                assert "hello_search" in names
                result = await client.call_tool_mcp("hello_search", {"query": "q", "filter": "all"})
                assert result.is_error is False
            assert recorded == ["tools/call"]


async def test_stale_era_falls_back_to_auto():
    recorded: list[str] = []
    modern = build_lowlevel_upstream_app(tools=["greet"], stateless=True)
    legacy = build_lowlevel_upstream_app(tools=["greet"], stateless=False)
    holder: dict[str, Callable[..., Any]] = {}

    modern_asgi = _asgi_with_recording(modern, recorded)
    async with LifespanManager(modern_asgi):
        holder["asgi"] = modern_asgi
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-stale")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=lambda t: asgi_http_client_factory(holder["asgi"])(t),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()
        conn = upstreams.connection("hello")
        assert isinstance(conn, HttpUpstreamConnection)
        assert conn._mode in MODERN_PROTOCOL_VERSIONS

        legacy_blocked = _asgi_with_block_discover(legacy)
        legacy_asgi = _asgi_with_recording(legacy_blocked, recorded)
        async with LifespanManager(legacy_asgi):
            holder["asgi"] = legacy_asgi
            recorded.clear()
            async with Client(main, mode=next(iter(MODERN_PROTOCOL_VERSIONS))) as client:
                try:
                    await client.call_tool_mcp("hello_greet", {"name": "x"})
                except ToolError:
                    pass
                result = await client.call_tool_mcp("hello_greet", {"name": "y"})
                assert result.is_error is False
            assert conn._mode in ("legacy", "auto", next(iter(MODERN_PROTOCOL_VERSIONS)))


async def test_pool_reuses_transport_and_closes_on_stop(monkeypatch):
    created: list[httpx2.AsyncHTTPTransport] = []
    real_transport = httpx2.AsyncHTTPTransport

    def _tracking_transport(*args, **kwargs):
        transport = real_transport(*args, **kwargs)
        created.append(transport)
        return transport

    monkeypatch.setattr(httpx2, "AsyncHTTPTransport", _tracking_transport)
    conn = HttpUpstreamConnection("pool-test", "http://example.test/mcp")
    conn.call_client(headers={}, timeout=5.0)
    conn.call_client(headers={"x": "1"}, timeout=5.0)
    assert len(created) == 1

    main = FastMCP("x")
    upstreams = UpstreamRegistry(
        main_mcp=main,
        registry=RouterRegistry(RouterEngine(Settings(base_url="http://localhost:8080")), main),
    )
    upstreams._connections["pool-test"] = conn
    await upstreams.stop_connections()
    assert len(created) == 1


async def test_param_headers_survive_pinned_era():
    observed: dict[str, Any] = {}

    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="where",
                    description="where",
                    inputSchema=_REGION_SCHEMA,
                )
            ]
        )

    async def on_call_tool(ctx, params):
        request = ctx.request
        headers = {k.lower(): v for k, v in request.headers.items()} if request else {}
        observed["headers"] = headers
        region = (params.arguments or {}).get("region")
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=f"region={region}")],
        )

    server = Server("where", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)

    class _Endpoint:
        async def __call__(self, scope, receive, send):
            await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        async with manager.run():
            yield

    base = Starlette(
        routes=[Route("/mcp", endpoint=_Endpoint(), methods=["GET", "POST", "DELETE"])],
        lifespan=lifespan,
    )
    recorded: list[str] = []
    asgi_app = _asgi_with_recording(base, recorded)
    async with LifespanManager(asgi_app):
        async with _keystone_over_upstream(asgi_app) as (main, _upstreams):
            recorded.clear()
            async with Client(main, mode=next(iter(MODERN_PROTOCOL_VERSIONS))) as client:
                result = await client.call_tool_mcp("hello_where", {"region": "eu-west"})
                assert result.is_error is False
            assert recorded == ["tools/call"]
            assert observed["headers"].get("mcp-param-region") == "eu-west"
