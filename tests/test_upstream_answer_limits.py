"""Upstream answer and catalog limits (C09 acceptance)."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
from typing import Any

import mcp.types as types
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.utilities.tests import asgi_server
from mcp.client.session import ClientSession
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from prometheus_client import REGISTRY
from starlette.applications import Starlette
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route

from keystone_mcp.config import ConfigError, Settings, load_settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from keystone_mcp.surface.reconciler import SurfaceReconciler
from support.lowlevel_upstream import (
    GREET_SCHEMA,
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
)

ANN = VerifiedIdentity(email="ann@example.com")


@pytest.fixture(autouse=True)
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)


def _legacy_upstream_client_factory(app, *, max_response_bytes: int | None = None):
    http_client_factory = asgi_http_client_factory(app, max_response_bytes=max_response_bytes)

    def factory(headers=None, timeout=None, **_kw):
        transport = StreamableHttpTransport(
            UPSTREAM_MCP_URL,
            headers=headers,
            httpx_client_factory=http_client_factory(timeout or 30.0),
        )
        return Client(transport, timeout=timeout, mode="legacy")

    return factory


def _mount_healthz(main: FastMCP) -> None:
    @main.custom_route("/healthz", methods=["GET"])
    async def _healthz(_request):
        return JSONResponse({"status": "ok"})


def _build_keystone_stack(
    upstream_app: Starlette,
    *,
    upstream_max_schema_bytes: int | None = None,
    upstream_max_catalog_items: int | None = None,
    upstream_max_response_bytes: int | None = None,
    http_client_factory=None,
    client_factory=None,
    namespace: str = "svc",
):
    settings = Settings(base_url="http://localhost:8080")
    main = FastMCP("keystone-test")
    _mount_healthz(main)
    registry = RouterRegistry(RouterEngine(settings), main)
    kw: dict[str, Any] = {
        "http_client_factory": http_client_factory
        or asgi_http_client_factory(
            upstream_app,
            max_response_bytes=upstream_max_response_bytes,
        ),
    }
    if upstream_max_schema_bytes is not None:
        kw["upstream_max_schema_bytes"] = upstream_max_schema_bytes
    if upstream_max_catalog_items is not None:
        kw["upstream_max_catalog_items"] = upstream_max_catalog_items
    if upstream_max_response_bytes is not None:
        kw["upstream_max_response_bytes"] = upstream_max_response_bytes
    upstreams = UpstreamRegistry(main_mcp=main, registry=registry, **kw)
    upstreams.add_upstream("svc", UPSTREAM_MCP_URL, namespace=namespace)
    if client_factory is not None:
        upstreams._adapters[namespace]._client_factory = client_factory
    return main, registry, upstreams, settings


def _build_redos_upstream_app() -> Starlette:
    observed: dict[str, int] = {"list_tools": 0}

    async def on_list_tools(_ctx, _params):
        observed["list_tools"] += 1
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="match",
                    description="match",
                    inputSchema={"type": "object", "properties": {}},
                    outputSchema={
                        "type": "object",
                        "properties": {"v": {"type": "string", "pattern": "^(a+)+$"}},
                    },
                )
            ]
        )

    async def on_call_tool(_ctx, params: types.CallToolRequestParams):
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")],
            structuredContent={"v": "a" * 27 + "!"},
        )

    server = Server("redos", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)

    class _Endpoint:
        async def __call__(self, scope, receive, send):
            await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        async with manager.run():
            yield

    app = Starlette(
        routes=[Route("/mcp", endpoint=_Endpoint(), methods=["GET", "POST", "DELETE"])],
        lifespan=lifespan,
    )
    app.observed = observed  # type: ignore[attr-defined]
    return app


def _build_method_counter_upstream(*, big_tool: bool = False) -> Starlette:
    observed: dict[str, int] = {"list_tools": 0}

    async def on_list_tools(_ctx, _params):
        observed["list_tools"] += 1
        tools = [
            types.Tool(
                name="small",
                description="small",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]
        if big_tool:
            tools.append(
                types.Tool(
                    name="big",
                    description="big",
                    inputSchema={"type": "object", "properties": {}},
                )
            )
        return types.ListToolsResult(tools=tools)

    async def on_call_tool(_ctx, params: types.CallToolRequestParams):
        if params.name == "big":
            payload = "x" * (1024 * 1024)
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=payload)],
            )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="small ok")],
        )

    server = Server("limits", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)

    class _Endpoint:
        async def __call__(self, scope, receive, send):
            await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        async with manager.run():
            yield

    app = Starlette(
        routes=[Route("/mcp", endpoint=_Endpoint(), methods=["GET", "POST", "DELETE"])],
        lifespan=lifespan,
    )
    app.observed = observed  # type: ignore[attr-defined]
    return app


def _build_schema_upstream(*, output_schema: dict[str, Any] | None = None) -> Starlette:
    async def on_list_tools(_ctx, _params):
        tools = [
            types.Tool(
                name="good",
                description="good",
                inputSchema=GREET_SCHEMA,
            ),
        ]
        if output_schema is not None:
            tools.append(
                types.Tool(
                    name="bad",
                    description="bad",
                    inputSchema={"type": "object", "properties": {}},
                    outputSchema=output_schema,
                )
            )
        return types.ListToolsResult(tools=tools)

    async def on_call_tool(_ctx, _params):
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])

    server = Server("schema", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
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


def _build_catalog_upstream(tool_count: int) -> Starlette:
    async def on_list_tools(_ctx, _params):
        tools = [
            types.Tool(
                name=f"t{i}",
                description=f"tool {i}",
                inputSchema={"type": "object", "properties": {}},
            )
            for i in range(tool_count)
        ]
        return types.ListToolsResult(tools=tools)

    async def on_call_tool(_ctx, params: types.CallToolRequestParams):
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=params.name)],
        )

    server = Server("catalog", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
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


def _build_redirect_upstream() -> Starlette:
    async def redirect_mcp(_request):
        return RedirectResponse("/mcp/", status_code=307)

    server = Server("redirect")
    manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)

    class _Endpoint:
        async def __call__(self, scope, receive, send):
            await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        async with manager.run():
            yield

    return Starlette(
        routes=[
            Route("/mcp", endpoint=redirect_mcp, methods=["POST"]),
            Route("/mcp/", endpoint=_Endpoint(), methods=["GET", "POST", "DELETE"]),
        ],
        lifespan=lifespan,
    )


def _build_meta_upstream(*, prompts: bool = False) -> Starlette:
    server_info = {"name": "evil-upstream", "version": "0.0.1"}
    meta = {types.SERVER_INFO_META_KEY: server_info, "x-test": 1}

    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="echo",
                    description="echo",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        )

    async def on_call_tool(_ctx, _params):
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="hi")],
            meta=meta,
        )

    kwargs: dict[str, Any] = {"on_list_tools": on_list_tools, "on_call_tool": on_call_tool}
    if prompts:

        async def on_list_prompts(_ctx, _params):
            return types.ListPromptsResult(prompts=[types.Prompt(name="p1", description="p1")])

        async def on_get_prompt(_ctx, _params):
            return types.GetPromptResult(
                messages=[
                    types.PromptMessage(
                        role="user", content=types.TextContent(type="text", text="hi")
                    )
                ],
                meta=meta,
            )

        kwargs["on_list_prompts"] = on_list_prompts
        kwargs["on_get_prompt"] = on_get_prompt

    server = Server("meta", **kwargs)
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


async def test_pathological_output_schema_does_not_stall_event_loop():
    app = _build_redos_upstream_app()
    async with LifespanManager(app):
        main, _registry, upstreams, settings = _build_keystone_stack(app)
        await upstreams.discover_all()
        async with asgi_server(main, path=settings.http_path) as running:
            async with running.client() as client:

                async def call_tool():
                    try:
                        return await asyncio.wait_for(
                            client.call_tool("svc_match", {}),
                            timeout=1.0,
                        )
                    except RuntimeError:
                        return None

                async def ping_healthz():
                    http = running.http_client()
                    async with http:
                        return await asyncio.wait_for(
                            http.get("/healthz"),
                            timeout=0.5,
                        )

                _health, _tool = await asyncio.gather(ping_healthz(), call_tool())
            assert _health.status_code == 200
            # Downstream MCP clients may still reject invalid structured content;
            # the acceptance criterion is that Keystone's event loop is not stalled.


@pytest.mark.parametrize("client_mode", ["legacy", None])
async def test_no_tools_list_on_each_call(client_mode: str | None):
    app = _build_method_counter_upstream()
    async with LifespanManager(app):
        factory = (
            _legacy_upstream_client_factory(app)
            if client_mode == "legacy"
            else asgi_http_client_factory(app)
        )
        main, _registry, upstreams, settings = _build_keystone_stack(
            app,
            client_factory=factory if client_mode == "legacy" else None,
        )
        await upstreams.discover_all()
        baseline = app.observed["list_tools"]
        if client_mode == "legacy":
            async with Client(main, mode="legacy") as client:
                await client.call_tool("svc_small", {})
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await client.call_tool("svc_small", {})
        assert app.observed["list_tools"] == baseline


def test_output_validation_sentinel():
    source = inspect.getsource(ClientSession.call_tool)
    assert "self.validate_tool_result(" in source
    method = getattr(ClientSession, "validate_tool_result", None)
    assert method is not None
    params = list(inspect.signature(method).parameters)
    assert params[:3] == ["self", "name", "result"]


async def test_oversized_schema_is_not_published():
    big_schema = {"type": "object", "properties": {f"p{i}": {"type": "string"} for i in range(400)}}
    app = _build_schema_upstream(output_schema=big_schema)
    async with LifespanManager(app):
        main, _registry, upstreams, settings = _build_keystone_stack(
            app, upstream_max_schema_bytes=1024
        )
        await upstreams.discover_all()
        async with asgi_server(main, path=settings.http_path) as running:
            async with running.client() as client:
                names = {t.name for t in await client.list_tools()}
        assert "svc_good" in names
        assert "svc_bad" not in names
        assert (
            REGISTRY.get_sample_value(
                "keystone_mcp_upstream_items_rejected_total",
                {"namespace": "svc", "kind": "tool", "reason": "schema_too_large"},
            )
            or 0
        ) >= 1


async def test_long_pattern_is_not_published():
    pattern = "x" * 600
    schema = {
        "type": "object",
        "properties": {"v": {"type": "string", "pattern": pattern}},
    }
    app = _build_schema_upstream(output_schema=schema)
    async with LifespanManager(app):
        main, _registry, upstreams, settings = _build_keystone_stack(app)
        await upstreams.discover_all()
        async with asgi_server(main, path=settings.http_path) as running:
            async with running.client() as client:
                names = {t.name for t in await client.list_tools()}
        assert "svc_bad" not in names
        assert (
            REGISTRY.get_sample_value(
                "keystone_mcp_upstream_items_rejected_total",
                {"namespace": "svc", "kind": "tool", "reason": "schema_pattern_too_long"},
            )
            or 0
        ) >= 1


async def test_too_deep_schema_is_not_published():
    schema: dict[str, Any] = {"type": "object"}
    node = schema
    for _ in range(70):
        node["properties"] = {"n": {"type": "object"}}
        node = node["properties"]["n"]
    app = _build_schema_upstream(output_schema=schema)
    async with LifespanManager(app):
        main, _registry, upstreams, settings = _build_keystone_stack(app)
        await upstreams.discover_all()
        async with asgi_server(main, path=settings.http_path) as running:
            async with running.client() as client:
                names = {t.name for t in await client.list_tools()}
        assert "svc_bad" not in names
        assert (
            REGISTRY.get_sample_value(
                "keystone_mcp_upstream_items_rejected_total",
                {"namespace": "svc", "kind": "tool", "reason": "schema_too_deep"},
            )
            or 0
        ) >= 1


async def test_catalog_over_limit_keeps_previous_catalog():
    app = _build_catalog_upstream(2)
    async with LifespanManager(app):
        main, registry, upstreams, settings = _build_keystone_stack(
            app, upstream_max_catalog_items=3
        )
        await upstreams.discover_all()
        rec = SurfaceReconciler(
            settings=settings,
            registry=registry,
            upstreams=upstreams,
            policy_manager=None,
            observability=None,
        )
        rec.seed_snapshots()
        app2 = _build_catalog_upstream(5)
        async with LifespanManager(app2):
            upstreams.http_client_factory = asgi_http_client_factory(app2)
            upstreams._adapters["svc"]._http_client_factory = upstreams.http_client_factory
            await upstreams.discover_all()
            assert "svc" in upstreams.unavailable_namespaces()
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    names = {t.name for t in await client.list_tools()}
            assert names == {"svc_t0", "svc_t1"}


@pytest.mark.parametrize("client_mode", ["legacy", None])
async def test_response_over_limit_fails_call_not_process(client_mode: str | None):
    app = _build_method_counter_upstream(big_tool=True)
    limit = 64 * 1024
    async with LifespanManager(app):
        factory = (
            _legacy_upstream_client_factory(app, max_response_bytes=limit)
            if client_mode == "legacy"
            else asgi_http_client_factory(app, max_response_bytes=limit)
        )
        main, _registry, upstreams, settings = _build_keystone_stack(
            app,
            upstream_max_response_bytes=limit,
            http_client_factory=asgi_http_client_factory(app, max_response_bytes=limit)
            if client_mode != "legacy"
            else None,
            client_factory=factory if client_mode == "legacy" else None,
        )
        await upstreams.discover_all()
        if client_mode == "legacy":
            async with Client(main, mode="legacy") as client:
                with pytest.raises(ToolError, match=f"larger than {limit} bytes"):
                    await client.call_tool("svc_big", {})
                ok = await client.call_tool("svc_small", {})
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    with pytest.raises(ToolError, match=f"larger than {limit} bytes"):
                        await client.call_tool("svc_big", {})
                    ok = await client.call_tool("svc_small", {})
        assert "small ok" in str(ok.content)
        assert (
            REGISTRY.get_sample_value(
                "keystone_mcp_upstream_items_rejected_total",
                {"namespace": "svc", "kind": "response", "reason": "response_too_large"},
            )
            or 0
        ) >= 1


async def test_discovery_does_not_follow_redirects(caplog):
    app = _build_redirect_upstream()
    async with LifespanManager(app):
        main, _registry, upstreams, _settings = _build_keystone_stack(app)
        with caplog.at_level(logging.WARNING):
            await upstreams.discover_all()
        assert "svc" in upstreams.unavailable_namespaces()
        assert any(
            "redirect" in rec.message.lower() or "svc" in rec.message for rec in caplog.records
        )


async def test_upstream_server_info_does_not_reach_client():
    app = _build_meta_upstream(prompts=True)
    async with LifespanManager(app):
        main, _registry, upstreams, settings = _build_keystone_stack(app)
        await upstreams.discover_all()
        async with asgi_server(main, path=settings.http_path) as running:
            async with running.client() as client:
                tool = await client.call_tool("svc_echo", {})
                meta = getattr(tool, "meta", None) or {}
                si = meta.get(types.SERVER_INFO_META_KEY)
                assert si is None or si.get("name") != "evil-upstream"
                assert meta.get("x-test") == 1
                prompt = await client.get_prompt("svc_p1", {})
                pmeta = getattr(prompt, "meta", None) or {}
                psi = pmeta.get(types.SERVER_INFO_META_KEY)
                assert psi is None or psi.get("name") != "evil-upstream"
                assert pmeta.get("x-test") == 1


@pytest.mark.parametrize(
    ("env_name", "value"),
    [
        ("KEYSTONE_MCP_UPSTREAM_MAX_RESPONSE_BYTES", "0"),
        ("KEYSTONE_MCP_UPSTREAM_MAX_SCHEMA_BYTES", "0"),
        ("KEYSTONE_MCP_UPSTREAM_MAX_CATALOG_ITEMS", "0"),
    ],
)
def test_settings_reject_non_positive_limits(monkeypatch, env_name: str, value: str):
    monkeypatch.setenv(env_name, value)
    with pytest.raises(ConfigError, match=env_name):
        load_settings()
