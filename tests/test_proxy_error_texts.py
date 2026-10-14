"""Neutral upstream error messages through the Keystone MCP client."""

from __future__ import annotations

import contextlib
from typing import Any

import httpx2
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.utilities.tests import asgi_server
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.shared.exceptions import MCPError
from starlette.applications import Starlette
from starlette.routing import Route

from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)

ANN = VerifiedIdentity(email="ann@example.com")


@pytest.fixture(autouse=True)
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)


def _build_rpc_error_upstream() -> Starlette:
    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="rpc_err",
                    description="rpc",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        )

    async def on_call_tool(_ctx, _params):
        return types.ErrorData(code=types.INVALID_PARAMS, message="secret rpc detail")

    server = Server("rpc", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
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


@pytest.fixture
async def proxy_stack():
    app = build_lowlevel_upstream_app(
        tools={"greet", "fail", "slow"},
        stateless=True,
        json_response=True,
    )
    async with LifespanManager(app):
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(Settings(base_url="http://127.0.0.1:8080")), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()
        yield main, upstreams, app


@pytest.mark.parametrize("downstream_mode", [None, "legacy"], ids=["modern", "legacy"])
async def test_upstream_unavailable_hides_transport_details(proxy_stack, downstream_mode):
    main, upstreams, _app = proxy_stack

    def _connect_error(**_kw: Any) -> Client:
        raise httpx2.ConnectError("Client failed to connect: All connection attempts failed")

    upstreams._adapters["hello"]._client_factory = _connect_error  # noqa: SLF001

    client_kwargs: dict[str, Any] = {}
    if downstream_mode == "legacy":
        client_kwargs["mode"] = "legacy"

    async with asgi_server(main) as running:
        async with running.client(**client_kwargs) as client:
            with pytest.raises(ToolError, match=r"^upstream hello is unavailable$"):
                await client.call_tool("hello_greet", {"name": "Ann"})


@pytest.mark.parametrize("downstream_mode", [None, "legacy"], ids=["modern", "legacy"])
async def test_upstream_timeout_is_not_empty(proxy_stack, downstream_mode):
    main, upstreams, _app = proxy_stack
    upstreams._adapters["hello"]._tool_timeout_overrides = {"hello_slow": 0.3}

    client_kwargs: dict[str, Any] = {}
    if downstream_mode == "legacy":
        client_kwargs["mode"] = "legacy"

    async with asgi_server(main) as running:
        async with running.client(**client_kwargs) as client:
            with pytest.raises(ToolError, match=r"^upstream hello did not answer within 0\.3s$"):
                await client.call_tool("hello_slow", {})


@pytest.fixture
async def rpc_stack():
    app = _build_rpc_error_upstream()
    async with LifespanManager(app):
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(Settings(base_url="http://127.0.0.1:8080")), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()
        yield main, upstreams


@pytest.mark.parametrize("downstream_mode", [None, "legacy"], ids=["modern", "legacy"])
async def test_upstream_json_rpc_error_is_neutral(rpc_stack, downstream_mode):
    main, _upstreams = rpc_stack
    client_kwargs: dict[str, Any] = {}
    if downstream_mode == "legacy":
        client_kwargs["mode"] = "legacy"

    async with asgi_server(main) as running:
        async with running.client(**client_kwargs) as client:
            with pytest.raises(ToolError, match=r"returned an error \(code -32602\)"):
                await client.call_tool("hello_rpc_err", {})


@pytest.mark.parametrize("downstream_mode", [None, "legacy"], ids=["modern", "legacy"])
async def test_upstream_is_error_passes_service_text(proxy_stack, downstream_mode):
    main, _upstreams, _app = proxy_stack
    client_kwargs: dict[str, Any] = {}
    if downstream_mode == "legacy":
        client_kwargs["mode"] = "legacy"

    async with asgi_server(main) as running:
        async with running.client(**client_kwargs) as client:
            with pytest.raises(ToolError, match="upstream failure: quota exceeded"):
                await client.call_tool("hello_fail", {})


def _build_empty_resource_upstream_app() -> Starlette:
    resource = types.Resource(uri="https://secret.example/doc", name="doc", mimeType="text/plain")

    async def _on_list_tools(_ctx, _params):
        return types.ListToolsResult(tools=[])

    async def _on_list_resources(_ctx, _params):
        return types.ListResourcesResult(resources=[resource])

    async def _on_list_resource_templates(_ctx, _params):
        return types.ListResourceTemplatesResult(resource_templates=[])

    async def _on_read_resource(_ctx, _params):
        return types.ReadResourceResult(contents=[])

    server = Server(
        "empty-resource",
        on_list_tools=_on_list_tools,
        on_list_resources=_on_list_resources,
        on_list_resource_templates=_on_list_resource_templates,
        on_read_resource=_on_read_resource,
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


@pytest.mark.parametrize("downstream_mode", [None, "legacy"], ids=["modern", "legacy"])
async def test_empty_resource_read_hides_uri(downstream_mode):
    empty_app = _build_empty_resource_upstream_app()

    async with LifespanManager(empty_app):
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(Settings(base_url="http://127.0.0.1:8080")), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(empty_app),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()

        client_kwargs: dict[str, Any] = {}
        if downstream_mode == "legacy":
            client_kwargs["mode"] = "legacy"

        async with asgi_server(main) as running:
            async with running.client(**client_kwargs) as client:
                resources = await client.list_resources()
                uri = resources[0].uri
                with pytest.raises(
                    MCPError, match=r"^upstream hello returned no content$"
                ) as exc:
                    await client.read_resource(uri)
                assert "file://" not in str(exc.value)
                assert "secret.example" not in str(exc.value)
