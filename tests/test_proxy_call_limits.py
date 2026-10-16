"""Proxy call limits: input rounds, per-tool timeouts, Mcp-Param-* headers."""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import Any

import anyio
import jwt
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.client.elicitation import ElicitResult
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.utilities.tests import asgi_server
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from prometheus_client import REGISTRY
from starlette.applications import Starlette
from starlette.routing import Route

from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from keystone_mcp.router.upstream_call import (
    _decode_keystone_request_state,
    _encode_keystone_request_state,
)
from keystone_mcp.server import bootstrap_upstreams
from support.lowlevel_upstream import (
    ASK_SCHEMA,
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)

ANN = VerifiedIdentity(email="ann@example.com")
_IDENTITY_SECRET_VALUE = "0" * 32


@pytest.fixture(autouse=True)
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)


@pytest.fixture(autouse=True)
def reset_upstream_timeout_deprecation_warnings():
    from keystone_mcp.adapters import mcp_proxy

    mcp_proxy._warned_upstream_timeout_keys.clear()
    yield
    mcp_proxy._warned_upstream_timeout_keys.clear()


def _legacy_upstream_client_factory(app, *, streaming: bool = True):
    http_client_factory = asgi_http_client_factory(app, streaming=streaming)

    def factory(headers=None, timeout=None, **_kw):
        transport = StreamableHttpTransport(
            UPSTREAM_MCP_URL,
            headers=headers,
            httpx_client_factory=http_client_factory(timeout or 30.0),
        )
        return Client(transport, timeout=timeout, mode="legacy")

    return factory


def _accept_elicitation_handler():
    async def handler(message, response_type, params, _context):
        if response_type is not None:
            return {"ok": True}
        return ElicitResult(action="accept", content={"ok": True})

    return handler


def _build_url_nag_upstream(counter: dict[str, int]):
    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="nag",
                    description="nag",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        )

    async def on_call_tool(_ctx, _params):
        counter["n"] = counter.get("n", 0) + 1
        req = types.ElicitRequest(
            params=types.ElicitRequestURLParams(
                message="go",
                url="https://example.test/confirm",
                elicitation_id="e1",
            )
        )
        return types.InputRequiredResult(input_requests={"q": req})

    server = Server("nag", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
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


def _build_form_nag_upstream(counter: dict[str, int]):
    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="nag_form",
                    description="nag",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        )

    async def on_call_tool(_ctx, _params):
        counter["n"] = counter.get("n", 0) + 1
        req = types.ElicitRequest(
            params=types.ElicitRequestFormParams(
                message="Proceed?",
                requested_schema=ASK_SCHEMA,
            )
        )
        return types.InputRequiredResult(input_requests={"q": req})

    server = Server("nag", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
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


def _build_slow_input_upstream(counter: dict[str, int]):
    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="slow_ir",
                    description="slow",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        )

    async def on_call_tool(_ctx, _params):
        counter["n"] = counter.get("n", 0) + 1
        await anyio.sleep(0.3)
        req = types.ElicitRequest(
            params=types.ElicitRequestURLParams(
                message="go",
                url="https://example.test/confirm",
                elicitation_id="e1",
            )
        )
        return types.InputRequiredResult(input_requests={"q": req})

    server = Server("slow", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
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


def _build_legacy_nag_upstream(observed: dict[str, Any]):
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}

    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="nag_legacy",
                    description="legacy nag",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        )

    async def on_call_tool(ctx, _params):
        for _ in range(15):
            observed["rounds"] = observed.get("rounds", 0) + 1
            result = await ctx.session.elicit_form(
                "Question?",
                schema,
                related_request_id=ctx.request_id,
            )
            if result.action == "cancel":
                observed["last_action"] = "cancel"
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text="cancelled")],
                )
            observed["last_action"] = result.action
        return types.CallToolResult(content=[types.TextContent(type="text", text="done")])

    server = Server("legacy-nag", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
    manager = StreamableHTTPSessionManager(app=server, stateless=False, json_response=False)

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


_REGION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "region": {"type": "string", "x-mcp-header": "Region"},
    },
    "required": ["region"],
}


def _build_region_upstream(observed: dict[str, Any]):
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

    return Starlette(
        routes=[Route("/mcp", endpoint=_Endpoint(), methods=["GET", "POST", "DELETE"])],
        lifespan=lifespan,
    )


async def test_url_elicitation_loop_stops_after_max_rounds():
    counter: dict[str, int] = {}
    app = _build_url_nag_upstream(counter)
    async with LifespanManager(app):
        settings = Settings(base_url="http://127.0.0.1:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()

        before = (
            REGISTRY.get_sample_value(
                "keystone_mcp_upstream_input_rounds_exceeded_total",
                {"namespace": "hello"},
            )
            or 0.0
        )

        t0 = time.monotonic()
        async with asgi_server(main) as running:
            async with running.client(elicitation_handler=_accept_elicitation_handler()) as client:
                with pytest.raises(ToolError, match="kept requesting input"):
                    await client.call_tool("hello_nag", {})
        elapsed = time.monotonic() - t0

        assert elapsed < 2.0
        assert counter.get("n", 0) <= 10
        after = REGISTRY.get_sample_value(
            "keystone_mcp_upstream_input_rounds_exceeded_total",
            {"namespace": "hello"},
        )
        assert after == before + 1


async def test_form_question_rounds_are_capped_across_client_retries():
    counter: dict[str, int] = {}
    app = _build_form_nag_upstream(counter)
    async with LifespanManager(app):
        settings = Settings(base_url="http://127.0.0.1:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()

        async with asgi_server(main) as running:
            async with running.client(elicitation_handler=_accept_elicitation_handler()) as client:
                with pytest.raises(ToolError, match="kept requesting input"):
                    await client.call_tool("hello_nag_form", {"ok": True})

        assert counter.get("n", 0) <= 10


def test_request_state_from_050_without_round_counter_still_works():
    assert _decode_keystone_request_state('{"v":1,"u":"s","d":[]}') == ("s", [], 0)
    encoded = _encode_keystone_request_state("s", [], 0)
    assert _decode_keystone_request_state(encoded) == ("s", [], 0)


async def test_request_state_without_round_counter_end_to_end():
    from unittest.mock import AsyncMock, MagicMock

    from mcp.server.connection import MODERN_PROTOCOL_VERSIONS

    from keystone_mcp.router.upstream_call import DownstreamCall, call_upstream_tool

    legacy_state = '{"v":1,"u":"upstream-token","d":[]}'

    session = MagicMock()
    session.protocol_version = next(iter(MODERN_PROTOCOL_VERSIONS))
    session.check_client_capability = MagicMock(return_value=True)
    downstream = DownstreamCall(session=session, request_id="1", progress_token=None)

    client = MagicMock()
    client.protocol_version = next(iter(MODERN_PROTOCOL_VERSIONS))

    async def _monitor(awaitable):
        return await awaitable

    client._await_with_session_monitoring = _monitor
    client.session.call_tool = AsyncMock(
        return_value=types.CallToolResult(content=[types.TextContent(type="text", text="ok")]),
    )

    result = await call_upstream_tool(
        client,
        "tool",
        {},
        timeout=30.0,
        downstream=downstream,
        log_namespace="hello",
        request_state=legacy_state,
        input_responses={"q": types.ElicitResult(action="accept", content={"ok": True})},
    )
    assert isinstance(result, types.CallToolResult)
    kwargs = client.session.call_tool.call_args.kwargs
    assert kwargs["request_state"] == "upstream-token"


async def test_whole_input_loop_is_bounded_by_tool_timeout():
    counter: dict[str, int] = {}
    app = _build_slow_input_upstream(counter)
    async with LifespanManager(app):
        settings = Settings(base_url="http://127.0.0.1:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            tool_timeout_seconds=0.5,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()

        t0 = time.monotonic()
        async with asgi_server(main) as running:
            async with running.client(elicitation_handler=_accept_elicitation_handler()) as client:
                with pytest.raises(ToolError, match="did not answer within"):
                    await client.call_tool("hello_slow_ir", {})
        assert time.monotonic() - t0 < 1.5


async def test_legacy_elicitation_rounds_are_capped():
    observed: dict[str, Any] = {}
    app = _build_legacy_nag_upstream(observed)
    async with LifespanManager(app):
        settings = Settings(base_url="http://127.0.0.1:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app, streaming=True),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()
        upstreams._adapters["hello"]._client_factory = _legacy_upstream_client_factory(app)

        async with asgi_server(main) as running:
            async with running.client(elicitation_handler=_accept_elicitation_handler()) as client:
                result = await client.call_tool("hello_nag_legacy", {})
        assert not result.is_error
        assert observed.get("last_action") == "cancel"
        assert observed.get("rounds", 0) == 11


async def test_tool_timeout_override_by_published_name():
    observed = {"slow_started": asyncio.Event()}
    app = build_lowlevel_upstream_app(
        tools={"slow"},
        observed=observed,
        stateless=False,
        json_response=False,
    )
    async with LifespanManager(app):
        settings = Settings(base_url="http://127.0.0.1:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            tool_timeout_seconds=3.0,
            tool_timeout_overrides={"hello_slow": 0.5},
            http_client_factory=asgi_http_client_factory(app, streaming=True),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()

        t0 = time.monotonic()
        async with asgi_server(main) as running:
            async with running.client() as client:
                with pytest.raises(ToolError, match="did not answer within"):
                    await client.call_tool("hello_slow", {})
        assert time.monotonic() - t0 < 1.0


async def test_tool_timeout_override_by_upstream_name_still_works_with_warning(
    caplog,
):
    observed = {"slow_started": asyncio.Event()}
    app = build_lowlevel_upstream_app(
        tools={"slow"},
        observed=observed,
        stateless=False,
        json_response=False,
    )
    caplog.set_level("WARNING")
    async with LifespanManager(app):
        settings = Settings(base_url="http://127.0.0.1:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            tool_timeout_seconds=3.0,
            tool_timeout_overrides={"slow": 0.5},
            http_client_factory=asgi_http_client_factory(app, streaming=True),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()

        t0 = time.monotonic()
        async with asgi_server(main) as running:
            async with running.client() as client:
                with pytest.raises(ToolError, match="did not answer within"):
                    await client.call_tool("hello_slow", {})
        assert time.monotonic() - t0 < 1.0

        warnings = [
            r.message for r in caplog.records if "use the published name 'hello_slow'" in r.message
        ]
        assert len(warnings) == 1


async def test_same_upstream_tool_name_in_two_namespaces_gets_own_timeout():
    observed = {"slow_started": asyncio.Event()}
    app = build_lowlevel_upstream_app(
        tools={"slow"},
        observed=observed,
        stateless=False,
        json_response=False,
    )
    async with LifespanManager(app):
        settings = Settings(base_url="http://127.0.0.1:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            tool_timeout_seconds=3.0,
            tool_timeout_overrides={"hello_slow": 0.5},
            http_client_factory=asgi_http_client_factory(app, streaming=True),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        upstreams.add_upstream("other-upstream", UPSTREAM_MCP_URL, namespace="other")
        await upstreams.discover_all()

        t0 = time.monotonic()
        async with asgi_server(main) as running:
            async with running.client() as client:
                with pytest.raises(ToolError, match="did not answer within"):
                    await client.call_tool("other_slow", {})
        assert time.monotonic() - t0 > 1.0


async def test_unknown_timeout_keys_are_logged_after_discovery(caplog):
    observed = {"slow_started": asyncio.Event()}
    app = build_lowlevel_upstream_app(tools={"slow"}, observed=observed)
    caplog.set_level("WARNING")
    async with LifespanManager(app):
        settings = Settings(
            base_url="http://127.0.0.1:8080",
            upstream_tool_timeouts={"nope_x": 1.0},
        )
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            tool_timeout_overrides=dict(settings.upstream_tool_timeouts),
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await bootstrap_upstreams(upstreams, settings)

        assert any("['nope_x']" in r.message for r in caplog.records)


@pytest.mark.parametrize(
    "upstream_mode", ["auto", "legacy"], ids=["upstream-auto", "upstream-legacy"]
)
async def test_x_mcp_header_reaches_modern_upstream(upstream_mode):
    observed: dict[str, Any] = {}
    app = _build_region_upstream(observed)
    async with LifespanManager(app):
        settings = Settings(base_url="http://127.0.0.1:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()
        if upstream_mode == "legacy":
            upstreams._adapters["hello"]._client_factory = _legacy_upstream_client_factory(app)

        async with Client(main) as client:
            result = await client.call_tool("hello_where", {"region": "eu"})
        assert not result.is_error
        assert observed["headers"].get("mcp-param-region") == "eu"


async def test_x_mcp_header_is_harmless_for_legacy_upstream():
    observed: dict[str, Any] = {}
    app = _build_region_upstream(observed)
    async with LifespanManager(app):
        settings = Settings(base_url="http://127.0.0.1:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app, streaming=True),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()
        upstreams._adapters["hello"]._client_factory = _legacy_upstream_client_factory(app)

        async with Client(main) as client:
            result = await client.call_tool("hello_where", {"region": "eu"})
        assert not result.is_error


async def test_param_headers_do_not_replace_identity_headers(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_HELLO_IDENTITY_SECRET", _IDENTITY_SECRET_VALUE)
    observed: dict[str, Any] = {}
    app = _build_region_upstream(observed)
    async with LifespanManager(app):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
            identity_issuer=settings.base_url.rstrip("/"),
        )
        upstreams.add_upstream(
            "hello-upstream",
            UPSTREAM_MCP_URL,
            namespace="hello",
            identity_secret_env="KEYSTONE_MCP_UPSTREAM_HELLO_IDENTITY_SECRET",
        )
        await upstreams.discover_all()

        async with Client(main) as client:
            await client.call_tool("hello_where", {"region": "eu"})
        headers = observed["headers"]
        assert headers.get("mcp-param-region") == "eu"
        assert headers.get("x-author-email") == ANN.email
        token = headers.get("x-keystone-identity")
        assert token is not None
        jwt.decode(
            token,
            _IDENTITY_SECRET_VALUE,
            algorithms=["HS256"],
            audience="hello-upstream",
            issuer=settings.base_url.rstrip("/"),
        )
