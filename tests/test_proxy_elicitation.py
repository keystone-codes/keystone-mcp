"""Upstream elicitation forwarding through Keystone (Y07)."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.client.elicitation import ElicitResult
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.utilities.tests import asgi_server

from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from support.lowlevel_upstream import (
    ASK_SCHEMA,
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)

ANN = VerifiedIdentity(email="ann@example.com")


@pytest.fixture(autouse=True)
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)


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


def _accept_handler(record: dict[str, Any]):
    async def handler(message, response_type, params, _context):
        record["message"] = message
        record["schema"] = getattr(params, "requested_schema", None)
        if response_type is not None:
            return {"ok": True, "choice": "a"}
        return ElicitResult(action="accept", content={"ok": True})

    return handler


def _action_handler(record: dict[str, Any], action: str):
    async def handler(message, response_type, params, _context):
        record["message"] = message
        record["schema"] = getattr(params, "requested_schema", None)
        return ElicitResult(action=action)

    return handler


@pytest.fixture
async def elicitation_stack():
    app = build_lowlevel_upstream_app(
        extra_tools={"ask", "ask_url", "ask_weird"},
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
            http_client_factory=asgi_http_client_factory(app, streaming=True),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()
        yield main, upstreams, app


@pytest.mark.parametrize("downstream_mode", ["legacy", None], ids=["path-L", "path-N1"])
async def test_elicitation_reaches_client_with_prefix_and_schema(
    elicitation_stack, downstream_mode
):
    main, upstreams, app = elicitation_stack
    record: dict[str, Any] = {}
    client_kwargs: dict[str, Any] = {"elicitation_handler": _accept_handler(record)}
    if downstream_mode == "legacy":
        client_kwargs["mode"] = "legacy"

    async with asgi_server(main) as running:
        async with running.client(**client_kwargs) as client:
            result = await client.call_tool("hello_ask", {})
            assert not result.is_error
            text = result.content[0].text
            assert text.startswith("answer=accept:")

    assert record["message"] == "[hello] Proceed?"
    assert record["schema"] == ASK_SCHEMA


@pytest.mark.parametrize("downstream_mode", ["legacy", None], ids=["path-L", "path-N1"])
@pytest.mark.parametrize("action", ["accept", "decline", "cancel"])
async def test_client_elicitation_action_reaches_upstream(
    elicitation_stack, downstream_mode, action
):
    main, _upstreams, _app = elicitation_stack
    record: dict[str, Any] = {}
    if action == "accept":
        handler = _accept_handler(record)
    else:
        handler = _action_handler(record, action)
    client_kwargs: dict[str, Any] = {"elicitation_handler": handler}
    if downstream_mode == "legacy":
        client_kwargs["mode"] = "legacy"

    async with asgi_server(main) as running:
        async with running.client(**client_kwargs) as client:
            result = await client.call_tool("hello_ask", {})
            assert not result.is_error
            assert f"answer={action}:" in result.content[0].text


@pytest.mark.parametrize("downstream_mode", ["legacy", None], ids=["path-L", "path-N1"])
async def test_upstream_sees_no_elicitation_without_client_capability(
    elicitation_stack, downstream_mode
):
    main, _upstreams, _app = elicitation_stack
    client_kwargs: dict[str, Any] = {}
    if downstream_mode == "legacy":
        client_kwargs["mode"] = "legacy"

    async with asgi_server(main) as running:
        async with running.client(**client_kwargs) as client:
            result = await client.call_tool("hello_ask", {})
            assert result.content[0].text == "no-elicitation"


@pytest.mark.parametrize("downstream_mode", ["legacy", None], ids=["path-L", "path-N1"])
async def test_url_elicitation_is_declined_without_reaching_client(
    elicitation_stack, downstream_mode
):
    main, _upstreams, _app = elicitation_stack
    seen: dict[str, Any] = {"called": False}

    async def handler(message, _response_type, params, _context):
        seen["called"] = True
        seen["message"] = message
        return ElicitResult(action="accept")

    client_kwargs: dict[str, Any] = {"elicitation_handler": handler}
    if downstream_mode == "legacy":
        client_kwargs["mode"] = "legacy"

    async with asgi_server(main) as running:
        async with running.client(**client_kwargs) as client:
            result = await client.call_tool("hello_ask_url", {})
            assert not result.is_error
            assert "answer=decline:" in result.content[0].text

    assert seen["called"] is False


@pytest.mark.parametrize("downstream_mode", ["legacy", None], ids=["path-L", "path-N1"])
async def test_weird_schema_passes_without_error(elicitation_stack, downstream_mode):
    main, _upstreams, _app = elicitation_stack

    async def handler(_message, _response_type, _params, _context):
        return {"x": None}

    client_kwargs: dict[str, Any] = {"elicitation_handler": handler}
    if downstream_mode == "legacy":
        client_kwargs["mode"] = "legacy"

    async with asgi_server(main) as running:
        async with running.client(**client_kwargs) as client:
            result = await client.call_tool("hello_ask_weird", {})
            assert not result.is_error
            assert "answer=accept:" in result.content[0].text


async def test_modern_client_with_handshake_upstream_is_declined(elicitation_stack):
    main, upstreams, app = elicitation_stack
    upstreams._adapters["hello"]._client_factory = _legacy_upstream_client_factory(app)
    record: dict[str, Any] = {}

    async with asgi_server(main) as running:
        async with running.client(elicitation_handler=_accept_handler(record)) as client:
            result = await client.call_tool("hello_ask", {})
            assert not result.is_error
            assert "answer=decline:" in result.content[0].text


async def test_setting_false_disables_elicitation(elicitation_stack, monkeypatch):
    main, upstreams, _app = elicitation_stack
    upstreams._adapters["hello"]._proxy_elicitation = False
    record: dict[str, Any] = {}

    async with asgi_server(main) as running:
        async with running.client(elicitation_handler=_accept_handler(record)) as client:
            result = await client.call_tool("hello_ask", {})
            assert result.content[0].text == "no-elicitation"


async def test_stdio_upstream_never_gets_elicitation(monkeypatch, tmp_path):
    from test_stdio_upstream_e2e import _with_stdio_stack

    record: dict[str, Any] = {}
    async with _with_stdio_stack(monkeypatch, tmp_path) as (mcp, _upstreams, _reconciler):
        async with Client(mcp, elicitation_handler=_accept_handler(record)) as client:
            result = await client.call_tool("notes_ask", {})
            assert result.content[0].text == "no-elicitation"


def test_fastmcp_private_elicitation_apis_confined_to_upstream_call():
    root = Path(__file__).resolve().parents[1] / "src" / "keystone_mcp"
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        if path.name == "upstream_call.py":
            continue
        text = path.read_text(encoding="utf-8")
        if "_session_kwargs" in text or "_await_with_session_monitoring" in text:
            offenders.append(str(path.relative_to(root.parent)))
    assert offenders == []


def _build_input_required_upstream(*, method: str, observed: dict[str, int]) -> Any:
    import contextlib

    from mcp import types
    from mcp.server.lowlevel import Server
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.routing import Route

    tool_name = "ask_special"

    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name=tool_name,
                    description="ask",
                    inputSchema={"type": "object", "properties": {}},
                )
            ]
        )

    async def on_call_tool(_ctx, _params):
        observed["calls"] = observed.get("calls", 0) + 1
        if method == "sampling/createMessage":
            request = types.CreateMessageRequest(
                method=method,
                params=types.CreateMessageRequestParams(messages=[], max_tokens=1),
            )
        else:
            request = types.ListRootsRequest(method=method)
        return types.InputRequiredResult(input_requests={"q": request})

    server = Server("special", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
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


async def test_sampling_request_fails_call_with_clear_text(monkeypatch):
    observed: dict[str, int] = {}
    app = _build_input_required_upstream(method="sampling/createMessage", observed=observed)
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
            async with running.client() as client:
                with pytest.raises(ToolError, match="asked for sampling/createMessage"):
                    await client.call_tool("hello_ask_special", {})
    assert observed.get("calls") == 1


async def test_roots_request_fails_call_with_clear_text(monkeypatch):
    observed: dict[str, int] = {}
    app = _build_input_required_upstream(method="roots/list", observed=observed)
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
            async with running.client() as client:
                with pytest.raises(ToolError, match="asked for roots/list"):
                    await client.call_tool("hello_ask_special", {})
    assert observed.get("calls") == 1


def test_upstream_call_uses_only_allowed_private_fastmcp_apis():
    path = (
        Path(__file__).resolve().parents[1] / "src" / "keystone_mcp" / "router" / "upstream_call.py"
    )
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.attr, str):
            if node.attr in {"_session_kwargs", "_await_with_session_monitoring"}:
                names.add(node.attr)
    assert names == {"_await_with_session_monitoring", "_session_kwargs"}
