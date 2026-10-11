"""Proxy tests against a non-FastMCP (low-level MCP SDK) upstream.

``tests/support/lowlevel_upstream.py`` stands in for a server built on the
TypeScript SDK, the Go SDK, or the low-level Python SDK: it answers with plain
text (not JSON), and its ``search`` tool declares an optional property before
a required one. FastMCP-built upstreams never exercise these paths, so the
rest of the proxy test suite never saw the two bugs these tests pin down.

Keyword-only tool parameters and passing the upstream response through as-is
keep both paths working.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP

from conftest import retry_transient_mcp_errors
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from keystone_mcp.surface.reconciler import SurfaceReconciler
from support.lowlevel_upstream import (
    ODD_NAMES_SCHEMA,
    SEARCH_SCHEMA,
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)

ANN = VerifiedIdentity(email="ann@example.com")


@pytest.fixture(autouse=True)
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)


@pytest.fixture
async def upstream_app():
    app = build_lowlevel_upstream_app()
    async with LifespanManager(app):
        yield app


@pytest.fixture
async def stack(upstream_app, patch_verified_identity):
    """A Keystone proxy mounted over the low-level test upstream, in-process."""
    settings = Settings(base_url="http://localhost:8080")
    main = FastMCP("keystone-test")
    registry = RouterRegistry(RouterEngine(settings), main)
    upstreams = UpstreamRegistry(
        main_mcp=main,
        registry=registry,
        http_client_factory=asgi_http_client_factory(upstream_app),
    )
    upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
    return main, registry, upstreams


def test_support_server_does_not_use_fastmcp():
    source = (
        Path(__file__)
        .parent.joinpath("support", "lowlevel_upstream.py")
        .read_text(encoding="utf-8")
    )
    assert "fastmcp" not in source


async def test_discovery_registers_every_tool_of_a_lowlevel_upstream(stack):
    _main, registry, upstreams = stack

    counts = await retry_transient_mcp_errors(upstreams.discover_all)

    assert counts == {"hello": 6}
    for expected in (
        "hello:greet",
        "hello:search",
        "hello:report",
        "hello:fail",
        "hello:whoami",
        "hello:odd_names",
    ):
        assert expected in registry.routes


async def test_published_search_schema_keeps_required_fields_and_order(stack):
    main, _registry, upstreams = stack
    await retry_transient_mcp_errors(upstreams.discover_all)

    async def _list_tools():
        async with Client(main) as client:
            return await client.list_tools()

    tools = await retry_transient_mcp_errors(_list_tools)
    search_tool = next(t for t in tools if t.name == "hello_search")

    assert search_tool.inputSchema["required"] == ["query", "filter"]
    assert list(search_tool.inputSchema["properties"]) == ["query", "limit", "filter"]


async def test_published_schema_is_the_upstream_schema(stack):
    """P07: the published ``inputSchema`` is the upstream's own, verbatim --
    descriptions, ``enum``, ``minimum``/``maximum``, ``default`` included."""
    main, _registry, upstreams = stack
    await retry_transient_mcp_errors(upstreams.discover_all)

    async def _list_tools():
        async with Client(main) as client:
            return await client.list_tools()

    tools = await retry_transient_mcp_errors(_list_tools)
    search_tool = next(t for t in tools if t.name == "hello_search")

    assert search_tool.inputSchema == SEARCH_SCHEMA


async def test_tool_with_reserved_and_non_identifier_param_names_is_published(stack):
    """Ghost-tool regression guard (FX-proxy #1, closed by P07): a parameter
    named ``from`` (a Python keyword) or ``max-results`` (not a legal Python
    identifier) used to make the whole tool unpublishable, because the old
    code built a Python function signature from the schema. Publishing the
    upstream's own raw schema sidesteps that -- there is no signature to
    build, so the tool shows up in ``list_tools`` with its real schema.
    """
    main, _registry, upstreams = stack
    await retry_transient_mcp_errors(upstreams.discover_all)

    async def _list_tools():
        async with Client(main) as client:
            return await client.list_tools()

    tools = await retry_transient_mcp_errors(_list_tools)
    odd_tool = next(t for t in tools if t.name == "hello_odd_names")

    assert odd_tool.inputSchema == ODD_NAMES_SCHEMA


async def test_tool_with_reserved_param_name_call_reaches_upstream_verbatim(stack):
    """The call itself must carry the original argument names (``from``,
    ``max-results``) through to the upstream, not a renamed/escaped form."""
    main, _registry, upstreams = stack
    await retry_transient_mcp_errors(upstreams.discover_all)

    async def _call():
        async with Client(main) as client:
            return await client.call_tool_mcp("hello_odd_names", {"from": "bob", "max-results": 3})

    result = await retry_transient_mcp_errors(_call)

    assert result.isError is False
    assert result.content[0].text == "from=bob max-results=3"


async def test_search_call_reaches_upstream_without_optional_field(stack):
    main, _registry, upstreams = stack
    await retry_transient_mcp_errors(upstreams.discover_all)

    async def _call():
        async with Client(main) as client:
            return await client.call_tool_mcp("hello_search", {"query": "q", "filter": "all"})

    result = await retry_transient_mcp_errors(_call)

    assert result.isError is False
    assert "Found 3 documents for 'q'" in result.content[0].text


async def test_text_answer_reaches_the_client_as_text():
    app = build_lowlevel_upstream_app(tools=["greet"])
    async with LifespanManager(app):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await retry_transient_mcp_errors(upstreams.discover_all)

        async def _call():
            async with Client(main) as client:
                return await client.call_tool_mcp("hello_greet", {"name": "Ann"})

        result = await retry_transient_mcp_errors(_call)

        assert result.isError is False
        assert result.content[0].text == "Hello, Ann!"


async def test_all_content_blocks_pass_through():
    app = build_lowlevel_upstream_app(tools=["report"])
    async with LifespanManager(app):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await retry_transient_mcp_errors(upstreams.discover_all)

        async def _call():
            async with Client(main) as client:
                return await client.call_tool_mcp("hello_report", {})

        result = await retry_transient_mcp_errors(_call)

        assert [block.type for block in result.content] == ["text", "text", "image"]
        assert result.content[0].text == "Summary: 2 items"
        assert result.content[1].text == "Details: a, b"
        assert result.content[2].mimeType == "image/png"


async def test_upstream_error_is_a_tool_error_with_upstream_text():
    """Safety net: this already works on today's code — do not regress it."""
    app = build_lowlevel_upstream_app(tools=["fail"])
    async with LifespanManager(app):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await retry_transient_mcp_errors(upstreams.discover_all)

        async def _call():
            async with Client(main) as client:
                return await client.call_tool_mcp("hello_fail", {})

        result = await retry_transient_mcp_errors(_call)

        assert result.isError is True
        assert "quota exceeded" in result.content[0].text


async def test_identity_header_reaches_lowlevel_upstream(patch_verified_identity):
    observed: dict = {}
    app = build_lowlevel_upstream_app(tools=["whoami"], observed=observed)
    async with LifespanManager(app):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await retry_transient_mcp_errors(upstreams.discover_all)

        async def _call():
            async with Client(main) as client:
                return await client.call_tool_mcp("hello_whoami", {})

        await retry_transient_mcp_errors(_call)

        assert observed["headers"].get("x-author-email") == ANN.email


# --- upstream bearer auth (P08) -----------------------------------------------------


async def test_bearer_token_reaches_upstream_on_call(monkeypatch, patch_verified_identity):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_HELLO_TOKEN", "s3cr3t-value")
    observed: dict = {}
    app = build_lowlevel_upstream_app(tools=["whoami"], observed=observed)
    async with LifespanManager(app):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream(
            "hello-upstream",
            UPSTREAM_MCP_URL,
            namespace="hello",
            bearer_env="KEYSTONE_MCP_UPSTREAM_HELLO_TOKEN",
        )
        await retry_transient_mcp_errors(upstreams.discover_all)

        async def _call():
            async with Client(main) as client:
                return await client.call_tool_mcp("hello_whoami", {})

        await retry_transient_mcp_errors(_call)

        assert observed["headers"].get("authorization") == "Bearer s3cr3t-value"
        assert observed["headers"].get("x-author-email") == ANN.email


async def test_bearer_token_is_sent_on_discovery(monkeypatch):
    settings = Settings(base_url="http://localhost:8080")

    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_HELLO_TOKEN", "s3cr3t-value")
    app = build_lowlevel_upstream_app(tools=["greet"], require_bearer="s3cr3t-value")
    async with LifespanManager(app):
        main = FastMCP("keystone-test-with-token")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream(
            "hello-upstream",
            UPSTREAM_MCP_URL,
            namespace="hello",
            bearer_env="KEYSTONE_MCP_UPSTREAM_HELLO_TOKEN",
        )
        counts = await retry_transient_mcp_errors(upstreams.discover_all)

        assert counts == {"hello": 1}
        assert upstreams.unavailable_namespaces() == {}

    # Same upstream, same requirement, but discovery carries no token this
    # time: the service is unreachable from Keystone-MCP's point of view.
    monkeypatch.delenv("KEYSTONE_MCP_UPSTREAM_HELLO_TOKEN", raising=False)
    app_no_token = build_lowlevel_upstream_app(tools=["greet"], require_bearer="s3cr3t-value")
    async with LifespanManager(app_no_token):
        main2 = FastMCP("keystone-test-without-token")
        registry2 = RouterRegistry(RouterEngine(settings), main2)
        upstreams2 = UpstreamRegistry(
            main_mcp=main2,
            registry=registry2,
            http_client_factory=asgi_http_client_factory(app_no_token),
        )
        upstreams2.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        counts2 = await retry_transient_mcp_errors(upstreams2.discover_all)

        assert counts2 == {}
        assert "hello" in upstreams2.unavailable_namespaces()


async def test_bearer_token_is_never_logged(monkeypatch, caplog, patch_verified_identity):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_HELLO_TOKEN", "s3cr3t-value")
    # A second, independent representation of the same secret (settings read
    # from KEYSTONE_MCP_UPSTREAMS), so this test also exercises the repr of
    # the dataclass the registry file/JSON loader builds.
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(
            [
                {
                    "name": "hello-upstream",
                    "url": "https://hello.example/mcp",
                    "namespace": "hello",
                    "auth": {"bearer_env": "KEYSTONE_MCP_UPSTREAM_HELLO_TOKEN"},
                }
            ]
        ),
    )
    settings = Settings(base_url="http://localhost:8080", refresh_interval_seconds=300)
    caplog.set_level(logging.DEBUG)

    app = build_lowlevel_upstream_app(tools=["whoami"])
    async with LifespanManager(app):
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream(
            "hello-upstream",
            UPSTREAM_MCP_URL,
            namespace="hello",
            bearer_env="KEYSTONE_MCP_UPSTREAM_HELLO_TOKEN",
        )
        await retry_transient_mcp_errors(upstreams.discover_all)

        async def _call():
            async with Client(main) as client:
                return await client.call_tool_mcp("hello_whoami", {})

        await retry_transient_mcp_errors(_call)

        reconciler = SurfaceReconciler(
            settings=settings,
            registry=registry,
            upstreams=upstreams,
            policy_manager=None,
            observability=None,
        )
        reconciler.seed_snapshots()
        await reconciler.tick()

    assert "s3cr3t-value" not in caplog.text
    assert "s3cr3t-value" not in repr(settings.upstreams)
