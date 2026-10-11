"""Upstream auto-discovery and namespace mounting tests."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Callable
from unittest.mock import AsyncMock

import httpx
import pydantic
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations

from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.proxy_tool import UpstreamProxyTool
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.route import Route
from keystone_mcp.router.upstream import UpstreamListToolsError, UpstreamRegistry


@pytest.fixture
def downstream_server():
    mcp = FastMCP("reports-downstream")

    @mcp.tool()
    def get_item_history(item_id: str, max_rows: int | None = None) -> dict:
        """Return history for an item by id."""
        return {"status": "ok", "item_id": item_id, "max_rows": max_rows}

    @mcp.tool()
    def list_active_items(max_rows: int | None = None) -> dict:
        """Return active items."""
        return {"status": "ok", "max_rows": max_rows}

    return mcp


async def test_discover_and_register_creates_namespaced_routes(downstream_server):
    main = FastMCP("keystone-main")
    engine = RouterEngine(Settings(base_url="http://localhost:8080"))
    registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(main_mcp=main, registry=registry)

    adapter_url = "http://unused"
    upstreams.add_upstream("reports-mcp", adapter_url, namespace="reports")

    async def patched_discover(cfg):
        sub = upstreams._sub_servers[cfg.namespace]
        adapter = upstreams._adapters[cfg.namespace]
        async with Client(downstream_server) as client:
            tools = await client.list_tools()
        for tool in tools:
            from keystone_mcp.router.schema import schema_to_params

            params = schema_to_params(tool.inputSchema)
            registry.add_route(
                tool.name,
                adapter,
                params=params,
                description=tool.description or "",
                mode="live",
                upstream_tool=tool.name,
                namespace=cfg.namespace,
                config_mode="PROXY",
                tags={cfg.namespace},
                meta={"upstream": cfg.name},
                mcp=sub,
            )
        return len(tools)

    upstreams._discover_one = patched_discover  # type: ignore[method-assign]
    counts = await upstreams.discover_all()
    assert counts["reports"] == 2

    async with Client(main) as client:
        tools = await client.list_tools()
        names = {t.name for t in tools}
        assert "reports_get_item_history" in names
        assert "reports_list_active_items" in names

    route = registry.routes["reports:get_item_history"]
    assert route.namespace == "reports"
    assert route.upstream_tool == "get_item_history"
    assert route.tags == frozenset({"reports"})
    assert any(p.name == "item_id" for p in route.params)


def test_repr_does_not_leak_bearer_token(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_REPORTS_TOKEN", "super-secret-token-value")
    main = FastMCP("keystone-main")
    engine = RouterEngine(Settings(base_url="http://localhost:8080"))
    registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(main_mcp=main, registry=registry)
    upstreams.add_upstream(
        "reports-mcp",
        "http://unused",
        namespace="reports",
        bearer_env="KEYSTONE_MCP_UPSTREAM_REPORTS_TOKEN",
    )

    rendered = repr(upstreams)

    assert "super-secret-token-value" not in rendered
    assert "Bearer" not in rendered


async def test_one_unpublishable_tool_does_not_drop_the_namespace(monkeypatch, caplog):
    """A single tool that cannot be published is skipped, not fatal to discovery.

    Regression guard for the bug where one bad schema raised out of the
    registration loop and dropped every other tool of the same upstream.
    """
    main = FastMCP("keystone-main")
    engine = RouterEngine(Settings(base_url="http://localhost:8080"))
    registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(main_mcp=main, registry=registry)
    upstreams.add_upstream("broken-mcp", "http://unused", namespace="ns")

    empty_schema = {"type": "object", "properties": {}}
    tools = [
        SimpleNamespace(name="bad_tool", description="", inputSchema=empty_schema),
        SimpleNamespace(name="good_tool", description="", inputSchema=empty_schema),
    ]
    monkeypatch.setattr(
        "keystone_mcp.router.upstream.fetch_upstream_tools",
        AsyncMock(return_value=tools),
    )

    original_register_tool = RouterRegistry._register_tool

    def flaky_register_tool(self, route, mcp):
        if route.name == "bad_tool":
            raise RuntimeError("boom")
        return original_register_tool(self, route, mcp)

    monkeypatch.setattr(RouterRegistry, "_register_tool", flaky_register_tool)

    with caplog.at_level("ERROR"):
        counts = await upstreams.discover_all()

    assert counts == {"ns": 1}
    assert "ns:good_tool" in registry.routes
    assert "ns:bad_tool" not in registry.routes
    assert any("upstream tool skipped" in record.message for record in caplog.records)


async def test_namespace_included_in_task_id(downstream_server):
    from keystone_mcp.identity import VerifiedIdentity, make_task_id

    identity = VerifiedIdentity(email="u@example.com")
    bare = make_task_id(identity, "get_item_history", {"item_id": "402"})
    namespaced = make_task_id(
        identity,
        "get_item_history",
        {"item_id": "402"},
        namespace="reports",
    )
    assert bare != namespaced


# --- per-upstream discovery (P05) --------------------------------------------------


def _make_registry() -> tuple[FastMCP, RouterRegistry, UpstreamRegistry]:
    main = FastMCP("keystone-main")
    engine = RouterEngine(Settings(base_url="http://localhost:8080"))
    registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(main_mcp=main, registry=registry)
    return main, registry, upstreams


async def test_discover_all_proxies_available_upstreams_when_one_is_down():
    _main, _registry, upstreams = _make_registry()
    upstreams.add_upstream("down-svc", "http://unused-a", namespace="down")
    upstreams.add_upstream("up-svc", "http://unused-b", namespace="up")

    async def _discover_one(cfg):
        if cfg.namespace == "down":
            raise UpstreamListToolsError("connection refused")
        return 3

    upstreams._discover_one = _discover_one  # type: ignore[method-assign]

    counts = await upstreams.discover_all()

    assert counts == {"up": 3}
    unavailable = upstreams.unavailable_namespaces()
    assert set(unavailable) == {"down"}
    assert "connection refused" in unavailable["down"]


async def test_unavailable_at_startup_log_says_retried_when_refresh_enabled(caplog):
    """Default (refresh enabled): the startup WARNING promises a retry."""
    _main, _registry, upstreams = _make_registry()
    upstreams.add_upstream("down-svc", "http://unused-a", namespace="down")

    async def _discover_one(cfg):
        raise UpstreamListToolsError("connection refused")

    upstreams._discover_one = _discover_one  # type: ignore[method-assign]

    with caplog.at_level("WARNING"):
        counts = await upstreams.discover_all()

    assert counts == {}
    assert any("retried on every refresh tick" in record.message for record in caplog.records)
    assert not any("refresh is disabled" in record.message for record in caplog.records)


async def test_unavailable_at_startup_log_says_disabled_when_refresh_is_off(caplog):
    """``KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS=0``: no background tick will ever
    retry this upstream, so the WARNING must not claim one will happen."""
    main = FastMCP("keystone-main")
    engine = RouterEngine(Settings(base_url="http://localhost:8080"))
    registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(main_mcp=main, registry=registry, refresh_enabled=False)
    upstreams.add_upstream("down-svc", "http://unused-a", namespace="down")

    async def _discover_one(cfg):
        raise UpstreamListToolsError("connection refused")

    upstreams._discover_one = _discover_one  # type: ignore[method-assign]

    with caplog.at_level("WARNING"):
        counts = await upstreams.discover_all()

    assert counts == {}
    assert any(
        "will not be retried; refresh is disabled" in record.message for record in caplog.records
    )
    assert not any("retried on every refresh tick" in record.message for record in caplog.records)


async def test_discovery_retries_each_upstream_separately(monkeypatch: pytest.MonkeyPatch):
    import keystone_mcp.router.upstream as upstream_module

    async def _instant_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(upstream_module.asyncio, "sleep", _instant_sleep)

    _main, _registry, upstreams = _make_registry()
    upstreams.discovery_retries = 2
    upstreams.add_upstream("flaky-svc", "http://unused-a", namespace="flaky")
    upstreams.add_upstream("stable-svc", "http://unused-b", namespace="stable")

    calls = {"flaky": 0, "stable": 0}

    async def _discover_one(cfg):
        calls[cfg.namespace] += 1
        if cfg.namespace == "flaky" and calls["flaky"] < 3:
            raise UpstreamListToolsError("not ready yet")
        return 1

    upstreams._discover_one = _discover_one  # type: ignore[method-assign]

    counts = await upstreams.discover_all()

    assert counts == {"flaky": 1, "stable": 1}
    assert calls["flaky"] == 3
    assert calls["stable"] == 1
    assert upstreams.unavailable_namespaces() == {}


# --- namespace published-name collisions at discovery time (P09) -------------------


async def test_discovery_skips_tool_whose_published_name_is_taken(monkeypatch, caplog):
    """A route already publishing ``reports_read`` blocks the upstream's own tool.

    The upstream's ``read`` tool under namespace ``reports`` would publish
    the same name. Discovery must refuse to register it (ERROR logged, no
    duplicate ``list_tools`` entry) instead of adding a second route under
    the same published name.
    """
    _main, registry, upstreams = _make_registry()
    registry.add_route(
        "reports_read",
        target=object(),
        description="pre-existing owner of this published name",
        mode="live",
    )

    upstreams.add_upstream("reports-mcp", "http://unused", namespace="reports")

    tools = [
        SimpleNamespace(
            name="read", description="", inputSchema={"type": "object", "properties": {}}
        ),
    ]
    monkeypatch.setattr(
        "keystone_mcp.router.upstream.fetch_upstream_tools",
        AsyncMock(return_value=tools),
    )

    with caplog.at_level("ERROR"):
        counts = await upstreams.discover_all()

    assert counts == {"reports": 0}
    assert "reports:read" not in registry.routes
    assert "reports_read" in registry.routes
    assert any("upstream discovery refused" in record.message for record in caplog.records)


# --- published schema is the upstream's own, verbatim (P07) -------------------------


class _Filter(pydantic.BaseModel):
    owner: str


def _build_schema_upstream() -> FastMCP:
    """A FastMCP upstream exercising everything P07 must carry through
    verbatim: a nested required pydantic-model parameter alongside a plain
    required string (neither nullable), an auto-built ``outputSchema``, a
    ``title``, and ``annotations``."""
    mcp = FastMCP("schema-downstream")

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True), title="Advanced Search")
    def advanced_search(filter: _Filter, query: str) -> dict[str, int]:
        """Search with an owner filter."""
        return {"matches": len(query) + len(filter.owner)}

    return mcp


def _asgi_http_client_factory(app) -> Callable[[float], Callable[..., httpx.AsyncClient]]:
    """Same shape as ``support.lowlevel_upstream.asgi_http_client_factory``,
    for a FastMCP (not low-level-SDK) ASGI app."""

    def builder(timeout_seconds: float) -> Callable[..., httpx.AsyncClient]:
        def factory(
            headers: dict[str, str] | None = None,
            timeout: Any = None,  # noqa: ARG001 — superseded by timeout_seconds
            auth: Any = None,
            **_kwargs: Any,
        ) -> httpx.AsyncClient:
            return httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://schema.test",
                headers=headers,
                timeout=httpx.Timeout(timeout_seconds),
                auth=auth,
                follow_redirects=False,
            )

        return factory

    return builder


async def test_nested_object_and_required_are_published_as_is() -> None:
    mcp = _build_schema_upstream()
    app = mcp.http_app(path="/mcp")
    async with LifespanManager(app):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-main")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=_asgi_http_client_factory(app),
        )
        upstreams.add_upstream("schema-mcp", "http://schema.test/mcp", namespace="schema")
        counts = await upstreams.discover_all()
        assert counts == {"schema": 1}

        async with Client(main) as client:
            tools = await client.list_tools()
        tool = next(t for t in tools if t.name == "schema_advanced_search")

        assert tool.inputSchema["required"] == ["filter", "query"]
        filter_schema = tool.inputSchema["properties"]["filter"]
        assert filter_schema["required"] == ["owner"]
        assert filter_schema["properties"]["owner"] == {"type": "string"}
        # Required, no default: must not be published as nullable.
        assert tool.inputSchema["properties"]["query"] == {"type": "string"}


async def test_output_schema_published_only_in_transparent_mode() -> None:
    mcp = _build_schema_upstream()

    async with Client(mcp) as direct_client:
        upstream_tools = await direct_client.list_tools()
    upstream_output_schema = next(
        t for t in upstream_tools if t.name == "advanced_search"
    ).outputSchema
    assert upstream_output_schema is not None

    settings = Settings(base_url="http://localhost:8080")

    # Transparent mode (default): outputSchema is published, verbatim.
    app = mcp.http_app(path="/mcp")
    async with LifespanManager(app):
        main = FastMCP("keystone-main")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            status_envelope=False,
            http_client_factory=_asgi_http_client_factory(app),
        )
        upstreams.add_upstream("schema-mcp", "http://schema.test/mcp", namespace="schema")
        await upstreams.discover_all()

        async with Client(main) as client:
            tools = await client.list_tools()
        tool = next(t for t in tools if t.name == "schema_advanced_search")
        assert tool.outputSchema == upstream_output_schema

    # Envelope mode: the response shape no longer matches the upstream's
    # outputSchema (it is wrapped in {state, tool, task_id, result}), so it
    # must not be published.
    mcp2 = _build_schema_upstream()
    app2 = mcp2.http_app(path="/mcp")
    async with LifespanManager(app2):
        main2 = FastMCP("keystone-main-2")
        registry2 = RouterRegistry(RouterEngine(settings), main2)
        upstreams2 = UpstreamRegistry(
            main_mcp=main2,
            registry=registry2,
            status_envelope=True,
            http_client_factory=_asgi_http_client_factory(app2),
        )
        upstreams2.add_upstream("schema-mcp", "http://schema.test/mcp", namespace="schema")
        await upstreams2.discover_all()

        async with Client(main2) as client2:
            tools2 = await client2.list_tools()
        tool2 = next(t for t in tools2 if t.name == "schema_advanced_search")
        assert tool2.outputSchema is None


async def test_upstream_annotations_and_title_are_published() -> None:
    mcp = _build_schema_upstream()
    app = mcp.http_app(path="/mcp")
    async with LifespanManager(app):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-main")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=_asgi_http_client_factory(app),
        )
        upstreams.add_upstream("schema-mcp", "http://schema.test/mcp", namespace="schema")
        await upstreams.discover_all()

        async with Client(main) as client:
            tools = await client.list_tools()
        tool = next(t for t in tools if t.name == "schema_advanced_search")

        assert tool.title == "Advanced Search"
        assert tool.annotations is not None
        assert tool.annotations.readOnlyHint is True


async def test_proxy_tool_call_round_trip_with_raw_schema(monkeypatch) -> None:
    monkeypatch.setattr(
        "keystone_mcp.identity.resolve_verified_identity",
        lambda: VerifiedIdentity(email="ann@example.com"),
    )
    mcp = _build_schema_upstream()
    app = mcp.http_app(path="/mcp")
    async with LifespanManager(app):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-main")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=_asgi_http_client_factory(app),
        )
        upstreams.add_upstream("schema-mcp", "http://schema.test/mcp", namespace="schema")
        await upstreams.discover_all()

        async with Client(main) as client:
            result = await client.call_tool_mcp(
                "schema_advanced_search",
                {"filter": {"owner": "ann"}, "query": "docs"},
            )

        assert result.isError is False
        # Transparent by default: the upstream's own structuredContent reaches
        # the client unchanged, not wrapped in the {state, tool, ...} envelope.
        assert result.structuredContent == {"matches": len("docs") + len("ann")}


async def test_unauthorized_denial_is_a_tool_error_not_a_schema_mismatch(monkeypatch) -> None:
    """A denied call on a route with a published upstream outputSchema (P07,
    transparent mode) must surface as a clean tool-call failure, not as the
    ad hoc {"state": "error", ...} dict -- a strict client validates
    structuredContent against the published schema and that dict does not
    match it, so the old behaviour surfaced as a confusing schema-validation
    error instead of a straightforward denial.

    A direct unit test of ``UpstreamProxyTool.run`` (no discovery, no ASGI
    transport, no MCP client): the regression is entirely in whether
    ``run()`` raises ``ToolError`` or returns the denial as a plain
    ``ToolResult``, so nothing beyond ``RouterEngine.execute`` denying the
    call needs to be real here. ``route.target`` is never touched -- the
    denial (no verified identity) is raised before the adapter would be
    dispatched to.
    """
    monkeypatch.setattr(
        "keystone_mcp.identity.resolve_verified_identity",
        lambda: None,
    )
    settings = Settings(base_url="http://localhost:8080")
    engine = RouterEngine(settings)
    route = Route(
        name="advanced_search",
        target=None,  # type: ignore[arg-type]
        mode="live",
        namespace="schema",
        upstream_tool="advanced_search",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
        output_schema={
            "type": "object",
            "properties": {"matches": {"type": "integer"}},
            "required": ["matches"],
        },
    )
    tool = UpstreamProxyTool.for_route(route, engine)

    with pytest.raises(ToolError, match="no verified identity"):
        await tool.run({"query": "docs"})
