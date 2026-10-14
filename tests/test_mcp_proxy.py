"""McpProxyAdapter unit tests."""

from __future__ import annotations

import json

import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.tools.base import ToolResult

from keystone_mcp.adapters.base import Pattern
from keystone_mcp.adapters.mcp_proxy import McpProxyAdapter
from keystone_mcp.config import Settings, load_settings
from keystone_mcp.identity import AUTHOR_EMAIL_HEADER, VerifiedIdentity, upstream_identity_headers
from keystone_mcp.router.context import RouteContext
from keystone_mcp.router.route import Route
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)

ID = VerifiedIdentity(email="analyst@example.com")


def _ctx(task_id: str = "t_test") -> RouteContext:
    return RouteContext(
        verified_identity=ID,
        task_id=task_id,
        canonical_args="{}",
        tool_name="reports_query_totals",
        pattern=Pattern.SYNC,
        settings=Settings(base_url="http://localhost:8080"),
    )


async def test_mcp_proxy_wraps_success_and_forwards_identity():
    downstream = FastMCP("reports-downstream")

    @downstream.tool()
    def query_totals(report_key: str) -> dict:
        return {
            "status": "ok",
            "columns": ["report_key"],
            "rows": [{"report_key": report_key}],
            "row_count": 1,
            "truncated": False,
            "query_summary": "ok",
            "generated_sql": "SELECT 1",
            "warnings": [],
            "error_code": None,
            "error_message": None,
        }

    adapter = McpProxyAdapter("http://unused")
    adapter._client_factory = lambda **_kw: Client(downstream)  # type: ignore[assignment]

    route = Route(
        name="query_totals",
        target=adapter,
        upstream_tool="query_totals",
        namespace="reports",
        mode="live",
    )
    out = await adapter.execute(route, _ctx(), {"report_key": "402"}, None)
    assert isinstance(out, ToolResult)
    assert out.is_error is False
    assert out.structured_content["status"] == "ok"


async def test_mcp_proxy_maps_upstream_error():
    downstream = FastMCP("reports-downstream")

    @downstream.tool()
    def query_totals(report_key: str) -> dict:
        return {
            "status": "error",
            "columns": [],
            "rows": [],
            "row_count": 0,
            "truncated": False,
            "query_summary": "",
            "generated_sql": None,
            "warnings": [],
            "error_code": "invalid_tool_input",
            "error_message": "bad input",
        }

    adapter = McpProxyAdapter("http://unused", status_envelope=True)
    adapter._client_factory = lambda **_kw: Client(downstream)  # type: ignore[assignment]
    route = Route(
        name="query_totals",
        target=adapter,
        upstream_tool="query_totals",
        namespace="reports",
        mode="live",
    )
    out = await adapter.execute(route, _ctx(), {"report_key": ""}, None)
    assert out["state"] == "error"
    assert out["code"] == "invalid_tool_input"
    assert out["message"] == "bad input"


async def test_mcp_proxy_maps_refused_as_rate_limited():
    downstream = FastMCP("reports-downstream")

    @downstream.tool()
    def query_totals(report_key: str) -> dict:
        return {
            "status": "refused",
            "columns": [],
            "rows": [],
            "row_count": 0,
            "truncated": False,
            "query_summary": "",
            "generated_sql": None,
            "warnings": [],
            "error_code": "rate_limit_exceeded",
            "error_message": "too many requests",
        }

    adapter = McpProxyAdapter("http://unused", status_envelope=True)
    adapter._client_factory = lambda **_kw: Client(downstream)  # type: ignore[assignment]
    route = Route(
        name="query_totals",
        target=adapter,
        upstream_tool="query_totals",
        namespace="reports",
        mode="live",
    )
    out = await adapter.execute(route, _ctx(), {"report_key": "402"}, None)
    assert out["state"] == "error"
    assert out["code"] == "rate_limited"


async def test_mcp_proxy_maps_accepted_as_pending():
    downstream = FastMCP("catalog-downstream")

    @downstream.tool()
    def reports_build(run_id: str) -> dict:
        return {
            "status": "accepted",
            "run_id": run_id,
            "advance_task_id": f"{run_id}:1",
            "target_iteration": 1,
            "source_iteration": 0,
            "job_status": "queued",
            "poll_op": "catalog_status",
        }

    adapter = McpProxyAdapter("http://unused", status_envelope=True)
    adapter._client_factory = lambda **_kw: Client(downstream)  # type: ignore[assignment]
    route = Route(
        name="reports_build",
        target=adapter,
        upstream_tool="reports_build",
        namespace="catalog",
        mode="live",
    )
    out = await adapter.execute(route, _ctx("t_pending"), {"run_id": "run-1"}, None)
    assert out["state"] == "pending"
    assert out["task_id"] == "t_pending"
    assert out["result"]["status"] == "accepted"


def _route(
    name: str,
    *,
    namespace: str = "reports",
    upstream_tool: str | None = None,
) -> Route:
    return Route(
        name=name,
        target=McpProxyAdapter("http://unused"),
        upstream_tool=upstream_tool or name,
        namespace=namespace,
        mode="live",
    )


def test_mcp_proxy_per_tool_timeout_override():
    adapter = McpProxyAdapter(
        "http://unused",
        tool_timeout_seconds=180,
        tool_timeout_overrides={
            "reports_build": 30,
            "reports_publish": 30,
        },
    )
    assert adapter._timeout_for(_route("build", upstream_tool="reports_build")) == 30
    assert adapter._timeout_for(_route("publish", upstream_tool="reports_publish")) == 30
    assert adapter._timeout_for(_route("status", namespace="catalog")) == 180


def test_mcp_proxy_falls_back_to_default_timeout_without_overrides():
    adapter = McpProxyAdapter("http://unused", tool_timeout_seconds=180)
    assert adapter._timeout_for(_route("build", upstream_tool="reports_build")) == 180


def test_mcp_proxy_http_client_disables_redirects():
    from keystone_mcp.adapters.mcp_proxy import _http_client_factory

    client = _http_client_factory(30.0)(headers=None, timeout=None, auth=None)
    assert client.follow_redirects is False


def test_configured_tool_timeouts_reach_the_proxy_adapter(monkeypatch):
    """KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS must land on the adapter that enforces it."""
    from fastmcp import FastMCP

    from keystone_mcp.router.engine import RouterEngine
    from keystone_mcp.router.registry import RouterRegistry
    from keystone_mcp.router.upstream import UpstreamRegistry

    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS", '{"reports_build": 25}')
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUT_SECONDS", "180")
    settings = Settings(base_url="http://localhost:8080")

    main = FastMCP("timeout-host")
    registry = RouterRegistry(RouterEngine(settings), main)
    upstreams = UpstreamRegistry(
        main_mcp=main,
        registry=registry,
        tool_timeout_seconds=settings.upstream_tool_timeout_seconds,
        tool_timeout_overrides=dict(settings.upstream_tool_timeouts),
    )
    upstreams.add_upstream("catalog-mcp", "http://unused", namespace="catalog")

    adapter = upstreams._adapters["catalog"]
    assert (
        adapter._timeout_for(_route("build", namespace="catalog", upstream_tool="reports_build"))
        == 25
    )
    assert adapter._timeout_for(_route("status", namespace="catalog")) == 180


# ── Identity and timeout reach the upstream on the live path ────────────────
async def test_injected_factory_receives_identity_headers_and_timeout():
    """The factory branch used to discard both, so injected clients saw neither."""
    downstream = FastMCP("reports-downstream")

    @downstream.tool()
    def query_totals(report_key: str) -> dict:
        return {"status": "ok", "report_key": report_key}

    seen: dict = {}

    def factory(**kwargs):
        seen.update(kwargs)
        return Client(downstream)

    adapter = McpProxyAdapter(
        "http://unused",
        tool_timeout_seconds=180,
        tool_timeout_overrides={"query_totals": 25},
        client_factory=factory,
    )
    route = Route(
        name="query_totals",
        target=adapter,
        upstream_tool="query_totals",
        namespace="reports",
        mode="live",
    )
    out = await adapter.execute(route, _ctx(), {"report_key": "r1"}, None)

    assert out.is_error is False
    assert seen["headers"] == upstream_identity_headers(ID)
    assert seen["timeout"] == 25


async def test_identity_header_reaches_an_http_upstream_end_to_end():
    """Drive the real StreamableHttpTransport path against an in-process upstream.

    The upstream is served as an ASGI app and reached over httpx, so the
    verified identity genuinely travels as a request header rather than being
    asserted on the adapter's own inputs.
    """
    import httpx2
    from fastmcp.server.dependencies import get_http_headers

    from keystone_mcp.adapters.mcp_proxy import _http_client_factory

    upstream = FastMCP("reports-upstream")
    observed: dict = {}

    @upstream.tool()
    def query_totals(report_key: str) -> dict:
        observed["headers"] = {k.lower(): v for k, v in get_http_headers().items()}
        return {"status": "ok", "report_key": report_key}

    upstream_app = upstream.http_app(path="/mcp")

    captured: dict = {}

    def asgi_http_client_factory(tool_timeout_seconds: float):
        base = _http_client_factory(tool_timeout_seconds)

        def factory(headers=None, timeout=None, auth=None, **_kw):
            built = base(headers=headers, timeout=timeout, auth=auth, **_kw)
            captured["timeout"] = built.timeout
            return httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=upstream_app),
                base_url="http://upstream.local",
                headers=headers,
                timeout=built.timeout,
                auth=auth,
                follow_redirects=False,
            )

        return factory

    adapter = McpProxyAdapter(
        "http://upstream.local/mcp",
        tool_timeout_seconds=180,
        tool_timeout_overrides={"query_totals": 25},
        http_client_factory=asgi_http_client_factory,
    )

    async with LifespanManager(upstream_app):
        route = Route(
            name="query_totals",
            target=adapter,
            upstream_tool="query_totals",
            namespace="reports",
            mode="live",
        )

        async def run_proxy_call():
            return await adapter.execute(route, _ctx(), {"report_key": "r1"}, None)

        out = await run_proxy_call()

    assert out.is_error is False
    assert out.structured_content["report_key"] == "r1"

    # The identity travelled as a header the upstream actually received.
    assert observed["headers"][AUTHOR_EMAIL_HEADER.lower()] == ID.email
    # And the per-tool override (25s), not the 180s default, is the budget the
    # adapter put on the HTTP client the transport actually uses. (The identity
    # header is applied per request by the transport, so it is asserted above on
    # the upstream side rather than on the client object.)
    assert captured["timeout"].read == 25
    assert captured["timeout"].connect == 25


# ── Transparent mode (default): the upstream's answer passes through as-is ──


async def test_transparent_mode_returns_text_as_is():
    app = build_lowlevel_upstream_app(tools=["greet"])
    async with LifespanManager(app):
        adapter = McpProxyAdapter(
            UPSTREAM_MCP_URL, http_client_factory=asgi_http_client_factory(app)
        )
        route = Route(
            name="greet",
            target=adapter,
            upstream_tool="greet",
            namespace="hello",
            mode="live",
        )

        async def run_call():
            return await adapter.execute(route, _ctx(), {"name": "Ann"}, None)

        out = await run_call()

    assert out.content[0].text == "Hello, Ann!"
    assert out.structured_content is None


async def test_transparent_mode_returns_search_text_as_is():
    """Same text-passthrough path as ``greet``, exercised directly on
    ``search`` by calling the adapter without going through discovery/route
    registration.

    ``search`` declares an optional property before a required one in its
    ``inputSchema`` (see ``tests/support/lowlevel_upstream.py``), which keeps
    ``tests/test_proxy_foreign_upstream.py::
    test_search_call_reaches_upstream_without_optional_field`` ``xfail`` until
    P02 fixes route registration. This test calls ``McpProxyAdapter.execute``
    directly, bypassing that registration step, to confirm P03's half of the
    fix — the upstream's plain-text answer is not JSON-decoded — already
    holds for ``search`` too.
    """
    app = build_lowlevel_upstream_app(tools=["search"])
    async with LifespanManager(app):
        adapter = McpProxyAdapter(
            UPSTREAM_MCP_URL, http_client_factory=asgi_http_client_factory(app)
        )
        route = Route(
            name="search", target=adapter, upstream_tool="search", namespace="hello", mode="live"
        )

        async def run_call():
            return await adapter.execute(route, _ctx(), {"query": "q", "filter": "all"}, None)

        out = await run_call()

    assert out.is_error is False
    assert "Found 3 documents for 'q'" in out.content[0].text
    assert out.structured_content is None


async def test_transparent_mode_passes_structured_content_verbatim():
    downstream = FastMCP("misc-downstream")

    @downstream.tool()
    def echo() -> dict:
        return {"status": "ok", "n": 1}

    adapter = McpProxyAdapter("http://unused")
    adapter._client_factory = lambda **_kw: Client(downstream)  # type: ignore[assignment]
    route = Route(name="echo", target=adapter, upstream_tool="echo", namespace="misc", mode="live")

    out = await adapter.execute(route, _ctx(), {}, None)

    assert out.structured_content == {"status": "ok", "n": 1}


async def test_transparent_mode_ignores_status_field():
    downstream = FastMCP("misc-downstream")

    @downstream.tool()
    def echo() -> dict:
        return {"status": "error", "error_message": "x"}

    adapter = McpProxyAdapter("http://unused")
    adapter._client_factory = lambda **_kw: Client(downstream)  # type: ignore[assignment]
    route = Route(name="echo", target=adapter, upstream_tool="echo", namespace="misc", mode="live")

    out = await adapter.execute(route, _ctx(), {}, None)

    assert out.is_error is False
    assert out.structured_content == {"status": "error", "error_message": "x"}


async def test_transparent_mode_reports_upstream_error_flag():
    app = build_lowlevel_upstream_app(tools=["fail"])
    async with LifespanManager(app):
        adapter = McpProxyAdapter(
            UPSTREAM_MCP_URL, http_client_factory=asgi_http_client_factory(app)
        )
        route = Route(
            name="fail", target=adapter, upstream_tool="fail", namespace="hello", mode="live"
        )

        async def run_call():
            return await adapter.execute(route, _ctx(), {}, None)

        out = await run_call()

    assert out.is_error is True
    assert "quota exceeded" in out.content[0].text


async def test_proxy_call_over_legacy_handshake():
    """``Client(..., mode="legacy")`` reaches the same upstream, same answer.

    ``McpProxyAdapter`` builds its default client with ``mode="auto"``
    (X02: no epoch-caching optimisation here, that is left to section Y) --
    the upstream negotiates the newest protocol epoch it can. This pins the
    other end of that negotiation range: a client that forces the pre-SDK-v2
    handshake must still reach the same (SDK v2) upstream and get the exact
    same answer, confirming the proxy does not depend on auto-negotiation to
    talk to an older peer.
    """
    app = build_lowlevel_upstream_app(tools=["greet"])
    async with LifespanManager(app):
        http_client_factory = asgi_http_client_factory(app)

        def legacy_client_factory(headers=None, timeout=None, **_kw):
            transport = StreamableHttpTransport(
                UPSTREAM_MCP_URL,
                headers=headers,
                httpx_client_factory=http_client_factory(timeout or 30.0),
            )
            return Client(transport, timeout=timeout, mode="legacy")

        adapter = McpProxyAdapter(UPSTREAM_MCP_URL, client_factory=legacy_client_factory)
        route = Route(
            name="greet", target=adapter, upstream_tool="greet", namespace="hello", mode="live"
        )

        out = await adapter.execute(route, _ctx(), {"name": "Ann"}, None)

    assert out.is_error is False
    assert out.content[0].text == "Hello, Ann!"


# ── status_envelope=True: 0.3.x envelope, kept for deployments that want it ──


async def test_status_envelope_wraps_plain_text():
    app = build_lowlevel_upstream_app(tools=["greet"])
    async with LifespanManager(app):
        adapter = McpProxyAdapter(
            UPSTREAM_MCP_URL,
            http_client_factory=asgi_http_client_factory(app),
            status_envelope=True,
        )
        route = Route(
            name="greet", target=adapter, upstream_tool="greet", namespace="hello", mode="live"
        )

        async def run_call():
            return await adapter.execute(route, _ctx("t_greet"), {"name": "Ann"}, None)

        out = await run_call()

    assert out == {
        "state": "done",
        "tool": "hello_greet",
        "task_id": "t_greet",
        "result": "Hello, Ann!",
    }


async def test_status_envelope_parses_json_text():
    app = build_lowlevel_upstream_app(tools=["whoami"])
    async with LifespanManager(app):
        adapter = McpProxyAdapter(
            UPSTREAM_MCP_URL,
            http_client_factory=asgi_http_client_factory(app),
            status_envelope=True,
        )
        route = Route(
            name="whoami", target=adapter, upstream_tool="whoami", namespace="hello", mode="live"
        )

        async def run_call():
            return await adapter.execute(route, _ctx(), {}, None)

        out = await run_call()

    assert out["state"] == "done"
    assert isinstance(out["result"], dict)


async def test_status_envelope_raises_tool_error_on_upstream_error():
    app = build_lowlevel_upstream_app(tools=["fail"])
    async with LifespanManager(app):
        adapter = McpProxyAdapter(
            UPSTREAM_MCP_URL,
            http_client_factory=asgi_http_client_factory(app),
            status_envelope=True,
        )
        route = Route(
            name="fail", target=adapter, upstream_tool="fail", namespace="hello", mode="live"
        )

        async def run_call():
            return await adapter.execute(route, _ctx(), {}, None)

        with pytest.raises(ToolError, match="quota exceeded"):
            await run_call()


def test_proxy_status_envelope_env_flag(monkeypatch):
    monkeypatch.delenv("KEYSTONE_MCP_PROXY_STATUS_ENVELOPE", raising=False)
    assert Settings(base_url="http://localhost:8080").proxy_status_envelope is False

    monkeypatch.setenv("KEYSTONE_MCP_PROXY_STATUS_ENVELOPE", "true")
    assert Settings(base_url="http://localhost:8080").proxy_status_envelope is True

    from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
    from keystone_mcp.server import build_server

    payload = [
        {
            "name": "reports-mcp",
            "url": "http://reports-mcp:8081/mcp",
            "namespace": "reports",
            "enabled": True,
        }
    ]
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS", json.dumps(payload))
    _mcp, _registry, _oauth, upstreams, _pm, _obs, _reconciler = build_server(
        settings=load_settings(),
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )

    assert upstreams._adapters["reports"]._status_envelope is True
