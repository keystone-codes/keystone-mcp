"""Acceptance tests for upstream registry ``limits`` (F11)."""

from __future__ import annotations

import asyncio
import contextlib
import time
from dataclasses import replace
from typing import Any

import httpx
import httpx2
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.utilities.tests import asgi_server
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from prometheus_client import REGISTRY
from starlette.applications import Starlette
from starlette.routing import Route

from keystone_mcp.auth.rate_window import InMemorySlidingWindow
from keystone_mcp.config import Settings, UpstreamLimits
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.observability.service import RbacObservability
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from keystone_mcp.router.upstream_content import published_uri_for_namespace
from keystone_mcp.router.upstream_guard import UpstreamGuard, UpstreamLimitError
from keystone_mcp.router.upstream_uri_middleware import UpstreamResourceUriMiddleware
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)
from support.test_env import redis_key_prefix, require_redis_url

SUBJECT_A = VerifiedIdentity(email="alice@example.com")
SUBJECT_B = VerifiedIdentity(email="bob@example.com")


def _metric(name: str, labels: dict[str, str]) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def _sliding_window_for(settings: Settings):
    from keystone_mcp.auth.oauth_store import build_shared_auth_stores
    from keystone_mcp.auth.rate_window import InMemorySlidingWindow, RedisSlidingWindow

    if settings.throttle_backend == "redis" and settings.redis_url.strip():
        store, _ = build_shared_auth_stores(settings)
        redis_client = getattr(store, "redis", None)
        if redis_client is not None:
            return RedisSlidingWindow(
                redis_client,
                key_prefix=settings.redis_key_prefix or redis_key_prefix("oauth"),
                kind="upstream",
            )
    return InMemorySlidingWindow()


async def _stack(
    app,
    *,
    limits: UpstreamLimits | None,
    settings: Settings | None = None,
    streaming: bool = True,
    tool_timeout_seconds: float = 3.0,
    tool_timeout_overrides: dict[str, float] | None = None,
    http_client_factory=None,
):
    settings = settings or Settings(
        base_url="http://127.0.0.1:8080",
        metrics_enabled=True,
        throttle_max_requests=10_000,
    )
    main = FastMCP("keystone-upstream-limits")
    registry = RouterRegistry(RouterEngine(settings), main)
    factory = http_client_factory or asgi_http_client_factory(app, streaming=streaming)
    obs = RbacObservability(settings)
    upstreams = UpstreamRegistry(
        main_mcp=main,
        registry=registry,
        http_client_factory=factory,
        tool_timeout_seconds=tool_timeout_seconds,
        tool_timeout_overrides=dict(tool_timeout_overrides or {}),
        observability=obs,
        sliding_window=_sliding_window_for(settings),
    )
    upstreams.add_upstream(
        "hello-upstream",
        UPSTREAM_MCP_URL,
        namespace="hello",
        limits=limits,
    )
    await upstreams.discover_all()
    return main, upstreams, settings, obs


def _restore_working_factory(upstreams: UpstreamRegistry, app) -> None:
    from keystone_mcp.router.upstream_connection import HttpUpstreamConnection

    upstreams.http_client_factory = asgi_http_client_factory(app)
    conn = upstreams._connections["hello"]
    if isinstance(conn, HttpUpstreamConnection):
        conn._http_client_factory = upstreams.http_client_factory


def _hold_upstream_app(observed: dict[str, Any]) -> Starlette:
    releases: list[asyncio.Event] = []

    async def on_list_tools(_ctx, _params):
        return types.ListToolsResult(
            tools=[
                types.Tool(
                    name="slow",
                    description="hold",
                    inputSchema={"type": "object", "properties": {"tag": {"type": "string"}}},
                )
            ]
        )

    async def on_call_tool(_ctx, params):
        tag = (params.arguments or {}).get("tag", "")
        release = asyncio.Event()
        releases.append(release)
        observed.setdefault("tags", []).append(tag)
        observed["slow_running"] = observed.get("slow_running", 0) + 1
        observed["max_running"] = max(observed.get("max_running", 0), observed["slow_running"])
        await release.wait()
        observed["slow_running"] -= 1
        return types.CallToolResult(content=[types.TextContent(type="text", text=tag)])

    observed["releases"] = releases

    server = Server("hold", on_list_tools=on_list_tools, on_call_tool=on_call_tool)
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


@pytest.fixture(autouse=True)
def patch_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: SUBJECT_A)


@pytest.mark.asyncio
async def test_third_call_waits_with_concurrency_two() -> None:
    observed: dict[str, Any] = {}
    app = _hold_upstream_app(observed)
    limits = UpstreamLimits(concurrency=2)
    async with LifespanManager(app):
        main, upstreams, settings, _obs = await _stack(app, limits=limits, streaming=True)
        async with asgi_server(main) as running:
            async with running.client() as client:

                async def one(tag: str) -> str:
                    result = await client.call_tool("hello_slow", {"tag": tag})
                    if isinstance(result.data, str):
                        return result.data
                    if result.content and hasattr(result.content[0], "text"):
                        return result.content[0].text
                    return str(result.data)

                tasks = [
                    asyncio.create_task(one("a")),
                    asyncio.create_task(one("b")),
                    asyncio.create_task(one("c")),
                ]
                for _ in range(40):
                    if observed.get("max_running", 0) >= 2:
                        break
                    await asyncio.sleep(0.05)
                assert observed.get("max_running", 0) == 2
                while len(observed.get("releases", [])) < 2:
                    await asyncio.sleep(0.02)
                for release in observed["releases"][:3]:
                    release.set()
                while len(observed.get("tags", [])) < 3:
                    await asyncio.sleep(0.02)
                if len(observed["releases"]) > 2:
                    observed["releases"][2].set()
                results = await asyncio.gather(*tasks)
                assert sorted(results) == ["a", "b", "c"]
        assert observed.get("max_running", 0) <= 2


@pytest.mark.asyncio
async def test_concurrency_wait_gives_up_with_busy() -> None:
    """Slot wait uses ``min(tool_timeout, 30)`` then returns ``is busy``."""
    limits = UpstreamLimits(concurrency=1)
    obs = RbacObservability(
        Settings(base_url="http://127.0.0.1:8080", metrics_enabled=True),
    )
    guard = UpstreamGuard(
        "hello",
        limits,
        window=InMemorySlidingWindow(),
        observability=obs,
    )
    assert guard._semaphore is not None
    await guard._semaphore.acquire()
    before = _metric(
        "keystone_mcp_upstream_limit_rejections_total",
        {"namespace": "hello", "reason": "concurrency"},
    )
    with pytest.raises(UpstreamLimitError, match="is busy"):
        async with guard.call(timeout=0.5, slot_wait_timeout=0.5):
            pass
    guard._semaphore.release()
    after = _metric(
        "keystone_mcp_upstream_limit_rejections_total",
        {"namespace": "hello", "reason": "concurrency"},
    )
    assert after == before + 1


@pytest.mark.asyncio
async def test_service_rate_limit_is_shared_by_people(monkeypatch) -> None:
    app = build_lowlevel_upstream_app(tools={"greet"})
    limits = UpstreamLimits(rate=3, window_seconds=60)
    async with LifespanManager(app):
        main, _upstreams, settings, _obs = await _stack(app, limits=limits, streaming=False)
        throttle_before = sum(
            sample.value
            for metric in REGISTRY.collect()
            if metric.name == "keystone_mcp_rbac_decisions_total"
            for sample in metric.samples
            if sample.labels.get("reason") == "throttled"
        )
        async with asgi_server(main) as running:
            async with running.client() as client:
                for _ in range(2):
                    await client.call_tool("hello_greet", {"name": "a"})
                monkeypatch.setattr(
                    "keystone_mcp.identity.resolve_verified_identity",
                    lambda: SUBJECT_B,
                )
                for _ in range(2):
                    if _ == 1:
                        with pytest.raises(ToolError, match="over its call limit"):
                            await client.call_tool("hello_greet", {"name": "b"})
                    else:
                        await client.call_tool("hello_greet", {"name": "b"})
        assert _metric(
            "keystone_mcp_upstream_limit_rejections_total",
            {"namespace": "hello", "reason": "rate"},
        ) >= 1
        throttle_after = sum(
            sample.value
            for metric in REGISTRY.collect()
            if metric.name == "keystone_mcp_rbac_decisions_total"
            for sample in metric.samples
            if sample.labels.get("reason") == "throttled"
        )
        assert throttle_after == throttle_before


@pytest.mark.asyncio
async def test_service_rate_limit_shared_across_replicas(monkeypatch) -> None:
    app = build_lowlevel_upstream_app(tools={"greet"})
    limits = UpstreamLimits(rate=3, window_seconds=60)
    redis_url = require_redis_url()
    settings = Settings(
        base_url="http://127.0.0.1:8080",
        metrics_enabled=True,
        throttle_backend="redis",
        redis_url=redis_url,
        redis_key_prefix=redis_key_prefix("limits"),
        throttle_max_requests=10_000,
    )
    async with LifespanManager(app):
        main_a, _ua, _s, _ = await _stack(app, limits=limits, settings=settings, streaming=False)
        main_b, _ub, _s2, _ = await _stack(app, limits=limits, settings=settings, streaming=False)
        async with asgi_server(main_a) as run_a, asgi_server(main_b) as run_b:
            async with run_a.client() as client_a, run_b.client() as client_b:
                await client_a.call_tool("hello_greet", {"name": "1"})
                await client_a.call_tool("hello_greet", {"name": "2"})
                await client_b.call_tool("hello_greet", {"name": "3"})
                with pytest.raises(ToolError, match="over its call limit"):
                    await client_a.call_tool("hello_greet", {"name": "4"})


def _connect_error_factory(app):
    real = asgi_http_client_factory(app)

    def builder(timeout: float):
        _real_inner = real(timeout)

        def _broken(*_args, **_kwargs):
            raise httpx2.ConnectError("transport down")

        return _broken

    return builder


def _apply_connect_errors(upstreams: UpstreamRegistry, app) -> None:
    from keystone_mcp.router.upstream_connection import HttpUpstreamConnection

    factory = _connect_error_factory(app)
    upstreams.http_client_factory = factory
    conn = upstreams._connections["hello"]
    if isinstance(conn, HttpUpstreamConnection):
        conn._http_client_factory = factory


@pytest.mark.asyncio
async def test_breaker_opens_after_failures_and_half_opens() -> None:
    app = build_lowlevel_upstream_app(tools={"greet"})
    limits = UpstreamLimits(breaker_failures=3, breaker_recovery_seconds=0.5)
    async with LifespanManager(app):
        main, upstreams, settings, obs = await _stack(app, limits=limits, streaming=False)
        _apply_connect_errors(upstreams, app)
        assert upstreams._adapters["hello"].guard is not None
        async with asgi_server(main) as running:
            async with running.client() as client:
                for _ in range(3):
                    with pytest.raises(ToolError):
                        await client.call_tool("hello_greet", {"name": "x"})
                guard = upstreams._adapters["hello"].guard
                assert guard is not None
                assert guard._breaker is not None
                assert guard._breaker.state() == "open"
                t0 = time.monotonic()
                with pytest.raises(ToolError, match="temporarily unavailable|failed to connect"):
                    await client.call_tool("hello_greet", {"name": "x"})
                assert time.monotonic() - t0 < 0.05
                await asyncio.sleep(0.55)
                _restore_working_factory(upstreams, app)
                result = await client.call_tool("hello_greet", {"name": "ok"})
                assert not result.is_error
        assert obs.metrics and _metric(
            "keystone_mcp_upstream_circuit_state",
            {"namespace": "hello"},
        ) == 0


@pytest.mark.asyncio
async def test_half_open_allows_single_probe() -> None:
    observed: dict[str, Any] = {}
    app = _hold_upstream_app(observed)
    limits = UpstreamLimits(breaker_failures=1, breaker_recovery_seconds=0.05)
    async with LifespanManager(app):
        main, upstreams, settings, _obs = await _stack(app, limits=limits, streaming=True)
        _apply_connect_errors(upstreams, app)
        async with asgi_server(main) as running:
            async with running.client() as client:
                with pytest.raises(ToolError):
                    await client.call_tool("hello_slow", {"tag": "x"})
                await asyncio.sleep(0.06)
                _restore_working_factory(upstreams, app)
                slow = asyncio.create_task(client.call_tool("hello_slow", {"tag": "probe"}))
                while not observed.get("releases"):
                    await asyncio.sleep(0.02)
                with pytest.raises(ToolError, match="temporarily unavailable"):
                    await client.call_tool("hello_slow", {"tag": "blocked"})
                observed["releases"][0].set()
                await slow


@pytest.mark.asyncio
async def test_failed_probe_reopens() -> None:
    app = build_lowlevel_upstream_app(tools={"greet"})
    limits = UpstreamLimits(breaker_failures=1, breaker_recovery_seconds=0.05)
    async with LifespanManager(app):
        main, upstreams, settings, obs = await _stack(app, limits=limits, streaming=False)
        _apply_connect_errors(upstreams, app)
        async with asgi_server(main) as running:
            async with running.client() as client:
                with pytest.raises(ToolError):
                    await client.call_tool("hello_greet", {"name": "x"})
                await asyncio.sleep(0.06)
                with pytest.raises(ToolError):
                    await client.call_tool("hello_greet", {"name": "probe"})
        assert _metric("keystone_mcp_upstream_circuit_state", {"namespace": "hello"}) == 1


@pytest.mark.asyncio
async def test_tool_error_from_upstream_is_not_a_failure() -> None:
    app = build_lowlevel_upstream_app(tools={"fail"})
    limits = UpstreamLimits(breaker_failures=3, breaker_recovery_seconds=30)
    async with LifespanManager(app):
        main, _upstreams, settings, obs = await _stack(app, limits=limits, streaming=False)
        async with asgi_server(main) as running:
            async with running.client() as client:
                for _ in range(5):
                    with pytest.raises(ToolError, match="fail"):
                        await client.call_tool("hello_fail", {})
        assert _metric("keystone_mcp_upstream_circuit_state", {"namespace": "hello"}) == 0


@pytest.mark.asyncio
async def test_limits_apply_to_prompts_and_resources() -> None:
    app = build_lowlevel_upstream_app(tools={"greet"}, prompts=True, resources=True)
    limits = UpstreamLimits(rate=1, window_seconds=60)
    async with LifespanManager(app):
        main, upstreams, settings, _obs = await _stack(app, limits=limits, streaming=False)
        main.add_middleware(UpstreamResourceUriMiddleware(upstreams.content))
        handbook_uri = published_uri_for_namespace("hello", "file:///handbook.md")
        async with asgi_server(main) as running:
            async with running.client() as client:
                await client.get_prompt("hello_summarize", {"topic": "t"})
                with pytest.raises(Exception, match="over its call limit"):
                    await client.read_resource(handbook_uri)


@pytest.mark.asyncio
async def test_no_limits_no_guard() -> None:
    app = build_lowlevel_upstream_app(tools={"greet"})
    async with LifespanManager(app):
        main, upstreams, settings, _obs = await _stack(app, limits=None, streaming=False)
        assert upstreams._adapters["hello"].guard is None
        assert _metric("keystone_mcp_upstream_inflight", {"namespace": "hello"}) == 0
        async with asgi_server(main) as running:
            async with running.client() as client:
                result = await client.call_tool("hello_greet", {"name": "x"})
                assert not result.is_error


@pytest.mark.asyncio
async def test_readyz_shows_circuit_state_to_internal_callers() -> None:
    from starlette.responses import JSONResponse

    from keystone_mcp.server import _is_trusted_internal_caller

    app = build_lowlevel_upstream_app(tools={"greet"})
    limits = UpstreamLimits(breaker_failures=5, breaker_recovery_seconds=30)
    async with LifespanManager(app):
        main, upstreams, settings, _obs = await _stack(app, limits=limits, streaming=False)
        settings = replace(settings, base_url="http://127.0.0.1:8080")

        @main.custom_route("/readyz", methods=["GET"])
        async def _readyz(request):  # noqa: ANN001
            body: dict[str, object] = {"status": "ok"}
            if _is_trusted_internal_caller(request, settings):
                body["upstreams"] = upstreams.upstream_readiness_snapshot()
            return JSONResponse(body)

        http_app = main.http_app(path=settings.http_path)
        async with LifespanManager(http_app):
            transport = httpx.ASGITransport(app=http_app, client=("127.0.0.1", 12345))
            async with httpx.AsyncClient(transport=transport, base_url=settings.base_url) as client:
                internal = await client.get(
                    "/readyz",
                    headers={"Host": "127.0.0.1:8080"},
                )
                assert internal.json()["upstreams"]["hello"]["circuit"] == "closed"
                assert "inflight" in internal.json()["upstreams"]["hello"]
            transport_ext = httpx.ASGITransport(app=http_app, client=("203.0.113.9", 12345))
            async with httpx.AsyncClient(transport=transport_ext, base_url=settings.base_url) as client:
                external = await client.get("/readyz")
                assert "upstreams" not in external.json()
