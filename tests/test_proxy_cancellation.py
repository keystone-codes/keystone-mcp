"""Client cancellation and Keystone timeouts reach the upstream (Y04)."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx2
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from fastmcp.utilities.tests import asgi_server

from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from keystone_mcp.router.upstream_call import call_upstream_tool
from support.lowlevel_upstream import (
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


async def _wait_for_cancelled(observed: dict[str, Any], *, deadline: float = 2.0) -> float:
    loop = asyncio.get_running_loop()
    end = loop.time() + deadline
    while "slow_cancelled_at" not in observed:
        if loop.time() >= end:
            raise AssertionError("upstream slow tool was not cancelled in time")
        await asyncio.sleep(0.01)
    return observed["slow_cancelled_at"]


@pytest.fixture
async def cancel_stack():
    observed: dict[str, Any] = {"slow_started": asyncio.Event()}
    app = build_lowlevel_upstream_app(
        tools={"slow"}, observed=observed, stateless=False, json_response=False
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
        yield main, upstreams, observed, app


@pytest.mark.parametrize(
    "downstream_mode", [None, "legacy"], ids=["downstream-modern", "downstream-legacy"]
)
@pytest.mark.parametrize(
    "upstream_mode", ["auto", "legacy"], ids=["upstream-auto", "upstream-legacy"]
)
async def test_client_cancel_reaches_upstream_within_one_second(
    cancel_stack, downstream_mode, upstream_mode
):
    main, upstreams, observed, app = cancel_stack
    if upstream_mode == "legacy":
        upstreams._adapters["hello"]._client_factory = _legacy_upstream_client_factory(app)

    client_kwargs = {"mode": downstream_mode} if downstream_mode else {}
    async with asgi_server(main) as running:
        async with running.client(**client_kwargs) as client:
            task = asyncio.create_task(client.call_tool("hello_slow", {}))
            await asyncio.wait_for(observed["slow_started"].wait(), timeout=5.0)
            t0 = time.monotonic()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            cancelled_at = await _wait_for_cancelled(observed)
            assert cancelled_at - t0 < 1.0


@pytest.mark.parametrize(
    "upstream_mode", ["auto", "legacy"], ids=["upstream-auto", "upstream-legacy"]
)
async def test_keystone_timeout_cancels_upstream(cancel_stack, upstream_mode):
    main, upstreams, observed, app = cancel_stack
    upstreams._adapters["hello"]._tool_timeout_overrides = {"slow": 0.5}
    if upstream_mode == "legacy":
        upstreams._adapters["hello"]._client_factory = _legacy_upstream_client_factory(app)

    async with asgi_server(main) as running:
        async with running.client() as client:
            with pytest.raises(ToolError, match="timed out"):
                await client.call_tool("hello_slow", {})

    assert "slow_cancelled_at" in observed


async def test_cancel_is_not_sent_for_finished_call():
    posts: list[bytes] = []
    app = build_lowlevel_upstream_app(tools={"greet"}, stateless=False, json_response=False)
    base_factory = asgi_http_client_factory(app, streaming=False)

    def spying_builder(timeout_seconds: float):
        inner = base_factory(timeout_seconds)

        def factory(**kwargs: Any) -> httpx2.AsyncClient:
            client = inner(**kwargs)
            transport = client._transport

            class _SpyTransport(httpx2.AsyncBaseTransport):
                async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
                    if request.method == "POST" and request.content:
                        posts.append(bytes(request.content))
                    return await transport.handle_async_request(request)

            client._transport = _SpyTransport()
            return client

        return factory

    async with LifespanManager(app):
        settings = Settings(base_url="http://127.0.0.1:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=spying_builder,
        )
        upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        upstreams._adapters["hello"]._client_factory = _legacy_upstream_client_factory(
            app, streaming=False
        )
        await upstreams.discover_all()

        async with asgi_server(main) as running:
            async with running.client(mode="legacy") as client:
                result = await client.call_tool("hello_greet", {"name": "Ann"})
            assert result.content[0].text == "Hello, Ann!"

    assert posts
    assert not any(b"notifications/cancelled" in body for body in posts)


async def test_cancel_send_failure_is_swallowed(cancel_stack):
    main, upstreams, observed, app = cancel_stack
    posts: list[bytes] = []
    base_factory = asgi_http_client_factory(app, streaming=True)

    def spying_builder(timeout_seconds: float):
        inner = base_factory(timeout_seconds)

        def factory(**kwargs: Any) -> httpx2.AsyncClient:
            client = inner(**kwargs)
            transport = client._transport

            class _SpyTransport(httpx2.AsyncBaseTransport):
                async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
                    if request.method == "POST" and request.content:
                        posts.append(bytes(request.content))
                        if b"notifications/cancelled" in request.content:
                            raise httpx2.ReadError("spy blocked courtesy cancel")
                    return await transport.handle_async_request(request)

            client._transport = _SpyTransport()
            return client

        return factory

    upstreams._adapters["hello"]._http_client_factory = spying_builder
    upstreams._adapters["hello"]._client_factory = _legacy_upstream_client_factory(app)

    async with asgi_server(main) as running:
        async with running.client(mode="legacy") as client:
            task = asyncio.create_task(client.call_tool("hello_slow", {}))
            await asyncio.wait_for(observed["slow_started"].wait(), timeout=5.0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


@pytest.mark.parametrize(
    "upstream_mode", ["auto", "legacy"], ids=["upstream-auto", "upstream-legacy"]
)
async def test_request_id_tracking_is_exact_under_concurrency(cancel_stack, upstream_mode):
    _main, upstreams, observed, app = cancel_stack
    if upstream_mode == "legacy":
        client_factory = _legacy_upstream_client_factory(app)
    else:
        http_client_factory = asgi_http_client_factory(app, streaming=True)

        def client_factory(headers=None, timeout=None, **_kw):
            transport = StreamableHttpTransport(
                UPSTREAM_MCP_URL,
                headers=headers,
                httpx_client_factory=http_client_factory(timeout or 30.0),
            )
            return Client(transport, timeout=timeout)

    client = client_factory(timeout=30.0)
    async with client:
        tasks = {
            tag: asyncio.create_task(
                call_upstream_tool(
                    client, "slow", {"tag": tag}, timeout=30.0, log_namespace="hello"
                )
            )
            for tag in ("a", "b", "c")
        }
        end = asyncio.get_running_loop().time() + 5.0
        while observed.get("slow_running", 0) < 3:
            if asyncio.get_running_loop().time() >= end:
                raise AssertionError("expected three concurrent slow calls")
            await asyncio.sleep(0.01)

        tasks["b"].cancel()
        with pytest.raises(asyncio.CancelledError):
            await tasks["b"]

        end = asyncio.get_running_loop().time() + 1.0
        while observed.get("slow_cancelled_tags") != ["b"]:
            if asyncio.get_running_loop().time() >= end:
                raise AssertionError(f"wrong cancel tags: {observed.get('slow_cancelled_tags')}")
            await asyncio.sleep(0.01)

        for tag in ("a", "c"):
            tasks[tag].cancel()
            with pytest.raises(asyncio.CancelledError):
                await tasks[tag]
