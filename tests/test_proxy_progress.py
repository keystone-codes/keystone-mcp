"""``notifications/progress`` from an upstream tool call reaches the client.

The proxy registers a ``progress_handler`` with the upstream call only
when the client asked for progress (sent a ``progressToken``), and relays
every notification to that same client request via its own session. Covered
on both axes that can vary independently: the protocol era the *client*
negotiates with Keystone (``mode="legacy"`` vs the default, which negotiates
the modern era), and the era Keystone's own client negotiates with the
*upstream* (``mode="auto"`` -- the test upstream, built on SDK 2, answers on
the modern era -- vs ``mode="legacy"``, forced via an injected client
factory, same as ``tests/test_mcp_proxy.py::
test_proxy_call_over_legacy_handshake``).
"""

from __future__ import annotations

from typing import Any

import anyio
import mcp.types
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport

from keystone_mcp.adapters.base import Pattern
from keystone_mcp.adapters.mcp_proxy import McpProxyAdapter
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.context import RouteContext
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.route import Route
from keystone_mcp.router.upstream import UpstreamRegistry
from keystone_mcp.router.upstream_call import (
    DownstreamCall,
    _progress_token_from_request_meta,
    call_upstream_tool,
)
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)

ANN = VerifiedIdentity(email="ann@example.com")


@pytest.fixture(autouse=True)
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)


def _ctx(task_id: str = "t_test") -> RouteContext:
    return RouteContext(
        verified_identity=ANN,
        task_id=task_id,
        canonical_args="{}",
        tool_name="hello_whoami",
        pattern=Pattern.SYNC,
        settings=Settings(base_url="http://localhost:8080"),
    )


def _legacy_upstream_client_factory(app):
    """Force Keystone's own client to use the pre-SDK-v2 handshake with *app*.

    Mirrors ``tests/test_mcp_proxy.py::test_proxy_call_over_legacy_handshake``
    -- the upstream (SDK 2) still answers; only the negotiated epoch changes.
    """
    http_client_factory = asgi_http_client_factory(app)

    def factory(headers=None, timeout=None, **_kw):
        transport = StreamableHttpTransport(
            UPSTREAM_MCP_URL,
            headers=headers,
            httpx_client_factory=http_client_factory(timeout or 30.0),
        )
        return Client(transport, timeout=timeout, mode="legacy")

    return factory


@pytest.fixture
async def progress_stack():
    """A Keystone proxy mounted over a lowlevel ``count`` upstream, in-process.

    ``stateless=False, json_response=False``: a progress notification can
    only reach the client ahead of the final answer when the upstream session
    is not buffering the whole call into one JSON response body (see
    ``build_lowlevel_upstream_app``'s docstring).
    """
    observed: dict = {}
    app = build_lowlevel_upstream_app(
        tools={"count"}, observed=observed, stateless=False, json_response=False
    )
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
        await upstreams.discover_all()
        yield main, upstreams, observed, app


class _ExplodingSession:
    """Stands in for a ``ServerSession`` whose client has already gone away."""

    async def report_progress(
        self, progress: float, total: float | None = None, message: str | None = None
    ) -> None:
        raise anyio.ClosedResourceError


@pytest.mark.parametrize(
    "downstream_mode", [None, "legacy"], ids=["downstream-modern", "downstream-legacy"]
)
@pytest.mark.parametrize(
    "upstream_mode", ["auto", "legacy"], ids=["upstream-auto", "upstream-legacy"]
)
async def test_three_progress_notifications_reach_the_client(
    progress_stack, downstream_mode, upstream_mode
):
    main, upstreams, _observed, app = progress_stack
    if upstream_mode == "legacy":
        upstreams._adapters["hello"]._client_factory = _legacy_upstream_client_factory(app)

    collected: list[tuple[float, float | None, str | None]] = []

    async def collect(progress: float, total: float | None, message: str | None) -> None:
        collected.append((progress, total, message))

    client_kwargs = {"mode": downstream_mode} if downstream_mode else {}
    async with Client(main, **client_kwargs) as client:
        result = await client.call_tool("hello_count", {"steps": 3}, progress_handler=collect)

    assert collected == [(1, 3, "step 1"), (2, 3, "step 2"), (3, 3, "step 3")]
    assert result.content[0].text == "counted 3"


async def test_no_progress_token_means_no_forwarding():
    """``call_upstream_tool`` registers no forwarding handler when the request
    it is answering carried no ``progressToken``.

    Not checked end to end by asking whether the *upstream* ever sees a
    ``progressToken`` on the wire: fastmcp's own ``Client`` substitutes a
    default, log-only, never-forwarded progress handler at construction time
    whenever none is given (``Client.__init__`` in ``fastmcp/client/
    client.py``: ``if progress_handler is None: progress_handler =
    default_progress_handler``), so *every* call a fastmcp ``Client`` makes
    already carries a token -- Keystone's own call to the upstream included,
    with or without progress forwarding, downstream request or not. That default handler
    only logs locally and is never reachable from outside this process, so it
    forwards nothing to the real client; it is not something this contract
    is about preventing. What progress forwarding actually guarantees -- and what is
    checked here directly -- is that ``call_upstream_tool`` only ever passes
    *its own* forwarding handler (the one that calls back into the
    downstream's ``ServerSession.report_progress``) when the request it is
    answering had a ``progressToken`` of its own.
    """
    calls: list[Any] = []

    class _RecordingClient:
        async def call_tool_mcp(self, name, arguments, progress_handler=None, **_kw):
            calls.append(progress_handler)
            return mcp.types.CallToolResult(
                content=[mcp.types.TextContent(type="text", text="counted 2")]
            )

    client = _RecordingClient()

    await call_upstream_tool(client, "count", {"steps": 2}, timeout=30.0, downstream=None)
    no_token_downstream = DownstreamCall(
        session=_ExplodingSession(), request_id="r1", progress_token=None
    )
    await call_upstream_tool(
        client, "count", {"steps": 2}, timeout=30.0, downstream=no_token_downstream
    )

    assert calls == [None, None]


async def test_progress_forward_failure_does_not_fail_the_call():
    app = build_lowlevel_upstream_app(tools={"count"}, stateless=False, json_response=False)
    async with LifespanManager(app):
        http_client_factory = asgi_http_client_factory(app)
        client = Client(
            StreamableHttpTransport(
                UPSTREAM_MCP_URL, httpx_client_factory=http_client_factory(30.0)
            ),
        )
        downstream = DownstreamCall(
            session=_ExplodingSession(), request_id="r1", progress_token="tok-1"
        )
        async with client:
            result = await call_upstream_tool(
                client, "count", {"steps": 2}, timeout=30.0, downstream=downstream
            )

    assert result.is_error is False
    assert result.content[0].text == "counted 2"


def test_downstream_call_outside_request_is_none():
    assert DownstreamCall.current() is None


def test_progress_token_from_request_meta_accepts_snake_case():
    class _Meta:
        progress_token = "tok-snake"

    assert _progress_token_from_request_meta(_Meta()) == "tok-snake"
    assert _progress_token_from_request_meta({"progress_token": "a"}) == "a"
    assert _progress_token_from_request_meta({"progressToken": "b"}) == "b"
    assert _progress_token_from_request_meta(None) is None


async def test_status_envelope_mode_still_parses_data():
    """Guards the private ``Client._parse_call_tool_result`` (see
    ``keystone_mcp.router.upstream_call.parse_for_status_envelope``): if a
    future fastmcp upgrade removes or renames it, this fails loudly instead of
    ``KEYSTONE_MCP_PROXY_STATUS_ENVELOPE=true`` silently losing ``result.data``.
    """
    app = build_lowlevel_upstream_app(tools={"whoami"})
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
