"""Y05: ``notifications/tools/list_changed`` to open sessions and listen streams.

Covers both protocol eras: handshake-era clients (``mode="legacy"``), which get
the notification pushed onto their standing connection, and 2026-07-28-era
clients, which only see it on a ``subscriptions/listen`` stream they opened
themselves. ``keystone_mcp.surface.client_sessions.ClientSessionRegistry`` is
the component that tracks connections/streams and sends the notification;
``SurfaceReconciler._tick_locked`` is what decides *when* to call it (a
catalog change, a policy reload, or a users-directory revision change).
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import httpx2
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.utilities.tests import asgi_server
from mcp.client.subscriptions import listen as listen_subscriptions

from conftest import BASE_URL, VALID_TOKEN, obtain_access_token
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from keystone_mcp.surface.client_sessions import ClientSessionRegistry
from keystone_mcp.user_directory.revision import InMemoryRevisionReader
from support.login import dev_token_login
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)

ENFORCE_POLICY = """\
version: "1.0.0"
default_deny: true
roles:
  administrator:
    allow: ["*"]
"""


def _settings(**overrides) -> Settings:
    overrides.setdefault("refresh_interval_seconds", 3600)
    return Settings(base_url=BASE_URL, **overrides)


async def _build_with_upstream(settings: Settings, app):
    """Build the server, mount ``app`` (P01) as the ``hello`` upstream, discover it once."""
    mcp, registry, oauth, upstreams, policy_manager, observability, reconciler = build_server(
        login_providers=[dev_token_login({VALID_TOKEN})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    upstreams.http_client_factory = asgi_http_client_factory(app)
    upstreams.add_upstream("hello", UPSTREAM_MCP_URL, namespace="hello")
    await upstreams.discover_all()
    assert reconciler is not None
    reconciler.seed_snapshots()
    return mcp, registry, oauth, upstreams, policy_manager, observability, reconciler


@asynccontextmanager
async def _fetch_from(app, upstreams):
    """Point the reconciler's next HTTP discovery at a different in-process app."""
    from keystone_mcp.router.upstream_connection import HttpUpstreamConnection

    factory_builder = asgi_http_client_factory(app)
    previous_registry_factory = upstreams.http_client_factory
    previous_conn_factories: dict[str, object] = {}
    upstreams.http_client_factory = factory_builder
    for namespace, conn in upstreams._connections.items():
        if isinstance(conn, HttpUpstreamConnection):
            previous_conn_factories[namespace] = conn._http_client_factory
            conn._http_client_factory = factory_builder
    try:
        yield
    finally:
        upstreams.http_client_factory = previous_registry_factory
        for namespace, previous in previous_conn_factories.items():
            conn = upstreams._connections[namespace]
            if isinstance(conn, HttpUpstreamConnection):
                conn._http_client_factory = previous  # type: ignore[assignment]


def _legacy_client(mcp, received: list) -> Client:
    async def handler(message):
        received.append(message)

    return Client(mcp, mode="legacy", message_handler=handler)


@asynccontextmanager
async def _modern_client(mcp, settings: Settings):
    async with asgi_server(mcp, path=settings.http_path) as running:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=running.app), base_url=BASE_URL
        ) as oauth_client:
            token_res = await obtain_access_token(oauth_client, settings.resource_url)
            token = token_res["body"]["access_token"]

        async with running.client(auth=token) as client:
            yield client


# ── test-only stand-ins for a handshake-era `Connection` ────────────────────


class _FakeExitStack:
    """Stands in for ``Connection.exit_stack``; ``add`` registers a real callback onto it."""

    def callback(self, fn, *args, **kwargs) -> None:  # noqa: ANN001
        pass


class _FakeConnection:
    """A minimal stand-in exposing just what ``ClientSessionRegistry`` reads."""

    def __init__(
        self,
        *,
        protocol_version: str = "2025-11-25",
        has_standalone_channel: bool = True,
        on_send=None,  # noqa: ANN001
        sleep_seconds: float = 0.0,
        raises: BaseException | None = None,
    ) -> None:
        self.protocol_version = protocol_version
        self.has_standalone_channel = has_standalone_channel
        self.exit_stack = _FakeExitStack()
        self._on_send = on_send
        self._sleep_seconds = sleep_seconds
        self._raises = raises

    async def send_tool_list_changed(self) -> None:
        if self._raises is not None:
            raise self._raises
        if self._sleep_seconds:
            await anyio.sleep(self._sleep_seconds)
        if self._on_send is not None:
            self._on_send()


class _FakeSession:
    def __init__(self, connection: _FakeConnection) -> None:
        self._connection = connection


# ── 1. a catalog change sends the notification, on both eras ───────────────


async def test_new_upstream_tool_sends_list_changed_legacy_era():
    app = build_lowlevel_upstream_app(tools=["greet"])
    async with LifespanManager(app):
        settings = _settings()
        (
            mcp,
            _registry,
            _oauth,
            _upstreams,
            _policy_manager,
            _observability,
            reconciler,
        ) = await _build_with_upstream(settings, app)

        received: list = []
        async with _legacy_client(mcp, received) as client:
            tools = await client.list_tools()
            assert {t.name for t in tools} == {"hello_greet"}

            app2 = build_lowlevel_upstream_app(tools=["greet", "search"])
            async with LifespanManager(app2), _fetch_from(app2, _upstreams):
                await reconciler.tick()
            await asyncio.sleep(0)  # let the in-memory handler run

            assert len(received) == 1
            assert received[0].method == "notifications/tools/list_changed"

            tools_after = await client.list_tools()
            assert {t.name for t in tools_after} == {"hello_greet", "hello_search"}


async def test_new_upstream_tool_sends_list_changed_modern_era():
    app = build_lowlevel_upstream_app(tools=["greet"])
    async with LifespanManager(app):
        settings = _settings()
        (
            mcp,
            _registry,
            _oauth,
            _upstreams,
            _policy_manager,
            _observability,
            reconciler,
        ) = await _build_with_upstream(settings, app)

        async with _modern_client(mcp, settings) as client:
            tools = await client.list_tools()
            assert {t.name for t in tools} == {"hello_greet"}

            async with listen_subscriptions(client.session, tools_list_changed=True) as sub:
                app2 = build_lowlevel_upstream_app(tools=["greet", "search"])
                async with LifespanManager(app2), _fetch_from(app2, _upstreams):
                    await reconciler.tick()

                event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)
                assert type(event).__name__ == "ToolsListChanged"

            tools_after = await client.list_tools()
            assert {t.name for t in tools_after} == {"hello_greet", "hello_search"}


# ── 2. an unchanged tick sends nothing, on both eras ────────────────────────


async def test_unchanged_tick_sends_nothing_legacy_era():
    app = build_lowlevel_upstream_app(tools=["greet"])
    async with LifespanManager(app):
        settings = _settings()
        (
            mcp,
            _registry,
            _oauth,
            _upstreams,
            _policy_manager,
            _observability,
            reconciler,
        ) = await _build_with_upstream(settings, app)

        received: list = []
        async with _legacy_client(mcp, received) as client:
            await client.list_tools()
            await reconciler.tick()
            await asyncio.sleep(0)
            assert received == []


async def test_unchanged_tick_sends_nothing_modern_era():
    app = build_lowlevel_upstream_app(tools=["greet"])
    async with LifespanManager(app):
        settings = _settings()
        (
            mcp,
            _registry,
            _oauth,
            _upstreams,
            _policy_manager,
            _observability,
            reconciler,
        ) = await _build_with_upstream(settings, app)

        async with _modern_client(mcp, settings) as client:
            await client.list_tools()
            async with listen_subscriptions(client.session, tools_list_changed=True) as sub:
                await reconciler.tick()
                with pytest.raises(TimeoutError):
                    await asyncio.wait_for(sub.__anext__(), timeout=0.2)


# ── 3. a policy reload sends the notification ───────────────────────────────


async def test_policy_reload_sends_list_changed(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(ENFORCE_POLICY, encoding="utf-8")

    settings = _settings(rbac_mode="enforce", rbac_policy_path=str(policy_path))
    mcp, registry, _oauth, _upstreams, policy_manager, _observability, reconciler = build_server(
        login_providers=[dev_token_login({VALID_TOKEN})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    assert policy_manager is not None
    assert reconciler is not None
    from keystone_mcp.adapters.stub import StubAdapter

    registry.add_route("ping", StubAdapter(), mode="live")
    policy_manager.load_initial(registry)
    reconciler.seed_snapshots()

    received: list = []
    async with _legacy_client(mcp, received) as client:
        await client.list_tools()

        policy_path.write_text(ENFORCE_POLICY.replace("1.0.0", "1.0.1"), encoding="utf-8")
        await reconciler.tick()
        await asyncio.sleep(0)

        assert len(received) == 1
        assert received[0].method == "notifications/tools/list_changed"


# ── 4. a users-directory revision change sends the notification ────────────


async def test_users_revision_change_sends_list_changed():
    settings = _settings()
    mcp, _registry, _oauth, _upstreams, _policy_manager, _observability, reconciler = build_server(
        login_providers=[dev_token_login({VALID_TOKEN})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    assert reconciler is not None
    revision_reader = InMemoryRevisionReader()
    reconciler.revision_reader = revision_reader
    reconciler.seed_snapshots()

    received: list = []
    async with _legacy_client(mcp, received) as client:
        await client.list_tools()

        # First observation only establishes the baseline (no prior revision
        # to compare against) and must not notify by itself.
        await reconciler.tick()
        await asyncio.sleep(0)
        assert received == []

        revision_reader.bump()
        await reconciler.tick()
        await asyncio.sleep(0)

        assert len(received) == 1
        assert received[0].method == "notifications/tools/list_changed"


# ── 5. a dead or raising connection is dropped, not fatal to the broadcast ──


async def test_closed_connection_is_dropped():
    settings = _settings()
    mcp, _registry, _oauth, _upstreams, _policy_manager, _observability, reconciler = build_server(
        login_providers=[dev_token_login({VALID_TOKEN})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    assert reconciler is not None
    registry = reconciler.client_sessions
    assert registry is not None

    async with Client(mcp, mode="legacy") as client:
        await client.list_tools()
        assert len(registry) == 1
    # The connection closed when the client disconnected: the exit_stack
    # callback registered by ClientSessionRegistry.add removed it.
    assert len(registry) == 0

    # A connection that raises while being notified (``Connection.notify`` is
    # documented as never raising, but this is the defensive boundary) must
    # not break the broadcast and must be dropped.
    bad = _FakeConnection(raises=anyio.ClosedResourceError())
    registry.add(_FakeSession(bad))
    assert len(registry) == 1

    reached = await registry.broadcast_list_changed({"tools"})

    assert reached == 0
    assert len(registry) == 0


async def test_slow_session_does_not_block_others():
    registry = ClientSessionRegistry()
    calls: list[str] = []
    slow = _FakeConnection(sleep_seconds=5.0)
    fast = _FakeConnection(on_send=lambda: calls.append("fast"))
    registry.add(_FakeSession(slow))
    registry.add(_FakeSession(fast))

    started = time.monotonic()
    reached = await registry.broadcast_list_changed({"tools"})
    elapsed = time.monotonic() - started

    assert elapsed < 2.0, f"broadcast took {elapsed:.2f}s; the slow connection blocked it"
    assert calls == ["fast"]
    assert reached == 1
    assert len(registry) == 1  # only the slow one was dropped


# ── 6. tracking is independent of RBAC/throttle decisions ──────────────────


async def test_session_is_tracked_even_when_rbac_denies(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(ENFORCE_POLICY, encoding="utf-8")

    settings = _settings(rbac_mode="enforce", rbac_policy_path=str(policy_path))
    mcp, registry, _oauth, _upstreams, policy_manager, _observability, reconciler = build_server(
        login_providers=[dev_token_login({VALID_TOKEN})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    assert policy_manager is not None
    assert reconciler is not None
    from keystone_mcp.adapters.stub import StubAdapter

    registry.add_route("ping", StubAdapter(), mode="live")
    policy_manager.load_initial(registry)

    async with Client(mcp, mode="legacy") as client:
        # No OAuth token behind the in-memory transport: no identity is
        # resolved, so RbacMiddleware.on_list_tools denies and returns an
        # empty list -- but the connection must still be remembered.
        tools = await client.list_tools()
        assert tools == []
        assert len(reconciler.client_sessions) == 1


async def test_modern_requests_are_not_tracked():
    app = build_lowlevel_upstream_app(tools=["greet"])
    async with LifespanManager(app):
        settings = _settings()
        (
            mcp,
            _registry,
            _oauth,
            _upstreams,
            _policy_manager,
            _observability,
            reconciler,
        ) = await _build_with_upstream(settings, app)

        async with _modern_client(mcp, settings) as client:
            await client.list_tools()
            assert client.session.protocol_version in (
                "2026-07-28",
            )  # sanity: this really is the modern era
            assert len(reconciler.client_sessions) == 0


# ── 7. the SDK advertises listChanged on both eras once wired ──────────────


async def test_list_changed_is_advertised_on_both_eras():
    settings = _settings()
    mcp, _registry, _oauth, _upstreams, _policy_manager, _observability, _reconciler = build_server(
        login_providers=[dev_token_login({VALID_TOKEN})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )

    async with Client(mcp, mode="legacy") as legacy_client:
        await legacy_client.list_tools()
        assert legacy_client.server_capabilities.tools.list_changed is True

    async with _modern_client(mcp, settings) as modern_client:
        await modern_client.list_tools()
        assert modern_client.server_capabilities.tools.list_changed is True


# ── 8. guard: ClientSessionRegistry.add really does reach a live connection ─
# via the private ``session._connection`` field -- a future mcp upgrade that
# renames or removes it must fail this test loudly rather than silently
# stopping delivery.


async def test_registry_reaches_connection_via_private_field():
    settings = _settings()
    mcp, _registry, _oauth, _upstreams, _policy_manager, _observability, reconciler = build_server(
        login_providers=[dev_token_login({VALID_TOKEN})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    assert reconciler is not None

    async with Client(mcp, mode="legacy") as client:
        await client.list_tools()
        assert len(reconciler.client_sessions) == 1
