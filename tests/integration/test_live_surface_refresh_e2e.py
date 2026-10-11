"""Live surface refresh: dummy upstream + policy file on a real refresh timer.

Runs the reconciler loop from FastMCP lifespan with
KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS=30 (not the default 300).

Enable explicitly (slow, ~60–80s depending on reconciler jitter):
  uv run pytest tests/integration/test_live_surface_refresh_e2e.py -m live_refresh -v
"""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import pytest
import uvicorn
from asgi_lifespan import LifespanManager
from fastmcp import FastMCP

from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import bootstrap_platform, build_server
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver

REFRESH_SECONDS = 30
# First reconciler tick waits interval + jitter (up to interval / 4, capped at 15s).
_TICK_JITTER_UPPER = min(15.0, REFRESH_SECONDS / 4)
POLL_TIMEOUT_SECONDS = REFRESH_SECONDS + _TICK_JITTER_UPPER + 5


async def _wait_until(predicate, *, timeout_seconds: float, poll_seconds: float = 0.25) -> None:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < deadline:
        if predicate():
            return
        await asyncio.sleep(poll_seconds)
    assert predicate()


POLICY_V1 = """\
version: "live-refresh-1"
default_deny: true
roles:
  administrator:
    allow: ["demo_*", "users_*"]
"""

POLICY_V2 = """\
version: "live-refresh-2"
default_deny: true
roles:
  administrator:
    allow: ["demo_*", "users_*"]
"""


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _register_downstream_v1(mcp: FastMCP) -> None:
    @mcp.tool(name="demo_ping", description="ping v1")
    async def demo_ping() -> dict:
        return {"ok": True}

    @mcp.tool(name="demo_extra", description="extra v1")
    async def demo_extra() -> dict:
        return {"extra": True}


def _mutate_downstream_v2(mcp: FastMCP) -> None:
    for name in ("demo_ping", "demo_extra"):
        try:
            mcp.local_provider.remove_tool(name)
        except KeyError:
            pass

    @mcp.tool(name="demo_ping", description="ping v2 with item_id")
    async def demo_ping(item_id: str) -> dict:
        return {"item_id": item_id}

    @mcp.tool(name="demo_new", description="added on v2")
    async def demo_new() -> dict:
        return {"new": True}


@pytest.fixture
async def dummy_upstream_http():
    mcp = FastMCP("dummy-upstream")
    _register_downstream_v1(mcp)
    port = _free_port()
    config = uvicorn.Config(
        mcp.http_app(path="/mcp"),
        host="127.0.0.1",
        port=port,
        log_level="warning",
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.3)
    try:
        yield f"http://127.0.0.1:{port}/mcp", mcp
    finally:
        server.should_exit = True
        await task


@pytest.mark.live_refresh
@pytest.mark.integration
async def test_live_refresh_picks_up_upstream_and_policy_changes(
    tmp_path: Path,
    dummy_upstream_http,
):
    upstream_url, downstream_mcp = dummy_upstream_http
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(POLICY_V1, encoding="utf-8")

    user_resolver, user_backend, _revision = build_in_memory_user_directory_resolver()
    user_backend.seed("admin@example.com", roles=("administrator",))

    settings = Settings(
        base_url="http://127.0.0.1:18080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        rbac_audit_subject_salt="integration-test-salt",
        users_service_url="http://users-unused",
        users_service_token="token",
        redis_url="",
        refresh_interval_seconds=REFRESH_SECONDS,
        upstream_discovery_retries=0,
        upstream_discovery_timeout_seconds=5.0,
        upstreams_json=json.dumps(
            [
                {
                    "name": "dummy",
                    "url": upstream_url,
                    "namespace": "demo",
                    "enabled": True,
                }
            ]
        ),
    )

    mcp, registry, _oauth, upstreams, policy_manager, _obs, reconciler = build_server(
        identity_provider=StaticIdentityProvider({"integration-token"}),
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=user_resolver,
        register_builtin_catalog=True,
    )
    assert policy_manager is not None
    assert reconciler is not None

    await bootstrap_platform(upstreams, registry, settings, policy_manager)
    reconciler.seed_snapshots()

    route_ping = registry.routes["demo:demo_ping"]
    assert route_ping.upstream_tool == "demo_ping"
    assert not any(p.name == "item_id" for p in route_ping.params)
    assert "demo:demo_extra" in registry.routes
    assert policy_manager.identity is not None
    assert policy_manager.identity.version == "live-refresh-1"

    _mutate_downstream_v2(downstream_mcp)

    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):

        def _catalog_refreshed() -> bool:
            route = registry.routes.get("demo:demo_ping")
            if route is None:
                return False
            return (
                any(p.name == "item_id" for p in route.params)
                and "demo:demo_new" in registry.routes
                and "demo:demo_extra" not in registry.routes
            )

        await _wait_until(_catalog_refreshed, timeout_seconds=POLL_TIMEOUT_SECONDS)

        policy_path.write_text(POLICY_V2, encoding="utf-8")

        def _policy_refreshed() -> bool:
            return (
                policy_manager.identity is not None
                and policy_manager.identity.version == "live-refresh-2"
            )

        await _wait_until(_policy_refreshed, timeout_seconds=POLL_TIMEOUT_SECONDS)
