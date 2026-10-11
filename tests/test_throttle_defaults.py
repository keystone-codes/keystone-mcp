"""The tool-call throttle defaults to 120 calls per 60-second window.

The login throttle (`KEYSTONE_MCP_LOGIN_THROTTLE_*`) is a separate budget that
guards `/login` and `/register` against credential stuffing; its defaults are
pinned here too so a future change to one does not silently drag the other
along.
"""

from __future__ import annotations

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.throttle_middleware import THROTTLE_MESSAGE
from keystone_mcp.server import build_server

SUBJECT = "user@example.com"
DEFAULT_THROTTLE_MAX = 120
DEFAULT_THROTTLE_WINDOW = 60


@pytest.fixture
def patch_verified_identity(monkeypatch):
    """Every request carries the same verified identity, as OAuth would supply."""
    identity = VerifiedIdentity(email=SUBJECT)
    for module in (
        "keystone_mcp.identity",
        "keystone_mcp.router.rbac_middleware",
        "keystone_mcp.router.throttle_middleware",
    ):
        monkeypatch.setattr(f"{module}.resolve_verified_identity", lambda: identity)


def _build_app(settings: Settings, **kwargs) -> FastMCP:
    """Assemble the real server, publish one stub tool, and load any RBAC policy."""
    from keystone_mcp.adapters.stub import StubAdapter

    mcp, registry, _oauth, _upstreams, policy_manager, _obs, _reconciler = build_server(
        identity_provider=StaticIdentityProvider({"token"}),
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
        **kwargs,
    )
    registry.add_route("ping", StubAdapter(), mode="live")
    if policy_manager is not None:
        policy_manager.load_initial(registry)
    return mcp


async def _count_calls_until_throttled(mcp: FastMCP, attempts: int) -> int:
    """Return how many calls succeeded before the first throttle refusal."""
    succeeded = 0
    async with Client(mcp) as client:
        for _ in range(attempts):
            try:
                await client.call_tool("ping", {})
            except ToolError as exc:
                assert THROTTLE_MESSAGE in str(exc), exc
                return succeeded
            succeeded += 1
    return succeeded


def test_tool_throttle_default_is_120_per_60s(monkeypatch):
    monkeypatch.delenv("KEYSTONE_MCP_THROTTLE_MAX", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_THROTTLE_WINDOW", raising=False)
    settings = Settings()
    assert settings.throttle_max_requests == DEFAULT_THROTTLE_MAX
    assert settings.throttle_window_seconds == DEFAULT_THROTTLE_WINDOW


def test_login_throttle_defaults_unchanged(monkeypatch):
    monkeypatch.delenv("KEYSTONE_MCP_LOGIN_THROTTLE_IP_MAX", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_LOGIN_THROTTLE_EMAIL_MAX", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_LOGIN_THROTTLE_WINDOW", raising=False)
    settings = Settings()
    assert settings.login_throttle_ip_max == 30
    assert settings.login_throttle_email_max == 10
    assert settings.login_throttle_window_seconds == 300


@pytest.mark.asyncio
async def test_default_settings_allow_120_calls_then_throttle(patch_verified_identity):
    settings = Settings(base_url="http://localhost:8080", refresh_interval_seconds=0)
    assert settings.throttle_max_requests == DEFAULT_THROTTLE_MAX
    mcp = _build_app(settings)
    assert await _count_calls_until_throttled(mcp, DEFAULT_THROTTLE_MAX * 2) == DEFAULT_THROTTLE_MAX
