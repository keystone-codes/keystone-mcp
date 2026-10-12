"""Tests for auth-service identity provider and upstream config parsing."""

from __future__ import annotations

import json
import sys
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from keystone_mcp.auth.identity_provider import AuthServiceIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import ConfigError, Settings, load_settings
from keystone_mcp.server import build_identity_provider, build_server


@pytest.mark.asyncio
async def test_auth_service_provider_accepts_matching_email():
    provider = AuthServiceIdentityProvider("http://backend:8000", "svc-token")
    response = httpx.Response(
        200,
        json={"valid": True, "email": "user@example.com", "status": "issued"},
        request=httpx.Request("POST", "http://backend:8000/api/internal/apikey/introspect"),
    )

    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=response)):
        assert await provider.verify("secret-token", "user@example.com") is True


@pytest.mark.asyncio
async def test_auth_service_provider_rejects_email_mismatch():
    provider = AuthServiceIdentityProvider("http://backend:8000", "svc-token")
    response = httpx.Response(
        200,
        json={"valid": True, "email": "owner@example.com", "status": "issued"},
        request=httpx.Request("POST", "http://backend:8000/api/internal/apikey/introspect"),
    )

    with patch("httpx.AsyncClient.post", new=AsyncMock(return_value=response)):
        assert await provider.verify("secret-token", "other@example.com") is False


def test_settings_upstreams_from_json(monkeypatch):
    payload = [
        {
            "name": "reports-mcp",
            "url": "http://reports-mcp:8081/mcp",
            "namespace": "reports",
            "enabled": True,
        }
    ]
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS", json.dumps(payload))
    settings = load_settings()
    assert len(settings.upstreams) == 1
    assert settings.upstreams[0].namespace == "reports"


def test_no_upstreams_declared_means_no_upstreams(monkeypatch):
    """With no registry file and no JSON env, no upstreams are configured."""
    monkeypatch.delenv("KEYSTONE_MCP_UPSTREAMS", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_UPSTREAMS_PATH", raising=False)
    assert load_settings().upstreams == ()


def test_build_identity_provider_uses_auth_service_when_configured(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_AUTH_SERVICE_URL", "http://backend:8000")
    monkeypatch.setenv("KEYSTONE_MCP_AUTH_SERVICE_TOKEN", "svc-token")
    settings = Settings()
    provider = build_identity_provider(settings)
    assert isinstance(provider, AuthServiceIdentityProvider)


def test_settings_upstream_tool_timeout_from_env(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUT_SECONDS", "240")
    settings = load_settings()
    assert settings.upstream_tool_timeout_seconds == 240


def test_settings_throttle_from_env(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_THROTTLE_MAX", "100")
    monkeypatch.setenv("KEYSTONE_MCP_THROTTLE_WINDOW", "60")
    settings = load_settings()
    assert settings.throttle_max_requests == 100
    assert settings.throttle_window_seconds == 60


def test_build_server_wires_upstream_tool_timeout(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUT_SECONDS", "120")
    _mcp, _registry, _oauth, upstreams, _policy_manager, _observability, _reconciler = build_server(
        settings=load_settings(),
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    assert upstreams.tool_timeout_seconds == 120


def test_build_server_registers_json_upstreams(monkeypatch):
    payload = [
        {
            "name": "reports-mcp",
            "url": "http://reports-mcp:8081/mcp",
            "namespace": "reports",
            "enabled": True,
        }
    ]
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS", json.dumps(payload))
    _mcp, _registry, _oauth, upstreams, _policy_manager, _observability, _reconciler = build_server(
        settings=Settings(),
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    assert "reports" in upstreams._sub_servers


def test_build_server_refuses_stdio_upstream(monkeypatch):
    """The registry and the process supervisor (Y08) already accept

    ``transport: stdio`` entries, but nothing wires a supervised process to
    the proxy yet (that is the next card). ``build_server`` must refuse
    clearly instead of mounting it as a dead HTTP sub-server with
    ``url=""``.
    """
    payload = [
        {
            "name": "notes",
            "namespace": "notes",
            "transport": "stdio",
            "command": sys.executable,
        }
    ]
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS", json.dumps(payload))
    with pytest.raises(ConfigError, match="not wired to the proxy"):
        build_server(
            settings=Settings(),
            register_builtin_catalog=False,
            oauth_store=InMemoryOAuthStore(),
        )


def test_dev_tokens_come_from_settings(monkeypatch):
    """KEYSTONE_MCP_DEV_TOKENS is a Settings field, not a raw os.environ read."""
    from keystone_mcp.auth.identity_provider import StaticIdentityProvider

    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_URL", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "tok-a,tok-b,,tok-c")
    settings = load_settings()
    assert settings.dev_tokens == "tok-a,tok-b,,tok-c"

    provider = build_identity_provider(settings)
    assert isinstance(provider, StaticIdentityProvider)
    assert provider._valid_tokens == {"tok-a", "tok-b", "tok-c"}


def test_dev_tokens_honour_injected_settings_over_the_environment(monkeypatch):
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_URL", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "from-env")
    provider = build_identity_provider(Settings(dev_tokens="from-settings"))
    assert provider._valid_tokens == {"from-settings"}
