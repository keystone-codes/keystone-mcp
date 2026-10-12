"""Tests for upstream config parsing and server wiring."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings, load_settings
from keystone_mcp.server import build_server


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


def test_build_server_mounts_stdio_upstream(monkeypatch):
    server_script = str(Path(__file__).resolve().parent / "support" / "stdio_upstream.py")
    payload = [
        {
            "name": "notes",
            "namespace": "notes",
            "transport": "stdio",
            "command": sys.executable,
            "args": [server_script],
        }
    ]
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS", json.dumps(payload))
    _mcp, _registry, _oauth, upstreams, *_rest = build_server(
        settings=Settings(),
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    assert "notes" in upstreams._sub_servers
    assert upstreams._connections["notes"].transport == "stdio"


def test_dev_tokens_come_from_settings(monkeypatch):
    """KEYSTONE_MCP_DEV_TOKENS is a Settings field, not a raw os.environ read."""
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "tok-a,tok-b,,tok-c")
    settings = load_settings()
    assert settings.dev_tokens == "tok-a,tok-b,,tok-c"


def test_dev_tokens_honour_injected_settings_over_the_environment(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "from-env")
    settings = Settings(dev_tokens="from-settings")
    assert settings.dev_tokens == "from-settings"
