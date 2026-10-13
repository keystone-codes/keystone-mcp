"""Removed KEYSTONE_MCP_AUTH_SERVICE_* variables are refused at startup."""

from __future__ import annotations

from pathlib import Path

import pytest

from keystone_mcp.config import ConfigError, load_settings


@pytest.fixture(autouse=True)
def _clear_auth_service_env(monkeypatch):
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_URL", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_TOKEN", raising=False)


def test_auth_service_url_is_refused_at_startup(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_AUTH_SERVICE_URL", "http://backend:8000")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_AUTH_SERVICE_URL"):
        load_settings()


def test_auth_service_token_is_refused_at_startup(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_AUTH_SERVICE_TOKEN", "svc-token")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_AUTH_SERVICE_TOKEN"):
        load_settings()


def test_env_example_has_no_auth_service_block():
    repo_root = Path(__file__).resolve().parent.parent
    content = (repo_root / ".env.example").read_text(encoding="utf-8")
    assert "KEYSTONE_MCP_AUTH_SERVICE_URL" not in content
    assert "KEYSTONE_MCP_AUTH_SERVICE_TOKEN" not in content
