"""Startup validation for the deprecated auth-service identity provider.

``KEYSTONE_MCP_AUTH_SERVICE_URL`` and ``KEYSTONE_MCP_AUTH_SERVICE_TOKEN`` must be
set together: a URL without a token would otherwise select the external
introspection backend while it always reports every key as invalid (see
``AuthServiceIdentityProvider.verify``), silently locking everyone out instead
of failing fast at startup.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from keystone_mcp.auth.identity_provider import AuthServiceIdentityProvider, StaticIdentityProvider
from keystone_mcp.config import ConfigError, Settings, load_settings
from keystone_mcp.server import build_identity_provider


@pytest.fixture(autouse=True)
def _clear_auth_service_env(monkeypatch):
    """Keep these tests independent of whatever the developer's shell has set."""
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_URL", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_TOKEN", raising=False)


def test_auth_service_url_without_token_is_refused(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_AUTH_SERVICE_URL", "http://backend:8000")

    with pytest.raises(ConfigError, match="KEYSTONE_MCP_AUTH_SERVICE_TOKEN is empty"):
        load_settings()


def test_auth_service_token_without_url_is_ignored(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_AUTH_SERVICE_TOKEN", "svc-token")

    settings = load_settings()

    provider = build_identity_provider(settings)
    assert isinstance(provider, StaticIdentityProvider)


def test_build_identity_provider_refuses_url_without_token():
    settings = Settings(auth_service_url="http://x", auth_service_token="")

    with pytest.raises(ConfigError, match="KEYSTONE_MCP_AUTH_SERVICE_TOKEN is empty"):
        build_identity_provider(settings)


def test_auth_service_logs_deprecation(monkeypatch, caplog):
    monkeypatch.setenv("KEYSTONE_MCP_AUTH_SERVICE_URL", "http://backend:8000")
    monkeypatch.setenv("KEYSTONE_MCP_AUTH_SERVICE_TOKEN", "svc-token")
    settings = load_settings()

    with caplog.at_level(logging.WARNING, logger="keystone_mcp.server"):
        provider = build_identity_provider(settings)

    assert isinstance(provider, AuthServiceIdentityProvider)
    assert "deprecated" in caplog.text


def test_env_example_leaves_auth_service_url_empty():
    repo_root = Path(__file__).resolve().parent.parent
    content = (repo_root / ".env.example").read_text(encoding="utf-8")
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            stripped = stripped.lstrip("#").strip()
        if stripped.startswith("KEYSTONE_MCP_AUTH_SERVICE_URL="):
            value = stripped.split("=", 1)[1].strip()
            assert value == "", f"found a non-empty AUTH_SERVICE_URL example: {line!r}"
