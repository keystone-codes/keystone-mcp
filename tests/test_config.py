"""Tests for general settings parsing."""

from __future__ import annotations

import pytest

from keystone_mcp.config import ConfigError, Settings, load_settings


def test_login_brand_default():
    settings = Settings()
    assert settings.login_brand == "Keystone-MCP"


def test_login_brand_from_env(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_BRAND", "My Gateway")
    settings = load_settings()
    assert settings.login_brand == "My Gateway"


def test_login_brand_rejects_too_long(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_BRAND", "x" * 65)
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_LOGIN_BRAND"):
        load_settings()


def test_login_brand_rejects_newline(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_BRAND", "bad\nname")
    with pytest.raises(ConfigError, match="newline"):
        load_settings()
