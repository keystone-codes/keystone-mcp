"""Tests for general settings parsing."""

from __future__ import annotations

import pytest

from keystone_mcp.config import ConfigError, Settings, load_settings, validate_settings
from support.test_env import require_redis_url


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


@pytest.mark.parametrize("value", [-1, 61])
def test_oauth_refresh_grace_seconds_rejects_out_of_range(monkeypatch, value: int):
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS", str(value))
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS"):
        validate_settings(load_settings())


@pytest.mark.parametrize("value", [0, 60])
def test_oauth_refresh_grace_seconds_accepts_bounds(monkeypatch, value: int):
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS", str(value))
    settings = load_settings()
    validate_settings(settings)
    assert settings.oauth_refresh_grace_seconds == value


def test_session_max_age_seconds_rejects_negative(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYSTONE_MCP_SESSION_MAX_AGE_SECONDS", "-1")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{tmp_path}/u.db")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_SESSION_MAX_AGE_SECONDS"):
        validate_settings(load_settings())
