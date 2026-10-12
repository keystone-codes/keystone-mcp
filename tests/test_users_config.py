"""Tests for the built-in users directory settings (KEYSTONE_MCP_USERS_*)."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from keystone_mcp.config import ConfigError, Settings, load_settings


def test_users_backend_defaults_to_local():
    settings = Settings()
    assert settings.users_backend == "local"
    assert settings.users_directory_is_local is True


def test_users_db_url_default(monkeypatch):
    # The autouse _isolated_users_db fixture sets this for every other test
    # (so a server built in a test never migrates ./keystone-users.db in the
    # repo root); undo it here to see the real default.
    monkeypatch.delenv("KEYSTONE_MCP_USERS_DB_URL", raising=False)
    assert Settings().users_db_url == "sqlite:///./keystone-users.db"


def test_superadmin_email_default_empty():
    assert Settings().superadmin_email == ""


def test_unknown_users_backend_is_refused(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "not-valid!")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_USERS_BACKEND"):
        load_settings()


def test_local_backend_does_not_require_users_service(monkeypatch, tmp_path: Path):
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "local")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "test-salt")
    monkeypatch.delenv("KEYSTONE_MCP_USERS_SERVICE_URL", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_USERS_SERVICE_TOKEN", raising=False)
    settings = load_settings()
    assert settings.users_backend == "local"


def test_http_backend_still_requires_users_service(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "http")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.delenv("KEYSTONE_MCP_USERS_SERVICE_URL", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_USERS_SERVICE_TOKEN", raising=False)
    with pytest.raises(ConfigError, match="Users directory"):
        load_settings()


def test_bad_users_db_url_is_refused(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", "postgresql+asyncpg://u:secret@h/db")
    with pytest.raises(ConfigError) as exc_info:
        load_settings()
    message = str(exc_info.value)
    assert "KEYSTONE_MCP_USERS_DB_URL" in message
    assert "secret" not in message


def test_bad_superadmin_email_is_refused(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_SUPERADMIN_EMAIL", "not-an-email")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_SUPERADMIN_EMAIL"):
        load_settings()


def test_superadmin_email_ignored_with_http_backend_warns(monkeypatch, caplog):
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "http")
    monkeypatch.setenv("KEYSTONE_MCP_SUPERADMIN_EMAIL", "admin@example.com")
    with caplog.at_level(logging.WARNING):
        settings = load_settings()
    assert settings.superadmin_email == "admin@example.com"
    assert any("KEYSTONE_MCP_SUPERADMIN_EMAIL" in record.message for record in caplog.records)


# ── Upgraded 0.3.x deployments: USERS_SERVICE_URL without an explicit backend ─
#
# A 0.3.x install only ever knew KEYSTONE_MCP_USERS_SERVICE_URL/_TOKEN. After
# upgrading to 0.4.0 without adding KEYSTONE_MCP_USERS_BACKEND, the new default
# ("local") would silently start against an empty, brand-new SQLite database:
# every user looks unknown, `enforce` denies everyone, and nothing in the log
# says why. These three tests pin the three outcomes.


def test_users_service_url_without_explicit_backend_is_refused(monkeypatch):
    monkeypatch.delenv("KEYSTONE_MCP_USERS_BACKEND", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_URL", "http://users:8000")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_TOKEN", "users-token")
    with pytest.raises(ConfigError) as exc_info:
        load_settings()
    message = str(exc_info.value)
    assert "KEYSTONE_MCP_USERS_SERVICE_URL" in message
    assert "KEYSTONE_MCP_USERS_BACKEND" in message
    # The hint names both ways out.
    assert "KEYSTONE_MCP_USERS_BACKEND=http" in message
    assert "KEYSTONE_MCP_USERS_BACKEND=local" in message
    assert "users import" in message


def test_users_service_url_with_explicit_local_backend_warns(monkeypatch, caplog):
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "local")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_URL", "http://users:8000")
    with caplog.at_level(logging.WARNING):
        settings = load_settings()
    assert settings.users_backend == "local"
    assert any(
        "KEYSTONE_MCP_USERS_SERVICE_URL" in record.message and "ignored" in record.message
        for record in caplog.records
    )


def test_users_service_url_with_explicit_http_backend_is_not_refused_by_this_check(monkeypatch):
    # The explicit-backend escape hatch: an operator who set BACKEND=http on
    # purpose (keeping the external directory) is not caught by the new check,
    # only by the pre-existing "http needs URL+TOKEN when RBAC/Google is on"
    # rule, which does not apply here (RBAC and Google login are both off).
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "http")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_URL", "http://users:8000")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_TOKEN", "users-token")
    settings = load_settings()
    assert settings.users_backend == "http"
