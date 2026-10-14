"""Config validation hardening (strict booleans, refusals, startup warnings)."""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from keystone_mcp.config import (
    BOOL_VARIABLES,
    ConfigError,
    Settings,
    _env_bool,
    startup_warnings,
    validate_settings,
)

_REPO = Path(__file__).resolve().parents[1]
_REDIS = "redis://localhost:6379/10"


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("1", True),
        ("true", True),
        ("yes", True),
        ("on", True),
        ("TRUE", True),
        (" On ", True),
        ("0", False),
        ("false", False),
        ("no", False),
        ("off", False),
        ("OFF ", False),
    ],
)
def test_env_bool_accepts(monkeypatch, raw: str, expected: bool):
    monkeypatch.setenv("KEYSTONE_MCP_LOG_REDACT", raw)
    assert _env_bool("KEYSTONE_MCP_LOG_REDACT", True) is expected


@pytest.mark.parametrize("raw", ["enabled", "2", "y"])
def test_env_bool_refuses_unknown(monkeypatch, raw: str):
    monkeypatch.setenv("KEYSTONE_MCP_LOG_REDACT", raw)
    with pytest.raises(ConfigError) as exc_info:
        _env_bool("KEYSTONE_MCP_LOG_REDACT", True)
    assert exc_info.value.variable == "KEYSTONE_MCP_LOG_REDACT"


@pytest.mark.parametrize("raw", ["", "  "])
def test_env_bool_empty_is_false_and_warned(monkeypatch, raw: str):
    monkeypatch.setenv("KEYSTONE_MCP_LOG_REDACT", raw)
    assert _env_bool("KEYSTONE_MCP_LOG_REDACT", True) is False
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", _REDIS)
    settings = Settings()
    warnings = startup_warnings(settings, environ=os.environ.copy())
    assert any("KEYSTONE_MCP_LOG_REDACT" in w and "empty value" in w for w in warnings)


def test_bool_variables_tuple_matches_source():
    names: set[str] = set()
    for rel in ("src/keystone_mcp/config.py", "src/keystone_mcp/cli.py"):
        tree = ast.parse((_REPO / rel).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id == "_env_bool":
                if node.args and isinstance(node.args[0], ast.Constant):
                    names.add(str(node.args[0].value))
    assert names == set(BOOL_VARIABLES)


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("KEYSTONE_MCP_PORT", "x"),
        ("KEYSTONE_MCP_TOKEN_TTL", "abc"),
        ("KEYSTONE_MCP_LOG_REDACT", "maybe"),
        ("KEYSTONE_MCP_RBAC_MODE", "broken"),
        ("KEYSTONE_MCP_LOG_LEVEL", "verbose"),
        ("KEYSTONE_MCP_USERS_BACKEND", "Bad!"),
    ],
)
def test_every_settings_parse_error_names_its_variable(monkeypatch, name: str, bad: str):
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", _REDIS)
    monkeypatch.setenv(name, bad)
    with pytest.raises(ConfigError) as exc_info:
        Settings()
    assert exc_info.value.variable == name


def test_refusals_are_reported_together(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", _REDIS)
    monkeypatch.setenv("KEYSTONE_MCP_PORT", "0")
    monkeypatch.setenv("KEYSTONE_MCP_TOKEN_TTL", "0")
    settings = Settings()
    with pytest.raises(ConfigError) as exc_info:
        validate_settings(settings)
    assert len(exc_info.value.problems) == 2
    assert any("KEYSTONE_MCP_PORT" in p for p in exc_info.value.problems)
    assert any("KEYSTONE_MCP_TOKEN_TTL" in p for p in exc_info.value.problems)


def test_warnings_do_not_leak_secrets(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis://:secret-pass@redis.example.com:6379/0")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "short")
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "https://mcp.example.com")
    settings = Settings()
    for line in startup_warnings(settings):
        assert "secret-pass" not in line
        assert "short" not in line or "shorter than 16 bytes" in line
