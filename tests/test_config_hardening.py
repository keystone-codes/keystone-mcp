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
    load_settings,
    startup_warnings,
    validate_settings,
)
from keystone_mcp.login.api_key import ApiKeyLoginProvider
from keystone_mcp.server import build_server
from support.d02_profile_cases import PROFILE_CASES, WARNING_MARKERS, ProfileCase
from support.fake_login import FakeRedirectProvider
from support.test_env import require_redis_url

_REPO = Path(__file__).resolve().parents[1]


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
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())
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
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())
    monkeypatch.setenv(name, bad)
    with pytest.raises(ConfigError) as exc_info:
        Settings()
    assert exc_info.value.variable == name


def test_refusals_are_reported_together(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())
    monkeypatch.setenv("KEYSTONE_MCP_PORT", "0")
    monkeypatch.setenv("KEYSTONE_MCP_TOKEN_TTL", "0")
    settings = Settings()
    with pytest.raises(ConfigError) as exc_info:
        validate_settings(settings)
    assert len(exc_info.value.problems) == 2
    assert any("KEYSTONE_MCP_PORT" in p for p in exc_info.value.problems)
    assert any("KEYSTONE_MCP_TOKEN_TTL" in p for p in exc_info.value.problems)


def _apply_profile_base(monkeypatch, tmp_path: Path, profile: str) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "a" * 32)
    for name in (
        "KEYSTONE_MCP_GOOGLE_CLIENT_ID",
        "KEYSTONE_MCP_GOOGLE_CLIENT_SECRET",
        "KEYSTONE_MCP_ENABLED_LOGIN_METHODS",
        "KEYSTONE_MCP_PRIMARY_LOGIN_METHOD",
        "FORWARDED_ALLOW_IPS",
    ):
        monkeypatch.delenv(name, raising=False)
    if profile == "local":
        monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
        monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "http://localhost:8080")
        monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "off")
    else:
        policy = tmp_path / "rbac-policy.yaml"
        policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
        monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
        monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "https://mcp.example.com")
        monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
        monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
        monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "local")
        monkeypatch.setenv(
            "KEYSTONE_MCP_USERS_DB_URL",
            "postgresql+psycopg://u:p@db:5432/keystone",
        )
        monkeypatch.delenv("KEYSTONE_MCP_DEV_TOKENS", raising=False)


def _warning_hits(marker_key: str, line: str) -> bool:
    needle = WARNING_MARKERS[marker_key]
    if marker_key == "W19":
        return needle in line
    return needle in line


def _assert_warnings(
    lines: list[str],
    expected: frozenset[str],
    forbidden: frozenset[str],
) -> None:
    for key in expected:
        assert any(_warning_hits(key, line) for line in lines), f"missing {key}: {lines}"
    for key in forbidden:
        assert not any(_warning_hits(key, line) for line in lines), f"unexpected {key}: {lines}"


@pytest.mark.parametrize("case", PROFILE_CASES, ids=lambda c: c.id)
def test_profile_cases(case: ProfileCase, monkeypatch, tmp_path: Path) -> None:
    _apply_profile_base(monkeypatch, tmp_path, case.profile)
    for name in case.unset:
        monkeypatch.delenv(name, raising=False)
    for name, value in case.env.items():
        monkeypatch.setenv(name, value)

    if case.use_build_server:
        settings = load_settings()
        providers = [FakeRedirectProvider("oidc"), ApiKeyLoginProvider()]
        if case.expect == "build_server_error":
            with pytest.raises(ConfigError, match="interactive provider"):
                build_server(settings=settings, login_providers=providers)
        else:
            build_server(settings=settings, login_providers=providers)
        return

    if case.expect == "config_error":
        with pytest.raises(ConfigError):
            load_settings()
        return

    settings = load_settings()
    if case.check_audit_enabled is not None:
        assert settings.rbac_audit_enabled is case.check_audit_enabled
    if case.check_log_redact is not None:
        assert settings.log_redact is case.check_log_redact
    if case.check_oauth_dcr is not None:
        assert settings.oauth_dcr_enabled is case.check_oauth_dcr

    env_map = os.environ.copy()
    lines = startup_warnings(settings, environ=env_map)
    _assert_warnings(lines, case.warnings, case.forbid_warnings)


def test_warnings_do_not_leak_secrets(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis://:secret-pass@redis.example.com:6379/0")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "short")
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "https://mcp.example.com")
    settings = Settings()
    for line in startup_warnings(settings):
        assert "secret-pass" not in line
        assert "short" not in line or "shorter than 16 bytes" in line
