"""CLI tolerates invalid settings it does not use."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from keystone_mcp.config import settings_for_command
from keystone_mcp.users.cli import EXIT_USAGE

_REPO = Path(__file__).resolve().parents[1]
_REDIS = "redis://localhost:6379/10"


def _run_cli(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = {**os.environ, **(env or {})}
    return subprocess.run(
        [sys.executable, "-m", "keystone_mcp.cli", *args],
        cwd=_REPO,
        env=merged,
        capture_output=True,
        text=True,
        check=False,
    )


def _users_env(db_path: Path, **extra: str) -> dict[str, str]:
    env = {
        "KEYSTONE_MCP_ENV_FILE": "",
        "KEYSTONE_MCP_DEPLOYMENT_PROFILE": "local",
        "KEYSTONE_MCP_USERS_BACKEND": "local",
        "KEYSTONE_MCP_USERS_DB_URL": f"sqlite:///{db_path}",
        "KEYSTONE_MCP_REDIS_URL": _REDIS,
        "KEYSTONE_MCP_OAUTH_DCR_ENABLED": "enabled",
        "KEYSTONE_MCP_PORT": "x",
    }
    env.update(extra)
    return env


def test_help_works_with_garbage_in_environment():
    result = _run_cli(
        "--help",
        env={
            "KEYSTONE_MCP_ENV_FILE": "",
            "KEYSTONE_MCP_TOKEN_TTL": "abc",
            "KEYSTONE_MCP_REDIS_URL": _REDIS,
        },
    )
    assert result.returncode == 0


def test_settings_for_command_restores_environment(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", _REDIS)
    monkeypatch.setenv("KEYSTONE_MCP_PORT", "x")
    before = dict(os.environ)
    settings_for_command(frozenset())
    assert os.environ == before


def test_grant_admin_ignores_unrelated_typo(tmp_path: Path):
    db_path = tmp_path / "keystone-users.db"
    result = _run_cli(
        "users",
        "grant-admin",
        "--email",
        "a@example.com",
        "--create",
        env=_users_env(db_path),
    )
    assert result.returncode == 0, result.stderr
    assert "ignoring KEYSTONE_MCP_OAUTH_DCR_ENABLED" in result.stderr
    assert "ignoring KEYSTONE_MCP_PORT" in result.stderr


def test_users_command_fails_on_its_own_variable(tmp_path: Path):
    db_path = tmp_path / "keystone-users.db"
    env = _users_env(db_path, KEYSTONE_MCP_USERS_BACKEND="Bad!")
    result = _run_cli(
        "users",
        "grant-admin",
        "--email",
        "a@example.com",
        "--create",
        env=env,
    )
    assert result.returncode == EXIT_USAGE
    assert "Traceback" not in result.stderr
    assert not any(
        "ignoring KEYSTONE_MCP_USERS_BACKEND" in line for line in result.stderr.splitlines()
    )
    assert any(
        line.startswith("keystone-mcp: KEYSTONE_MCP_USERS_BACKEND")
        for line in result.stderr.splitlines()
    )


def test_keys_list_ignores_unrelated_typo(tmp_path: Path):
    db_path = tmp_path / "users.db"
    result = _run_cli("keys", "list", env=_users_env(db_path))
    assert result.returncode in (0, 3)
    assert "ignoring KEYSTONE_MCP_OAUTH_DCR_ENABLED" in result.stderr
    assert "ignoring KEYSTONE_MCP_PORT" in result.stderr


def test_service_accounts_list_ignores_unrelated_typo(tmp_path: Path):
    db_path = tmp_path / "users.db"
    result = _run_cli("service-accounts", "list", env=_users_env(db_path))
    assert result.returncode in (0, 3)
    assert "ignoring KEYSTONE_MCP_OAUTH_DCR_ENABLED" in result.stderr
    assert "ignoring KEYSTONE_MCP_PORT" in result.stderr
