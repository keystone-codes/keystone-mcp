"""CLI for service accounts on SQLite."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from keystone_mcp.users.cli import EXIT_STORE
from support.test_env import require_redis_url


def test_cli_add_list_update_block(tmp_path: Path, monkeypatch):
    db = tmp_path / "users.db"
    env = {
        **dict(__import__("os").environ),
        "KEYSTONE_MCP_USERS_BACKEND": "local",
        "KEYSTONE_MCP_USERS_DB_URL": f"sqlite:///{db}",
        "KEYSTONE_MCP_RBAC_MODE": "off",
        "KEYSTONE_MCP_REDIS_URL": require_redis_url(),
    }

    def run(*args: str) -> dict:
        proc = subprocess.run(
            [sys.executable, "-m", "keystone_mcp.cli", "service-accounts", *args],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            cwd=str(Path(__file__).resolve().parents[1]),
        )
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout)

    created = run("add", "--name", "ci", "--role", "member", "--description", "bot")
    assert created["name"] == "ci"
    listing = run("list")
    assert listing["total"] == 1
    blocked = run("update", "--name", "ci", "--block")
    assert blocked["is_blocked"] is True


def test_service_accounts_add_unknown_role_is_one_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "users.db"
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        'version: "1.0.0"\ndefault_deny: true\nroles:\n  member:\n    description: m\n    allow:\n      - some_tool\n',
        encoding="utf-8",
    )
    env = {
        **dict(__import__("os").environ),
        "KEYSTONE_MCP_ENV_FILE": "",
        "KEYSTONE_MCP_DEPLOYMENT_PROFILE": "local",
        "KEYSTONE_MCP_USERS_BACKEND": "local",
        "KEYSTONE_MCP_USERS_DB_URL": f"sqlite:///{db}",
        "KEYSTONE_MCP_RBAC_MODE": "enforce",
        "KEYSTONE_MCP_RBAC_POLICY_PATH": str(policy),
        "KEYSTONE_MCP_REDIS_URL": require_redis_url(),
    }
    opened: list[object] = []

    def _track_store(settings):
        from keystone_mcp.users.factory import build_users_store

        real = build_users_store(settings)
        opened.append(real)
        return real

    monkeypatch.setattr("keystone_mcp.users.cli.build_users_store", _track_store)
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "keystone_mcp.cli",
            "service-accounts",
            "add",
            "--name",
            "ci",
            "--role",
            "nope",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    assert proc.returncode == EXIT_STORE
    assert "Traceback" not in proc.stderr
    assert len([line for line in proc.stderr.splitlines() if line.strip()]) == 1
    assert not opened


def test_service_accounts_update_unknown_role_is_one_line(tmp_path: Path) -> None:
    db = tmp_path / "users.db"
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        'version: "1.0.0"\ndefault_deny: true\nroles:\n  member:\n    description: m\n    allow:\n      - some_tool\n',
        encoding="utf-8",
    )
    env = {
        **dict(__import__("os").environ),
        "KEYSTONE_MCP_ENV_FILE": "",
        "KEYSTONE_MCP_DEPLOYMENT_PROFILE": "local",
        "KEYSTONE_MCP_USERS_BACKEND": "local",
        "KEYSTONE_MCP_USERS_DB_URL": f"sqlite:///{db}",
        "KEYSTONE_MCP_RBAC_MODE": "enforce",
        "KEYSTONE_MCP_RBAC_POLICY_PATH": str(policy),
        "KEYSTONE_MCP_REDIS_URL": require_redis_url(),
    }
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "keystone_mcp.cli",
            "service-accounts",
            "update",
            "--name",
            "ci",
            "--role",
            "nope",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    assert proc.returncode == EXIT_STORE
    assert "Traceback" not in proc.stderr
    assert len([line for line in proc.stderr.splitlines() if line.strip()]) == 1
