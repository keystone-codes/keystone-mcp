"""CLI for service accounts on SQLite."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

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
