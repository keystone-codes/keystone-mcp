"""``keystone-mcp keys`` CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from keystone_mcp import cli
from keystone_mcp.users import service
from keystone_mcp.users.cli import EXIT_USAGE
from keystone_mcp.users.db import create_users_engine, make_session_factory, session_scope
from keystone_mcp.users.migrate import upgrade_to_head
from support.test_env import require_redis_url


@pytest.fixture(autouse=True)
def _quiet_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "configure_logging", lambda settings: None)


def _prepare_db(db_path: Path) -> None:
    engine = create_users_engine(f"sqlite:///{db_path}")
    upgrade_to_head(engine)
    factory = make_session_factory(engine)
    with session_scope(factory) as session:
        service.create_service_account(
            session,
            name="worker",
            description=None,
            roles=["member"],
            created_by="setup",
        )
    engine.dispose()


def _run_keys(argv: list[str], *, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "keystone_mcp.cli", "keys", *argv],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_cli_issue_list_revoke(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "users.db"
    _prepare_db(db_path)
    env = os.environ.copy()
    env["KEYSTONE_MCP_ENV_FILE"] = ""
    env["KEYSTONE_MCP_DEPLOYMENT_PROFILE"] = "local"
    env["KEYSTONE_MCP_USERS_BACKEND"] = "local"
    env["KEYSTONE_MCP_USERS_DB_URL"] = f"sqlite:///{db_path}"
    env.pop("KEYSTONE_MCP_REDIS_URL", None)

    issued = _run_keys(
        ["issue", "--subject", "svc:worker", "--days", "10", "--label", "ci"],
        env=env,
    )
    assert issued.returncode == 0, issued.stderr
    payload = json.loads(issued.stdout)
    key = payload["key"]
    key_id = payload["key_id"]
    assert key.startswith(f"ksk_{key_id}_")

    listed = _run_keys(["list", "--subject", "svc:worker"], env=env)
    assert listed.returncode == 0, listed.stderr
    rows = json.loads(listed.stdout)["api_keys"]
    assert any(row["key_id"] == key_id for row in rows)
    assert key not in listed.stdout

    revoked = _run_keys(["revoke", "--key-id", key_id], env=env)
    assert revoked.returncode == 0, revoked.stderr

    listed_after = _run_keys(["list", "--subject", "svc:worker", "--all"], env=env)
    row = next(r for r in json.loads(listed_after.stdout)["api_keys"] if r["key_id"] == key_id)
    assert row["revoked_at"] is not None


def test_keys_list_with_http_backend_is_one_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env = os.environ.copy()
    env["KEYSTONE_MCP_ENV_FILE"] = ""
    env["KEYSTONE_MCP_DEPLOYMENT_PROFILE"] = "local"
    env["KEYSTONE_MCP_USERS_BACKEND"] = "http"
    env["KEYSTONE_MCP_USERS_DB_URL"] = f"sqlite:///{tmp_path / 'users.db'}"
    env["KEYSTONE_MCP_REDIS_URL"] = require_redis_url()
    result = _run_keys(["list"], env=env)
    assert result.returncode == EXIT_USAGE
    assert "Traceback" not in result.stderr
    assert len([line for line in result.stderr.splitlines() if line.strip()]) == 1
