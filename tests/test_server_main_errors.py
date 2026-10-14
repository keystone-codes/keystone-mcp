"""Server main() reports startup mistakes in one line."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_REDIS = os.environ.get("KEYSTONE_MCP_REDIS_URL", "redis://localhost:6379/10")


def _run_server(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    merged = {**os.environ, "KEYSTONE_MCP_ENV_FILE": "", **env}
    return subprocess.run(
        [sys.executable, "-m", "keystone_mcp.server"],
        cwd=_REPO,
        env=merged,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )


def _local_server_env(tmp_path: Path, **extra: str) -> dict[str, str]:
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    base = {
        "KEYSTONE_MCP_REDIS_URL": _REDIS,
        "KEYSTONE_MCP_DEPLOYMENT_PROFILE": "local",
        "KEYSTONE_MCP_BASE_URL": "http://localhost:8080",
        "KEYSTONE_MCP_RBAC_MODE": "enforce",
        "KEYSTONE_MCP_RBAC_POLICY_PATH": str(policy),
        "KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT": "a" * 32,
    }
    base.update(extra)
    return base


def _startup_refused_lines(stderr: str) -> list[str]:
    found: list[str] = []
    for line in stderr.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            if "startup refused" in stripped:
                found.append(stripped)
            continue
        msg = payload.get("msg", "")
        if isinstance(msg, str) and "startup refused" in msg:
            found.append(stripped)
    return found


def test_config_error_is_one_line():
    result = _run_server(
        {
            "KEYSTONE_MCP_REDIS_URL": _REDIS,
            "KEYSTONE_MCP_PORT": "0",
            "KEYSTONE_MCP_DEPLOYMENT_PROFILE": "local",
        }
    )
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    lines = [line for line in result.stderr.splitlines() if line.strip()]
    assert len(lines) == 1
    assert lines[0].startswith("keystone-mcp: KEYSTONE_MCP_PORT")


def test_missing_redis_is_one_line():
    result = _run_server(
        {
            "KEYSTONE_MCP_REDIS_URL": "",
            "KEYSTONE_MCP_RBAC_MODE": "off",
            "KEYSTONE_MCP_DEPLOYMENT_PROFILE": "local",
        }
    )
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert any("KEYSTONE_MCP_REDIS_URL" in line for line in result.stderr.splitlines())


def test_upstream_registry_error_is_one_line(tmp_path: Path):
    upstreams = tmp_path / "upstreams.yaml"
    upstreams.write_text("schema_version: 99\nupstreams: []\n", encoding="utf-8")
    result = _run_server(_local_server_env(tmp_path, KEYSTONE_MCP_UPSTREAMS_PATH=str(upstreams)))
    assert result.returncode == 1
    assert "Traceback" not in (result.stderr + result.stdout)
    refused = _startup_refused_lines(result.stderr)
    assert len(refused) == 1


def test_policy_load_error_is_one_line(tmp_path: Path):
    policy = tmp_path / "bad-policy.yaml"
    policy.write_text("default_deny: true\nroles: {\n", encoding="utf-8")
    result = _run_server(_local_server_env(tmp_path, KEYSTONE_MCP_RBAC_POLICY_PATH=str(policy)))
    assert result.returncode == 1
    assert "Traceback" not in (result.stderr + result.stdout)
    refused = _startup_refused_lines(result.stderr)
    assert len(refused) == 1
