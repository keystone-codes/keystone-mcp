"""Server main() reports startup mistakes in one line."""

from __future__ import annotations

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
        timeout=15,
    )


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
