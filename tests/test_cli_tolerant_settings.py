"""CLI tolerates invalid settings it does not use."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from keystone_mcp.config import settings_for_command

_REPO = Path(__file__).resolve().parents[1]


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


def test_help_works_with_garbage_in_environment():
    result = _run_cli(
        "--help",
        env={
            "KEYSTONE_MCP_ENV_FILE": "",
            "KEYSTONE_MCP_TOKEN_TTL": "abc",
            "KEYSTONE_MCP_REDIS_URL": "redis://localhost:6379/10",
        },
    )
    assert result.returncode == 0


def test_settings_for_command_restores_environment(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis://localhost:6379/10")
    monkeypatch.setenv("KEYSTONE_MCP_PORT", "x")
    before = dict(os.environ)
    settings_for_command(frozenset())
    assert os.environ == before


@pytest.mark.skip(reason="grant-admin integration covered after users DB fixture wiring")
def test_grant_admin_ignores_unrelated_typo():
    pass
