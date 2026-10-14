"""Tests for the `keystone-mcp serve` subcommand.

The subcommand is a thin CLI entry point for the PyPI package : it must
call `keystone_mcp.server.main()` and nothing else, so `python -m
keystone_mcp.server` and `keystone-mcp serve` behave identically.
"""

from __future__ import annotations

import pytest

from keystone_mcp.cli import main
from keystone_mcp.env_file import load_env_file


def test_serve_calls_server_main(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []

    def fake_server_main(*, env_file_result=None) -> None:
        calls.append(env_file_result)

    monkeypatch.setattr("keystone_mcp.server.main", fake_server_main)

    exit_code = main(["serve"])

    assert len(calls) == 1
    assert exit_code == 0


def test_serve_reads_env_file_once(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KEYSTONE_MCP_ENV_FILE", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_LOG_LEVEL", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_PORT", raising=False)
    (tmp_path / ".env").write_text(
        "KEYSTONE_MCP_LOG_LEVEL=DEBUG\nKEYSTONE_MCP_PORT=9123\n",
        encoding="utf-8",
    )

    load_calls: list[object] = []
    real_load = load_env_file

    def counting_load(*args, **kwargs):
        load_calls.append(())
        return real_load(*args, **kwargs)

    captured: list[object] = []

    def fake_server_main(*, env_file_result=None) -> None:
        captured.append(env_file_result)

    monkeypatch.setattr("keystone_mcp.cli.load_env_file", counting_load)
    monkeypatch.setattr("keystone_mcp.server.main", fake_server_main)

    exit_code = main(["serve"])

    assert exit_code == 0
    assert len(load_calls) == 1
    assert captured
    result = captured[0]
    assert result is not None
    assert set(result.loaded) == {"KEYSTONE_MCP_LOG_LEVEL", "KEYSTONE_MCP_PORT"}
