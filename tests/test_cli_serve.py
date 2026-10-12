"""Tests for the `keystone-mcp serve` subcommand.

The subcommand is a thin CLI entry point for the PyPI package (X10): it must
call `keystone_mcp.server.main()` and nothing else, so `python -m
keystone_mcp.server` and `keystone-mcp serve` behave identically.
"""

from __future__ import annotations

import pytest

from keystone_mcp.cli import main


def test_serve_calls_server_main(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[()]] = []

    def fake_server_main() -> None:
        calls.append(())

    monkeypatch.setattr("keystone_mcp.server.main", fake_server_main)

    exit_code = main(["serve"])

    assert calls == [()]
    assert exit_code == 0
