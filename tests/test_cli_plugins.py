"""CLI: keystone-mcp plugins list."""

from __future__ import annotations

import subprocess
import sys


def test_plugins_list_shows_builtins() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "keystone_mcp.cli", "plugins", "list"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout
    for name in ("oidc", "google", "api_key", "local", "http"):
        assert name in out
        assert "(built-in)" in out
