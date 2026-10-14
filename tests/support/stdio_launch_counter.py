"""Wrapper that records each process launch, then runs the real stdio upstream."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _marker_path() -> str | None:
    if len(sys.argv) > 1 and sys.argv[1]:
        return sys.argv[1]
    return os.environ.get("KEYSTONE_TEST_STDIO_LAUNCH_MARKER")


def _record_launch() -> None:
    path = _marker_path()
    if not path:
        return
    marker = Path(path)
    marker.parent.mkdir(parents=True, exist_ok=True)
    with marker.open("a", encoding="utf-8") as fh:
        fh.write("launch\n")


if __name__ == "__main__":
    _record_launch()
    script_dir = Path(__file__).resolve().parent
    real = script_dir / "stdio_upstream.py"
    os.execv(sys.executable, [sys.executable, str(real), *sys.argv[2:]])
