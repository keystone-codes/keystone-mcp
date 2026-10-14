"""Stdio upstream that exits on the first N launches (counter file), then serves normally."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _counter_path() -> str | None:
    if len(sys.argv) > 1 and sys.argv[1]:
        return sys.argv[1]
    return os.environ.get("KEYSTONE_TEST_STDIO_LAUNCH_COUNTER")


def _bump_and_should_exit() -> bool:
    path = _counter_path()
    if not path:
        return False
    counter_path = Path(path)
    counter_path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    if counter_path.exists():
        try:
            count = int(counter_path.read_text(encoding="utf-8").strip())
        except ValueError:
            count = 0
    count += 1
    counter_path.write_text(str(count), encoding="utf-8")
    fail_until = int(os.environ.get("KEYSTONE_TEST_STDIO_FAIL_UNTIL", "2"))
    return count <= fail_until


if __name__ == "__main__":
    if _bump_and_should_exit():
        sys.stderr.flush()
        sys.stdout.flush()
        os._exit(2)
    import runpy

    real = str(Path(__file__).resolve().parent / "stdio_upstream.py")
    sys.argv = [real]
    runpy.run_path(real, run_name="__main__")
