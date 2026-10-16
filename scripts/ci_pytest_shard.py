#!/usr/bin/env python3
"""Split the pytest module list for CI jobs under short org job timeouts.

The tail shard starts at ``tests/test_stdio_upstream_e2e.py`` in collection order
(~81% of cases). Core and tail each finish within typical 6–10 minute job caps.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TAIL_START = "tests/test_stdio_upstream_e2e.py"


def _modules_in_collection_order() -> list[str]:
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-m",
            "not fuzz",
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    modules: list[str] = []
    seen: set[str] = set()
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if not stripped.startswith("tests/") or "::" not in stripped:
            continue
        module = stripped.split("::", 1)[0]
        if module not in seen:
            seen.add(module)
            modules.append(module)
    if not modules:
        raise SystemExit("pytest --collect-only produced no test modules")
    return modules


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("shard", choices=("core", "tail"))
    parser.add_argument(
        "mode",
        nargs="?",
        choices=("paths", "ignore-args"),
        default="paths",
        help="paths: print module paths to run; ignore-args: --ignore= for core shard",
    )
    args = parser.parse_args()
    modules = _modules_in_collection_order()
    try:
        split_at = modules.index(TAIL_START)
    except ValueError:
        raise SystemExit(f"tail start module not found in collection: {TAIL_START}") from None
    core = modules[:split_at]
    tail = modules[split_at:]
    if args.shard == "core":
        if args.mode == "ignore-args":
            for mod in tail:
                print(f"--ignore={mod}")
        else:
            for mod in core:
                print(mod)
    else:
        if args.mode == "ignore-args":
            raise SystemExit("ignore-args is only valid for the core shard")
        for mod in tail:
            print(mod)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
