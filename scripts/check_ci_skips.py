#!/usr/bin/env python3
"""Fail CI when pytest skips tests that are not on the allow-list."""

from __future__ import annotations

import sys
import warnings
import xml.etree.ElementTree as ET
from pathlib import Path


def _load_allowed(path: Path) -> dict[str, str]:
    allowed: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "\t" not in stripped:
            raise SystemExit(f"invalid allow-list line (expected nodeid<TAB>reason): {line!r}")
        nodeid, reason = stripped.split("\t", 1)
        allowed[nodeid.strip()] = reason.strip()
    return allowed


def _nodeid_from_junit(classname: str, name: str) -> str:
    module_path = classname.rsplit(".", 1)
    if len(module_path) == 2 and module_path[1][:1].isupper():
        module, cls = module_path
        return f"{module.replace('.', '/')}.py::{cls}::{name}"
    return f"{classname.replace('.', '/')}.py::{name}"


def _skipped_from_junit(path: Path) -> dict[str, str]:
    root = ET.parse(path).getroot()
    skipped: dict[str, str] = {}
    for case in root.iter("testcase"):
        skip = case.find("skipped")
        if skip is None:
            continue
        classname = case.get("classname") or ""
        name = case.get("name") or ""
        nodeid = _nodeid_from_junit(classname, name)
        message = (skip.get("message") or skip.text or "").strip()
        skipped[nodeid] = message
    return skipped


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} <junit.xml> <allowed.txt>", file=sys.stderr)
        return 2
    junit_path = Path(argv[1])
    allowed_path = Path(argv[2])
    allowed = _load_allowed(allowed_path)
    skipped = _skipped_from_junit(junit_path)

    unexpected = [
        f"{nodeid} — {reason}"
        for nodeid, reason in sorted(skipped.items())
        if nodeid not in allowed
    ]
    if unexpected:
        print("Unexpected skipped tests in CI:", file=sys.stderr)
        for line in unexpected:
            print(f"  {line}", file=sys.stderr)
        return 1

    stale = sorted(set(allowed) - set(skipped))
    for nodeid in stale:
        warnings.warn(f"allow-list entry no longer skipped: {nodeid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
