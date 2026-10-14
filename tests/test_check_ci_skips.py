"""Tests for ``scripts/check_ci_skips.py``."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_ci_skips.py"


def _run(junit: Path, allowed: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(junit), str(allowed)],
        capture_output=True,
        text=True,
        check=False,
    )


def _write_junit(
    path: Path, *, classname: str, name: str, skipped: bool, message: str = ""
) -> None:
    skip_xml = f'<skipped message="{message}"></skipped>' if skipped else ""
    path.write_text(
        f"""<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" tests="1" failures="0" skipped="{1 if skipped else 0}">
  <testcase classname="{classname}" name="{name}">{skip_xml}</testcase>
</testsuite>
""",
        encoding="utf-8",
    )


def test_unlisted_skip_fails(tmp_path: Path) -> None:
    junit = tmp_path / "junit.xml"
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("# empty\n", encoding="utf-8")
    _write_junit(junit, classname="tests.test_x", name="test_y", skipped=True, message="nope")
    result = _run(junit, allowed)
    assert result.returncode == 1
    assert "tests/test_x.py::test_y" in result.stderr


def test_listed_skip_passes(tmp_path: Path) -> None:
    junit = tmp_path / "junit.xml"
    allowed = tmp_path / "allowed.txt"
    allowed.write_text("tests/test_x.py::test_y\tallowed reason\n", encoding="utf-8")
    _write_junit(junit, classname="tests.test_x", name="test_y", skipped=True, message="nope")
    result = _run(junit, allowed)
    assert result.returncode == 0


def test_stale_allow_list_entry_warns(tmp_path: Path) -> None:
    junit = tmp_path / "junit.xml"
    allowed = tmp_path / "allowed.txt"
    allowed.write_text(
        "tests/test_x.py::test_y\treason\ntests/test_x.py::test_gone\tstale\n",
        encoding="utf-8",
    )
    _write_junit(junit, classname="tests.test_x", name="test_y", skipped=True)
    result = _run(junit, allowed)
    assert result.returncode == 0
    assert "test_gone" in result.stderr
