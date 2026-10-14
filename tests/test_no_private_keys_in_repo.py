"""Guard: PEM private-key blocks may live only under tests/data/test-keys/."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_ALLOWED_PREFIX = "tests/data/test-keys/"
_BEGIN = "-----BEGIN "
_END = "PRIVATE KEY-----"
_PRIVATE_KEY_BLOCK = re.compile(re.escape(_BEGIN) + r"[A-Z ]*" + re.escape(_END))


def test_private_key_blocks_live_only_in_test_keys() -> None:
    try:
        tracked = subprocess.check_output(
            ["git", "ls-files"],
            cwd=_REPO_ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip("git not available")

    violations: list[str] = []
    for rel_path in tracked.splitlines():
        if not rel_path or rel_path.startswith(_ALLOWED_PREFIX):
            continue
        path = _REPO_ROOT / rel_path
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if _PRIVATE_KEY_BLOCK.search(text):
            violations.append(rel_path)

    assert not violations, "Private key material outside tests/data/test-keys/:\n" + "\n".join(
        sorted(violations)
    )
