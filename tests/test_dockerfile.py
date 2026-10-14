"""Static checks on the container build definition."""

from __future__ import annotations

import re
from pathlib import Path

_DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"
_FROM_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}\b")


def test_every_from_is_pinned_by_digest():
    lines = _DOCKERFILE.read_text(encoding="utf-8").splitlines()
    from_lines = [line for line in lines if line.strip().upper().startswith("FROM ")]
    assert from_lines, "Dockerfile must declare at least one FROM line"
    for line in from_lines:
        assert _FROM_DIGEST_RE.search(line), f"FROM line must pin a multi-arch digest: {line!r}"
