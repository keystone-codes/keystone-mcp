"""Shape checks on the ``.trivyignore`` exception list.

Trivy's image scan blocks pull requests and releases on fixable HIGH and
CRITICAL findings (see ``.github/workflows/security.yml`` and
``.github/workflows/release.yml``). ``.trivyignore`` is the only way to
accept a finding temporarily, and every entry must carry a reason and a
review date so an exception does not silently become permanent.

Format enforced here: every non-empty line that does not start with ``#``
must be a vulnerability identifier (``CVE-YYYY-NNNN...`` or a ``GHSA-...``
advisory id), and the line directly above it must be a ``#`` comment that
contains a date in ``YYYY-MM-DD`` form (the review date). A file containing
only the header comment (no identifiers) is valid.
"""

from __future__ import annotations

import re
from pathlib import Path

TRIVYIGNORE_PATH = Path(__file__).resolve().parent.parent / ".trivyignore"

_IDENTIFIER_RE = re.compile(r"^(CVE-\d{4}-\d+|GHSA-[0-9a-z-]+)$")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _lines() -> list[str]:
    return TRIVYIGNORE_PATH.read_text(encoding="utf-8").splitlines()


def test_trivyignore_file_exists():
    assert TRIVYIGNORE_PATH.is_file(), ".trivyignore must exist at the repository root"


def test_empty_trivyignore_with_only_header_comments_is_valid():
    lines = _lines()
    non_comment_lines = [
        line for line in lines if line.strip() and not line.strip().startswith("#")
    ]
    # The file ships with only a header explaining the format; this is the
    # expected steady state when there are no accepted findings.
    if not non_comment_lines:
        assert all(line.strip() == "" or line.strip().startswith("#") for line in lines)


def test_every_identifier_line_is_a_known_vulnerability_id_format():
    for line in _lines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        assert _IDENTIFIER_RE.match(stripped), (
            f"'{stripped}' is not a CVE-YYYY-NNNN or GHSA-... identifier; "
            ".trivyignore only accepts vulnerability ids, one per line"
        )


def test_every_identifier_has_a_dated_reason_comment_directly_above_it():
    lines = _lines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        assert _IDENTIFIER_RE.match(stripped), f"'{stripped}' is not a valid identifier"
        assert index > 0, f"'{stripped}' has no comment line above it explaining why it is accepted"
        reason_line = lines[index - 1].strip()
        assert reason_line.startswith("#"), (
            f"the line directly above '{stripped}' must be a '#' comment with the "
            "reason it is accepted and the date to review it"
        )
        assert _DATE_RE.search(reason_line), (
            f"the reason comment above '{stripped}' must contain a review date in YYYY-MM-DD form"
        )
