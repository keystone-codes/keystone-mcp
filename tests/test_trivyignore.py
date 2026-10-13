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
only the header comment (no identifiers) is valid (nothing here loops over
an identifier, so an empty list trivially satisfies every check below).

The review date is read from that comment line only. Trivy's own inline
``exp:YYYY-MM-DD`` suffix on the identifier line itself is a different,
unrelated mechanism that this repository does not use; an identifier line
carrying one would fail ``test_every_identifier_line_is_a_known_vulnerability_id_format``
below, since the whole line must match the bare id pattern.
"""

from __future__ import annotations

import datetime
import re
from pathlib import Path

TRIVYIGNORE_PATH = Path(__file__).resolve().parent.parent / ".trivyignore"

_IDENTIFIER_RE = re.compile(r"^(CVE-\d{4}-\d+|GHSA-[0-9a-z-]+)$")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _lines() -> list[str]:
    return TRIVYIGNORE_PATH.read_text(encoding="utf-8").splitlines()


def test_trivyignore_file_exists():
    assert TRIVYIGNORE_PATH.is_file(), ".trivyignore must exist at the repository root"


def test_no_review_date_is_overdue():
    """An accepted exception does not quietly become permanent.

    Every identifier's review date (the ``YYYY-MM-DD`` in the comment line
    directly above it) must not be in the past; an overdue date means nobody
    came back to re-review it. Fix by removing the entry (the finding is
    actually resolved) or by giving it a fresh reason and a new date.
    """
    today = datetime.date.today()
    lines = _lines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        reason_line = lines[index - 1].strip() if index > 0 else ""
        match = _DATE_RE.search(reason_line)
        assert match, (
            f"'{stripped}' has no dated reason comment above it to check a review date against"
        )
        review_date = datetime.date.fromisoformat(match.group())
        assert review_date >= today, (
            f"'{stripped}': review date {review_date.isoformat()} is overdue "
            f"(today is {today.isoformat()}); re-review this exception — remove it "
            "if the finding is resolved, or give it a fresh reason and date"
        )


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
