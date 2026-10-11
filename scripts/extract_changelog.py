#!/usr/bin/env python3
"""Print the body of one ``CHANGELOG.md`` release section to stdout.

Used by the release workflow to build GitHub Release notes straight from the
CHANGELOG, instead of maintaining the text twice.

    python scripts/extract_changelog.py 0.4.0
    python scripts/extract_changelog.py Unreleased --changelog CHANGELOG.md

The heading itself (``## [VERSION] - DATE``) is not printed, only the text
between it and the next ``## [`` heading (or the end of the file). Leading
and trailing blank lines are trimmed. Exit codes: 0 on success, 1 when no
section for ``VERSION`` exists (message on stderr).

The heading regex is intentionally a standalone copy of the one in
``scripts/check_version.py`` rather than an import: the two scripts are
independent command-line tools and neither should depend on the other's
internals.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_CHANGELOG_HEADING_RE = re.compile(
    r"^## \[(?P<version>[^\]]+)\](?: - (?P<date>\d{4}-\d{2}-\d{2}))?\s*$",
    re.MULTILINE,
)


def extract_section(text: str, version: str) -> str | None:
    """Return the body of the ``## [version]`` section in ``text``.

    ``version`` is matched case-insensitively (so ``Unreleased`` and
    ``unreleased`` both work) and without surrounding whitespace. Returns
    ``None`` when no heading matches ``version``.
    """
    headings = list(_CHANGELOG_HEADING_RE.finditer(text))
    target = version.strip().lower()

    for index, match in enumerate(headings):
        if match.group("version").strip().lower() != target:
            continue
        start = match.end()
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        return text[start:end].strip("\n")

    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="Release version to extract, e.g. 0.4.0 or Unreleased")
    parser.add_argument(
        "--changelog",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "CHANGELOG.md",
        help="Path to CHANGELOG.md (default: repository root CHANGELOG.md)",
    )
    args = parser.parse_args(argv)

    try:
        text = args.changelog.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"{args.changelog}: file not found", file=sys.stderr)
        return 1

    section = extract_section(text, args.version)
    if section is None:
        print(f"{args.changelog}: no section for version {args.version!r}", file=sys.stderr)
        return 1

    print(section)
    return 0


if __name__ == "__main__":
    sys.exit(main())
