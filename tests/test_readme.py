"""Guards the README's product-boundaries section.

Keystone-MCP turns down two requests that come up for almost any product of
this shape -- "one deployment for several organizations" and "an admin UI"
-- because both would change the product rather than extend it. The
``## What it does not do`` section in ``README.md`` states that decision so
a newcomer learns it from the front page instead of from a closed issue.
This test does not re-check the exact wording (that is free to improve); it
only guards against the section disappearing or losing its substance in a
future README edit.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_HEADING = "## What it does not do"
_REQUIRED_WORDS = ("organization", "admin UI", "business data", "routing")


def test_readme_states_what_it_does_not_do() -> None:
    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert _HEADING in readme_text, f"README.md is missing the {_HEADING!r} heading"

    # Scope the word check to the section itself, not the whole file: take
    # the text from the heading up to the next level-2 heading (or EOF).
    start = readme_text.index(_HEADING) + len(_HEADING)
    match = re.search(r"^## ", readme_text[start:], flags=re.MULTILINE)
    section = readme_text[start : start + match.start()] if match else readme_text[start:]

    section_lower = section.lower()
    missing = [word for word in _REQUIRED_WORDS if word.lower() not in section_lower]
    assert not missing, f"README.md's {_HEADING!r} section is missing word(s): {missing}"
