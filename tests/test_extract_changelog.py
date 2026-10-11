"""Tests for scripts/extract_changelog.py (release notes for GitHub Release).

``scripts/`` is not a package, so the module under test is loaded directly
from its file path via importlib, exactly as the release workflow invokes it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "extract_changelog.py"

_spec = importlib.util.spec_from_file_location("extract_changelog", _SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
extract_changelog = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(extract_changelog)


_SAMPLE_CHANGELOG = """# Changelog

## [Unreleased]

### Added

- Unreleased thing one.
- Unreleased thing two.

## [0.2.0] - 2026-05-01

### Added

- Middle release feature.

### Fixed

- Middle release bugfix.

## [0.1.0] - 2026-01-01

### Added

- First release.
"""


def test_extracts_section_from_middle_of_file() -> None:
    section = extract_changelog.extract_section(_SAMPLE_CHANGELOG, "0.2.0")

    assert section is not None
    assert "## [0.2.0]" not in section
    assert "## [0.1.0]" not in section
    assert "Middle release feature." in section
    assert "Middle release bugfix." in section


def test_extracts_last_section_to_end_of_file() -> None:
    section = extract_changelog.extract_section(_SAMPLE_CHANGELOG, "0.1.0")

    assert section is not None
    assert "## [" not in section
    assert "First release." in section


def test_extracts_unreleased_by_name() -> None:
    section = extract_changelog.extract_section(_SAMPLE_CHANGELOG, "Unreleased")

    assert section is not None
    assert "Unreleased thing one." in section
    assert "Unreleased thing two." in section
    assert "## [0.2.0]" not in section


def test_missing_section_returns_none() -> None:
    assert extract_changelog.extract_section(_SAMPLE_CHANGELOG, "9.9.9") is None


def test_missing_section_exits_with_code_1(tmp_path: Path) -> None:
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(_SAMPLE_CHANGELOG, encoding="utf-8")

    exit_code = extract_changelog.main(["9.9.9", "--changelog", str(changelog)])

    assert exit_code == 1


def test_real_changelog_0_3_1_has_added_and_not_0_3_0() -> None:
    real_changelog = _REPO_ROOT / "CHANGELOG.md"
    text = real_changelog.read_text(encoding="utf-8")

    section = extract_changelog.extract_section(text, "0.3.1")

    assert section is not None
    assert "### Added" in section
    assert "## [0.3.0]" not in section
