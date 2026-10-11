"""Tests for scripts/check_version.py (the release version gate).

``scripts/`` is not a package, so the module under test is loaded directly
from its file path via importlib, exactly as CI invokes it.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "check_version.py"

_spec = importlib.util.spec_from_file_location("check_version", _SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
check_version = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_version)


def _write_project(
    tmp_path: Path,
    *,
    pyproject_version: str = "0.4.0",
    dunder_version: str = "0.4.0",
    changelog_heading: str = "## [Unreleased]\n\n## [0.4.0] - 2026-10-10\n",
) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "demo"\nversion = "{pyproject_version}"\n',
        encoding="utf-8",
    )
    package_dir = tmp_path / "src" / "keystone_mcp"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text(
        f'"""Demo package."""\n\n__version__ = "{dunder_version}"\n',
        encoding="utf-8",
    )
    (tmp_path / "CHANGELOG.md").write_text(
        f"# Changelog\n\n{changelog_heading}",
        encoding="utf-8",
    )
    return tmp_path


def test_consistent_versions_pass(tmp_path: Path) -> None:
    root = _write_project(tmp_path)

    assert check_version.check(root, None) == []
    assert check_version.main(["--root", str(root)]) == 0


def test_pyproject_mismatch_reported(tmp_path: Path) -> None:
    root = _write_project(tmp_path, pyproject_version="0.4.1")

    errors = check_version.check(root, None)
    assert errors
    joined = " ".join(errors)
    assert "pyproject.toml" in joined
    assert "0.4.1" in joined
    assert "0.4.0" in joined
    assert check_version.main(["--root", str(root)]) == 1


def test_dunder_version_mismatch_reported(tmp_path: Path) -> None:
    root = _write_project(tmp_path, dunder_version="0.4.1")

    errors = check_version.check(root, None)
    assert errors
    joined = " ".join(errors)
    assert "src/keystone_mcp/__init__.py" in joined
    assert "0.4.1" in joined
    assert "0.4.0" in joined
    assert check_version.main(["--root", str(root)]) == 1


def test_changelog_mismatch_reported(tmp_path: Path) -> None:
    root = _write_project(
        tmp_path,
        changelog_heading="## [Unreleased]\n\n## [0.4.1] - 2026-10-10\n",
    )

    errors = check_version.check(root, None)
    assert errors
    joined = " ".join(errors)
    assert "CHANGELOG.md" in joined
    assert "0.4.1" in joined
    assert "0.4.0" in joined
    assert check_version.main(["--root", str(root)]) == 1


def test_tag_matches(tmp_path: Path) -> None:
    root = _write_project(tmp_path)

    assert check_version.check(root, "v0.4.0") == []
    assert check_version.main(["--root", str(root), "--tag", "v0.4.0"]) == 0


def test_tag_without_v_prefix_fails(tmp_path: Path) -> None:
    root = _write_project(tmp_path)

    errors = check_version.check(root, "0.4.0")
    assert errors
    assert any("v" in e for e in errors)
    assert check_version.main(["--root", str(root), "--tag", "0.4.0"]) == 1


def test_tag_mismatch_fails(tmp_path: Path) -> None:
    root = _write_project(tmp_path)

    errors = check_version.check(root, "v0.4.1")
    assert errors
    assert check_version.main(["--root", str(root), "--tag", "v0.4.1"]) == 1


def test_tag_requires_changelog_date(tmp_path: Path) -> None:
    root = _write_project(
        tmp_path,
        changelog_heading="## [Unreleased]\n\n## [0.4.0]\n",
    )

    errors = check_version.check(root, "v0.4.0")
    assert errors
    assert any("date" in e for e in errors)
    assert check_version.main(["--root", str(root), "--tag", "v0.4.0"]) == 1


def test_prerelease_rejected(tmp_path: Path) -> None:
    root = _write_project(tmp_path)

    errors = check_version.check(root, "v0.4.0-rc1")
    assert errors
    assert any("pre-release" in e for e in errors)
    assert check_version.main(["--root", str(root), "--tag", "v0.4.0-rc1"]) == 1


def test_missing_released_heading_is_usage_error(tmp_path: Path) -> None:
    root = _write_project(tmp_path, changelog_heading="## [Unreleased]\n")

    with pytest.raises(check_version.VersionCheckError):
        check_version.check(root, None)
    assert check_version.main(["--root", str(root)]) == 2


def test_repository_is_consistent() -> None:
    assert check_version.main(["--root", str(_REPO_ROOT)]) == 0
