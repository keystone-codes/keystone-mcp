"""Tests for scripts/check_version.py (the release version gate).

``scripts/`` is not a package, so the module under test is loaded directly
from its file path via importlib, exactly as CI invokes it.
"""

from __future__ import annotations

import importlib.util
import io
import tarfile
import zipfile
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


def _write_wheel(
    dist_dir: Path,
    *,
    version: str = "0.4.0",
    name: str = check_version.DIST_NAME,
    normalized: str = check_version.NORMALIZED_DIST_NAME,
    include_required_files: bool = True,
) -> Path:
    """Write a minimal but well-formed wheel for the dist-dir checks below.

    Just enough to satisfy ``zipfile``: a ``*.dist-info/METADATA`` entry and,
    unless ``include_required_files`` is false, the files
    ``REQUIRED_WHEEL_FILES`` lists.
    """
    wheel_path = dist_dir / f"{normalized}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, "w") as archive:
        metadata = (
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"
            "Summary: Demo wheel for check_version.py tests\n"
        )
        archive.writestr(f"{normalized}-{version}.dist-info/METADATA", metadata)
        if include_required_files:
            for relative_path in check_version.REQUIRED_WHEEL_FILES:
                archive.writestr(relative_path, "# placeholder\n")
    return wheel_path


def _write_sdist(
    dist_dir: Path,
    *,
    version: str = "0.4.0",
    normalized: str = check_version.NORMALIZED_DIST_NAME,
    extra_members: tuple[str, ...] = (),
) -> Path:
    """Write a minimal tar.gz sdist with a single top-level ``name-version/`` dir."""
    sdist_path = dist_dir / f"{normalized}-{version}.tar.gz"
    top = f"{normalized}-{version}"
    with tarfile.open(sdist_path, mode="w:gz") as archive:

        def add(relative_path: str, content: str = "x\n") -> None:
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=f"{top}/{relative_path}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

        add("pyproject.toml")
        add("src/keystone_mcp/__init__.py")
        for relative_path in extra_members:
            add(relative_path)
    return sdist_path


def test_dist_dir_matching_versions_pass(tmp_path: Path) -> None:
    root = _write_project(tmp_path)
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    _write_wheel(dist_dir)
    _write_sdist(dist_dir)

    assert check_version.check(root, None, dist_dir) == []
    assert check_version.main(["--root", str(root), "--dist-dir", str(dist_dir)]) == 0


def test_dist_dir_version_mismatch_fails(tmp_path: Path) -> None:
    root = _write_project(tmp_path)  # pyproject.toml version is 0.4.0
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    _write_wheel(dist_dir, version="0.4.1")
    _write_sdist(dist_dir, version="0.4.1")

    errors = check_version.check(root, None, dist_dir)
    assert errors
    joined = " ".join(errors)
    assert "0.4.1" in joined
    assert "0.4.0" in joined
    assert check_version.main(["--root", str(root), "--dist-dir", str(dist_dir)]) == 1


def test_wheel_without_migrations_fails(tmp_path: Path) -> None:
    root = _write_project(tmp_path)
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    _write_wheel(dist_dir, include_required_files=False)
    _write_sdist(dist_dir)

    errors = check_version.check(root, None, dist_dir)
    assert errors
    joined = " ".join(errors)
    assert "migrations" in joined
    assert "py.typed" in joined
    assert check_version.main(["--root", str(root), "--dist-dir", str(dist_dir)]) == 1


def test_sdist_with_internal_dir_fails(tmp_path: Path) -> None:
    root = _write_project(tmp_path)
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    _write_wheel(dist_dir)
    _write_sdist(dist_dir, extra_members=("internal/tasks-0.5.0/README.md",))

    errors = check_version.check(root, None, dist_dir)
    assert errors
    joined = " ".join(errors)
    assert "internal/" in joined
    assert check_version.main(["--root", str(root), "--dist-dir", str(dist_dir)]) == 1


def test_two_wheels_is_usage_error(tmp_path: Path) -> None:
    root = _write_project(tmp_path)
    dist_dir = tmp_path / "dist"
    dist_dir.mkdir()
    _write_wheel(dist_dir, version="0.4.0")
    _write_wheel(dist_dir, version="0.3.9")
    _write_sdist(dist_dir)

    with pytest.raises(check_version.VersionCheckError):
        check_version.check(root, None, dist_dir)
    assert check_version.main(["--root", str(root), "--dist-dir", str(dist_dir)]) == 2


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
