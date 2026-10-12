#!/usr/bin/env python3
"""Check that the project version agrees across its sources of truth.

Sources checked:

- ``pyproject.toml`` -> ``project.version``
- ``src/keystone_mcp/__init__.py`` -> ``__version__`` (read as text, the
  module is never imported so this works without an installed package)
- ``CHANGELOG.md`` -> the first released heading (the first ``## [...]``
  heading that is not ``[Unreleased]``)

With ``--tag``, additionally checks that the tag starts with ``v`` and that
``tag[1:]`` matches all three sources, and that the matching CHANGELOG
heading carries a release date.

With ``--dist-dir``, additionally checks the wheel and sdist built by
``uv build`` into that directory: exactly one of each for this project's
distribution (``keystone-mcp-gateway``), their filenames and the wheel's
``METADATA`` agree with ``pyproject.toml``'s version, the wheel carries the
files in ``REQUIRED_WHEEL_FILES``, and the sdist does not leak
``internal/``, ``tests/`` or ``.env*``.

    python scripts/check_version.py
    python scripts/check_version.py --tag v0.4.0
    python scripts/check_version.py --dist-dir dist
    python scripts/check_version.py --tag v0.4.0 --dist-dir dist

Exit codes: 0 everything agrees, 1 a mismatch was found, 2 a source file is
missing or unparsable, the CHANGELOG has no released heading at all, or
``--dist-dir`` does not contain exactly one wheel and one sdist of this
project's distribution.
"""

from __future__ import annotations

import argparse
import re
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_DUNDER_VERSION_RE = re.compile(r"^__version__\s*=\s*[\"']([^\"']+)[\"']\s*$", re.MULTILINE)
_CHANGELOG_HEADING_RE = re.compile(
    r"^## \[(?P<version>[^\]]+)\](?: - (?P<date>\d{4}-\d{2}-\d{2}))?\s*$",
    re.MULTILINE,
)

PYPROJECT_SOURCE = "pyproject.toml"
DUNDER_SOURCE = "src/keystone_mcp/__init__.py"
CHANGELOG_SOURCE = "CHANGELOG.md"

# The project's PyPI distribution name (S14 / X10): "keystone-mcp" was
# already taken by an unrelated project, so the distribution is named
# differently from the importable module (`keystone_mcp`) and the `keystone-mcp`
# command. PEP 427/625 normalize both the wheel and the sdist filename to
# this form (hyphens and dots become underscores).
DIST_NAME = "keystone-mcp-gateway"
NORMALIZED_DIST_NAME = "keystone_mcp_gateway"

_WHEEL_RE = re.compile(rf"^{re.escape(NORMALIZED_DIST_NAME)}-(?P<version>[^-]+)-py3-none-any\.whl$")
_SDIST_RE = re.compile(rf"^{re.escape(NORMALIZED_DIST_NAME)}-(?P<version>.+)\.tar\.gz$")

# Files the wheel must carry so that `pip install keystone-mcp-gateway` ships
# a usable, typed package: type information for plugin authors (X10) and the
# Alembic migrations for the built-in users directory (U01's
# ``test_migration_files_are_packaged`` checks the same thing on an installed
# checkout; this constant checks it on the *built* wheel instead). Later
# cards append their own required files here (X09: ``entry_points.txt``;
# X11: contract-test modules) rather than adding a second constant.
REQUIRED_WHEEL_FILES: tuple[str, ...] = (
    "keystone_mcp/py.typed",
    "keystone_mcp/users/migrations/env.py",
    "keystone_mcp/users/migrations/versions/0001_initial.py",
    "keystone_mcp/contract_tests/__init__.py",
    "keystone_mcp/contract_tests/fake_oidc.py",
)

_REQUIRED_ENTRY_POINT_GROUPS: dict[str, frozenset[str]] = {
    "keystone_mcp.login_providers": frozenset({"oidc", "google", "api_key"}),
    "keystone_mcp.user_directories": frozenset({"local", "http"}),
}

# A sdist must not leak the operator-facing repository layout: internal task
# cards, the test suite (large, and no use to an installed package) or any
# flavour of a real or example .env file.
FORBIDDEN_SDIST_PREFIXES: tuple[str, ...] = ("internal/", "tests/", ".env")


class VersionCheckError(Exception):
    """Raised when a source file is missing or cannot be parsed."""


def _read_pyproject_version(root: Path) -> str:
    path = root / PYPROJECT_SOURCE
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise VersionCheckError(f"{PYPROJECT_SOURCE}: file not found ({path})") from exc
    except tomllib.TOMLDecodeError as exc:
        raise VersionCheckError(f"{PYPROJECT_SOURCE}: could not parse TOML ({exc})") from exc

    try:
        version = data["project"]["version"]
    except (KeyError, TypeError) as exc:
        raise VersionCheckError(f"{PYPROJECT_SOURCE}: missing [project].version") from exc

    if not isinstance(version, str):
        raise VersionCheckError(f"{PYPROJECT_SOURCE}: [project].version is not a string")
    return version


def _read_dunder_version(root: Path) -> str:
    path = root / DUNDER_SOURCE
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise VersionCheckError(f"{DUNDER_SOURCE}: file not found ({path})") from exc

    match = _DUNDER_VERSION_RE.search(text)
    if match is None:
        raise VersionCheckError(f"{DUNDER_SOURCE}: no __version__ assignment found")
    return match.group(1)


def _read_changelog_version(root: Path) -> tuple[str, str | None]:
    path = root / CHANGELOG_SOURCE
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise VersionCheckError(f"{CHANGELOG_SOURCE}: file not found ({path})") from exc

    for match in _CHANGELOG_HEADING_RE.finditer(text):
        version = match.group("version")
        if version.strip().lower() == "unreleased":
            continue
        return version, match.group("date")

    raise VersionCheckError(f"{CHANGELOG_SOURCE}: no released heading found (only [Unreleased]?)")


def read_versions(root: Path) -> dict[str, str]:
    """Read the version recorded by each source of truth under ``root``.

    Raises :class:`VersionCheckError` if a source is missing or unparsable.
    Returns a mapping with keys ``pyproject.toml``, ``src/keystone_mcp/__init__.py``
    and ``CHANGELOG.md``; the CHANGELOG value is just the version string (the
    date, if any, is available separately via :func:`_read_changelog_version`
    for callers that need it).
    """
    pyproject_version = _read_pyproject_version(root)
    dunder_version = _read_dunder_version(root)
    changelog_version, _changelog_date = _read_changelog_version(root)

    return {
        PYPROJECT_SOURCE: pyproject_version,
        DUNDER_SOURCE: dunder_version,
        CHANGELOG_SOURCE: changelog_version,
    }


def _find_dist_files(dist_dir: Path, *, pattern: re.Pattern[str], kind: str) -> Path:
    """Return the single file under ``dist_dir`` matching ``pattern``.

    Raises :class:`VersionCheckError` (a usage error, exit code 2) if
    ``dist_dir`` does not exist or does not contain exactly one match —
    including zero matches or two wheels for the same distribution.
    """
    if not dist_dir.is_dir():
        raise VersionCheckError(f"--dist-dir {dist_dir}: not a directory")

    matches = sorted(p for p in dist_dir.iterdir() if pattern.match(p.name))
    if len(matches) != 1:
        found = ", ".join(p.name for p in matches) or "(none)"
        raise VersionCheckError(
            f"--dist-dir {dist_dir}: expected exactly one {NORMALIZED_DIST_NAME} {kind}, "
            f"found {len(matches)}: {found}"
        )
    return matches[0]


def _check_wheel(wheel_path: Path, pyproject_version: str) -> list[str]:
    """Check a built wheel's filename version, METADATA and required files."""
    errors: list[str] = []

    match = _WHEEL_RE.match(wheel_path.name)
    assert match is not None  # guaranteed by _find_dist_files's pattern
    wheel_version = match.group("version")
    if wheel_version != pyproject_version:
        errors.append(
            f"{wheel_path.name}: wheel filename version ({wheel_version}) != "
            f"{PYPROJECT_SOURCE} ({pyproject_version})"
        )

    try:
        with zipfile.ZipFile(wheel_path) as archive:
            names = frozenset(archive.namelist())
            metadata_name = next(
                (name for name in names if name.endswith(".dist-info/METADATA")), None
            )
            if metadata_name is None:
                errors.append(f"{wheel_path.name}: no *.dist-info/METADATA found")
            else:
                metadata_lines = archive.read(metadata_name).decode("utf-8").splitlines()
                if f"Version: {pyproject_version}" not in metadata_lines:
                    errors.append(
                        f"{wheel_path.name}: {metadata_name} does not declare "
                        f"'Version: {pyproject_version}'"
                    )
                if f"Name: {DIST_NAME}" not in metadata_lines:
                    errors.append(
                        f"{wheel_path.name}: {metadata_name} does not declare 'Name: {DIST_NAME}'"
                    )
    except zipfile.BadZipFile as exc:
        raise VersionCheckError(f"{wheel_path}: not a valid wheel (zip) file: {exc}") from exc

    missing_files = [name for name in REQUIRED_WHEEL_FILES if name not in names]
    if missing_files:
        errors.append(f"{wheel_path.name}: missing required file(s): {', '.join(missing_files)}")

    entry_points_name = next(
        (name for name in names if name.endswith(".dist-info/entry_points.txt")), None
    )
    if entry_points_name is None:
        errors.append(f"{wheel_path.name}: no *.dist-info/entry_points.txt found")
    else:
        try:
            with zipfile.ZipFile(wheel_path) as archive:
                body = archive.read(entry_points_name).decode("utf-8")
        except zipfile.BadZipFile:
            body = ""
        parsed_groups: dict[str, set[str]] = {}
        current_group: str | None = None
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                current_group = stripped[1:-1]
                parsed_groups.setdefault(current_group, set())
                continue
            if current_group is not None and "=" in stripped:
                entry_name = stripped.split("=", 1)[0].strip()
                parsed_groups[current_group].add(entry_name)
        for group, required_names in _REQUIRED_ENTRY_POINT_GROUPS.items():
            found = parsed_groups.get(group, set())
            missing = sorted(required_names - found)
            if missing:
                errors.append(
                    f"{wheel_path.name}: {entry_points_name} group {group!r} "
                    f"missing entry point(s): {', '.join(missing)}"
                )

    return errors


def _check_sdist(sdist_path: Path, pyproject_version: str) -> list[str]:
    """Check a built sdist's filename version and absence of forbidden paths."""
    errors: list[str] = []

    match = _SDIST_RE.match(sdist_path.name)
    assert match is not None  # guaranteed by _find_dist_files's pattern
    sdist_version = match.group("version")
    if sdist_version != pyproject_version:
        errors.append(
            f"{sdist_path.name}: sdist filename version ({sdist_version}) != "
            f"{PYPROJECT_SOURCE} ({pyproject_version})"
        )

    try:
        with tarfile.open(sdist_path, mode="r:gz") as archive:
            member_names = archive.getnames()
    except tarfile.TarError as exc:
        raise VersionCheckError(f"{sdist_path}: not a valid sdist (tar.gz) file: {exc}") from exc

    forbidden: list[str] = []
    for name in member_names:
        # Each entry is "<dist>-<version>/<relative path>"; strip that one
        # top-level directory before matching against forbidden prefixes.
        _root_dir, _, relative = name.partition("/")
        if relative.startswith(FORBIDDEN_SDIST_PREFIXES):
            forbidden.append(name)
    if forbidden:
        errors.append(
            f"{sdist_path.name}: contains forbidden path(s): {', '.join(sorted(forbidden))}"
        )

    return errors


def check_dist_dir(root: Path, dist_dir: Path) -> list[str]:
    """Check the wheel and sdist built into ``dist_dir`` against ``root``.

    Raises :class:`VersionCheckError` (exit code 2) if ``dist_dir`` is
    missing or does not contain exactly one wheel and one sdist of this
    project's distribution, or if either archive cannot be opened. Returns a
    list of mismatch messages otherwise (exit code 1 if non-empty).
    """
    pyproject_version = _read_pyproject_version(root)

    wheel_path = _find_dist_files(dist_dir, pattern=_WHEEL_RE, kind="wheel")
    sdist_path = _find_dist_files(dist_dir, pattern=_SDIST_RE, kind="sdist")

    return [
        *_check_wheel(wheel_path, pyproject_version),
        *_check_sdist(sdist_path, pyproject_version),
    ]


def check(root: Path, tag: str | None, dist_dir: Path | None = None) -> list[str]:
    """Check version agreement across sources (``tag`` and ``dist_dir`` optional).

    Returns a list of human-readable error messages; empty means everything
    agrees. Raises :class:`VersionCheckError` only for a missing or
    unparsable source file, a CHANGELOG with no released heading at all, or
    a ``dist_dir`` that does not hold exactly one wheel and one sdist of this
    project's distribution (usage errors, exit code 2). A malformed
    ``X.Y.Z`` version or tag (for example a pre-release) is reported as an
    ordinary entry in the returned list (exit code 1), since 0.4.0 simply
    refuses to release it rather than treating it as a setup mistake.
    """
    versions = read_versions(root)
    _changelog_version, changelog_date = _read_changelog_version(root)

    errors: list[str] = []

    for source, version in versions.items():
        if not _VERSION_RE.match(version):
            errors.append(
                f"{source}: version {version!r} is not a plain X.Y.Z release "
                "version (pre-release versions are not supported)"
            )

    pyproject_version = versions[PYPROJECT_SOURCE]
    dunder_version = versions[DUNDER_SOURCE]
    changelog_version = versions[CHANGELOG_SOURCE]

    if pyproject_version != dunder_version:
        errors.append(
            f"{PYPROJECT_SOURCE} ({pyproject_version}) != {DUNDER_SOURCE} ({dunder_version})"
        )
    if pyproject_version != changelog_version:
        errors.append(
            f"{PYPROJECT_SOURCE} ({pyproject_version}) != {CHANGELOG_SOURCE} ({changelog_version})"
        )
    if dunder_version != changelog_version:
        errors.append(
            f"{DUNDER_SOURCE} ({dunder_version}) != {CHANGELOG_SOURCE} ({changelog_version})"
        )

    if tag is not None:
        if not tag.startswith("v"):
            errors.append(f"tag {tag!r} does not start with 'v'")
        else:
            tag_version = tag[1:]
            if not _VERSION_RE.match(tag_version):
                errors.append(
                    f"tag {tag!r} is not a plain vX.Y.Z release tag "
                    "(pre-release tags are not supported)"
                )
            else:
                for source, version in versions.items():
                    if version != tag_version:
                        errors.append(f"tag ({tag_version}) != {source} ({version})")
                if tag_version == changelog_version and changelog_date is None:
                    errors.append(
                        f"{CHANGELOG_SOURCE}: heading for {changelog_version} has no release date"
                    )

    if dist_dir is not None:
        errors.extend(check_dist_dir(root, dist_dir))

    return errors


def _format_report(
    root: Path, tag: str | None, dist_dir: Path | None = None
) -> tuple[list[str], int]:
    """Build the printable report lines and the resulting exit code."""
    lines: list[str] = []

    try:
        versions = read_versions(root)
        _changelog_version, changelog_date = _read_changelog_version(root)
    except VersionCheckError as exc:
        return [str(exc)], 2

    lines.append(f"{PYPROJECT_SOURCE}: {versions[PYPROJECT_SOURCE]}")
    lines.append(f"{DUNDER_SOURCE}: {versions[DUNDER_SOURCE]}")
    changelog_version = versions[CHANGELOG_SOURCE]
    if changelog_date:
        lines.append(f"{CHANGELOG_SOURCE}: {changelog_version} ({changelog_date})")
    else:
        lines.append(f"{CHANGELOG_SOURCE}: {changelog_version}")
    if tag is not None:
        lines.append(f"tag: {tag}")
    if dist_dir is not None:
        lines.append(f"dist-dir: {dist_dir}")

    try:
        errors = check(root, tag, dist_dir)
    except VersionCheckError as exc:
        lines.append(str(exc))
        return lines, 2

    if errors:
        lines.append("MISMATCH: " + "; ".join(errors))
        return lines, 1

    lines.append("OK")
    return lines, 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tag",
        default=None,
        help="Git tag to check against (e.g. v0.4.0); omit to only check the"
        " three file sources against each other",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root (default: parent of this script's directory)",
    )
    parser.add_argument(
        "--dist-dir",
        type=Path,
        default=None,
        help="Directory holding a wheel and sdist built by 'uv build' (e.g. dist/) to"
        " check against pyproject.toml's version; omit to skip this check",
    )
    args = parser.parse_args(argv)

    lines, exit_code = _format_report(args.root, args.tag, args.dist_dir)
    for line in lines:
        print(line)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
