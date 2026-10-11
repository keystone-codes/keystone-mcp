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

    python scripts/check_version.py
    python scripts/check_version.py --tag v0.4.0

Exit codes: 0 everything agrees, 1 a mismatch was found, 2 a source file is
missing, unparsable, or the CHANGELOG has no released heading at all.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
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


def check(root: Path, tag: str | None) -> list[str]:
    """Check version agreement across sources (and ``tag``, if given).

    Returns a list of human-readable error messages; empty means everything
    agrees. Raises :class:`VersionCheckError` only for a missing or
    unparsable source file, or a CHANGELOG with no released heading at all
    (usage errors, exit code 2). A malformed ``X.Y.Z`` version or tag (for
    example a pre-release) is reported as an ordinary entry in the returned
    list (exit code 1), since 0.4.0 simply refuses to release it rather than
    treating it as a setup mistake.
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

    return errors


def _format_report(root: Path, tag: str | None) -> tuple[list[str], int]:
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

    try:
        errors = check(root, tag)
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
    args = parser.parse_args(argv)

    lines, exit_code = _format_report(args.root, args.tag)
    for line in lines:
        print(line)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
