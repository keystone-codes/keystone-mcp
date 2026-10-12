"""Checks every relative link and heading anchor in the Markdown docs.

This test needs no network access and no running service: it only reads
Markdown files from disk. It exists so that a documentation change can say
"the test is green" instead of "I checked it by eye" -- renames, moved pages,
and typo'd paths are caught at ``pytest`` time.

Scope: ``README.md``, ``SECURITY.md``, ``CHANGELOG.md`` at the repository
root, plus every ``*.md`` under ``docs/``, ``examples/``, ``skills/`` and
``prometheus/``. External links (``http:``, ``https:``, ``mailto:``,
``data:``) are intentionally not checked -- CI has no network access and
external sites change independently of this repository.

For a relative target, the path part must resolve to an existing file or
directory (relative to the folder the linking file lives in). When the
target is a ``.md`` file and carries a ``#anchor``, the anchor must match one
of that file's headings, slugified the way GitHub does it.
"""

from __future__ import annotations

import re
import urllib.parse
from functools import lru_cache
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

_ROOT_FILES = ("README.md", "SECURITY.md", "CHANGELOG.md")
_SCAN_DIRS = ("docs", "examples", "skills", "prometheus")
_EXCLUDED_DIR_NAMES = {"internal", ".venv", ".git", "node_modules"}

_FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")
_INLINE_CODE_RE = re.compile(r"`[^`\n]*`")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_EXPLICIT_ANCHOR_RE = re.compile(r"""<a\s+(?:id|name)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

_MD_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
_HTML_ATTR_RE = re.compile(r"""(?:href|src)\s*=\s*(["'])(.*?)\1""")
_REF_LINK_RE = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)")
_TITLE_SPLIT_RE = re.compile(r"""^(\S+)(?:\s+(?:"[^"]*"|'[^']*'))?$""")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:")


def _discover_doc_files() -> list[str]:
    """Return every file this test checks, as repo-relative POSIX paths."""
    found: set[Path] = set()

    for name in _ROOT_FILES:
        path = REPO_ROOT / name
        if path.is_file():
            found.add(path)

    for dirname in _SCAN_DIRS:
        base = REPO_ROOT / dirname
        if not base.is_dir():
            continue
        for path in base.rglob("*.md"):
            parts = path.relative_to(REPO_ROOT).parts
            if any(part in _EXCLUDED_DIR_NAMES for part in parts):
                continue
            found.add(path)

    return sorted(p.relative_to(REPO_ROOT).as_posix() for p in found)


def _blank_fences(lines: list[str]) -> list[str]:
    """Replace fenced code block lines (``` or ~~~) with blank lines.

    Line numbers are preserved so error messages can point at the original
    file.
    """
    out: list[str] = []
    in_fence = False
    fence_char = ""
    for line in lines:
        match = _FENCE_RE.match(line)
        if in_fence:
            if match and match.group(1)[0] == fence_char:
                in_fence = False
            out.append("")
            continue
        if match:
            in_fence = True
            fence_char = match.group(1)[0]
            out.append("")
            continue
        out.append(line)
    return out


def _slugify(text: str) -> str:
    """Turn heading text into a GitHub-style anchor slug."""
    slug = text.strip().lower()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"\s+", "-", slug)
    return slug


@lru_cache(maxsize=None)
def _anchors_for_file(path: Path) -> frozenset[str]:
    """Collect every valid anchor target inside a Markdown file.

    Includes slugified headings (outside code fences, with GitHub's
    duplicate-suffix rule) and explicit ``<a id="...">`` / ``<a name="...">``
    anchors.
    """
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return frozenset()

    fence_blanked = _blank_fences(raw_lines)

    anchors: set[str] = set()
    seen: dict[str, int] = {}
    for line in fence_blanked:
        match = _HEADING_RE.match(line)
        if not match:
            continue
        # Inline code markers are dropped, their text is kept: a heading
        # written as "## `KEYSTONE_MCP_X`" anchors as "keystone_mcp_x".
        heading_text = match.group(2).replace("`", "")
        slug = _slugify(heading_text)
        if slug in seen:
            seen[slug] += 1
            slug = f"{slug}-{seen[slug]}"
        else:
            seen[slug] = 0
        anchors.add(slug)

    for line in fence_blanked:
        for match in _EXPLICIT_ANCHOR_RE.finditer(line):
            anchors.add(match.group(1))

    return frozenset(anchors)


def _extract_raw_targets(line: str) -> list[str]:
    """Pull every link/image/href/src/reference-link target out of a line."""
    targets = [m.group(1) for m in _MD_LINK_RE.finditer(line)]
    targets.extend(m.group(2) for m in _HTML_ATTR_RE.finditer(line))
    ref_match = _REF_LINK_RE.match(line)
    if ref_match:
        targets.append(ref_match.group(1))
    return targets


def _clean_target(raw: str) -> str | None:
    """Normalize a raw link target; return None if it should be skipped."""
    target = raw.strip()
    if not target:
        return None
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    title_match = _TITLE_SPLIT_RE.match(target)
    if title_match:
        target = title_match.group(1)
    if not target or target.startswith("//"):
        return None
    if _SCHEME_RE.match(target):
        return None
    return target


def _resolve_path_part(file_path: Path, path_part: str) -> Path:
    path_part = urllib.parse.unquote(path_part)
    if path_part.startswith("/"):
        return (REPO_ROOT / path_part.lstrip("/")).resolve()
    return (file_path.parent / path_part).resolve()


def _check_target(file_path: Path, target: str, own_anchors: frozenset[str]) -> str | None:
    """Return a short problem description, or None if the target is fine."""
    if "#" in target:
        path_part, _, anchor_part = target.partition("#")
    else:
        path_part, anchor_part = target, ""

    if path_part == "":
        if anchor_part and anchor_part not in own_anchors:
            return "anchor not found"
        return None

    resolved = _resolve_path_part(file_path, path_part)
    if not resolved.exists():
        return "file not found"

    if anchor_part and resolved.is_file() and resolved.suffix.lower() == ".md":
        if anchor_part not in _anchors_for_file(resolved):
            return "anchor not found"

    return None


def _check_links_in_file(rel_path: str) -> list[str]:
    file_path = REPO_ROOT / rel_path
    raw_lines = file_path.read_text(encoding="utf-8").splitlines()
    fence_blanked = _blank_fences(raw_lines)
    link_lines = [_INLINE_CODE_RE.sub("", line) for line in fence_blanked]
    own_anchors = _anchors_for_file(file_path.resolve())

    errors: list[str] = []
    for lineno, line in enumerate(link_lines, start=1):
        for raw_target in _extract_raw_targets(line):
            target = _clean_target(raw_target)
            if target is None:
                continue
            problem = _check_target(file_path, target, own_anchors)
            if problem is not None:
                errors.append(f"{rel_path}:{lineno}: {target} ({problem})")
    return errors


@pytest.mark.parametrize("rel_path", _discover_doc_files())
def test_relative_links_resolve(rel_path: str) -> None:
    errors = _check_links_in_file(rel_path)
    assert not errors, "broken relative link(s):\n" + "\n".join(errors)


def _docs_index_pages() -> list[str]:
    """Every ``docs/*.md``, ``docs/paths/*.md`` and ``docs/contrib/*.md`` file,
    except the index itself.

    This is the set ``docs/README.md`` is required to link: a new page
    dropped into any of these directories without an entry there fails
    ``test_docs_index_links_every_page`` instead of going unnoticed.
    """
    base = REPO_ROOT / "docs"
    found = [p for p in base.glob("*.md") if p.name != "README.md"]
    found.extend((base / "paths").glob("*.md"))
    found.extend((base / "contrib").glob("*.md"))
    return sorted(p.relative_to(REPO_ROOT).as_posix() for p in found)


def test_docs_index_links_every_page() -> None:
    """``docs/README.md`` links every page under ``docs/`` and ``docs/paths/``."""
    index_path = REPO_ROOT / "docs" / "README.md"
    raw_lines = index_path.read_text(encoding="utf-8").splitlines()
    fence_blanked = _blank_fences(raw_lines)

    linked: set[Path] = set()
    for line in fence_blanked:
        line = _INLINE_CODE_RE.sub("", line)
        for raw_target in _extract_raw_targets(line):
            target = _clean_target(raw_target)
            if target is None:
                continue
            path_part = target.split("#", 1)[0]
            if not path_part:
                continue
            resolved = _resolve_path_part(index_path, path_part)
            if resolved.suffix.lower() == ".md" and resolved.is_file():
                linked.add(resolved.resolve())

    missing = [
        rel_path
        for rel_path in _docs_index_pages()
        if (REPO_ROOT / rel_path).resolve() not in linked
    ]
    assert not missing, "docs/README.md does not link: " + ", ".join(missing)


_README_MAX_LINES = 130


def test_readme_is_short() -> None:
    """``README.md`` stays short enough to read in one sitting.

    The front page is a pitch, not a manual -- the rest of the detail lives
    under ``docs/``. A 130-line cap keeps that true as sections are added or
    edited; a change that needs more room trims an existing section instead
    of growing the file.
    """
    readme_path = REPO_ROOT / "README.md"
    line_count = len(readme_path.read_text(encoding="utf-8").splitlines())
    assert line_count <= _README_MAX_LINES, (
        f"README.md has {line_count} lines, more than the {_README_MAX_LINES}-line limit"
    )
