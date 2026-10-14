"""Reject internal labels of the original platform in tracked source and docs."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN: dict[str, str] = {
    r"Model[ -]?M\b": "use 'status envelope'",
    r"\bM[-_][BEDU]\b": "use Pattern.SYNC / CONTINUATION",
    r"\bK[34]\b": "internal label of the original platform",
    r"eph_codec|EPH_PREFIX|\beph:": (
        "the file API was removed in 0.5.0 (file transfer is an upstream service)"
    ),
    r"\bdet_internal\b|DetInternal": "adapter removed in 0.5.0",
    r"chat_attachment|ChatAttachment|CmaSession": "adapter removed in 0.5.0",
    r"\bS2S\b|SYS-scope|OQ-\d|trust_mcp": "internal label",
    r"(?i)\bcontour\b": "use 'deployment'",
    r"(?i)anthropic broker": "internal label",
    r"\bMD-\d+|\bADR-\d+": "internal ticket ids",
    r"doc-ingestion|catalog_advance|mcp-users": "names from the original platform",
    r"(?i)\.xlsx\b|\bExcel\b": "domain of the original platform",
    r"\bintended_project_id\b": "internal label of the original platform",
}

_SKIP_PATHS = frozenset(
    {
        REPO_ROOT / "tests" / "test_no_legacy_terms.py",
        REPO_ROOT / "CHANGELOG.md",
    }
)

_INTERNAL_CARD_ID = re.compile(
    r"\b([ABCDEFGUVXYZ][0-9]{2}|PO[0-9]{1,2}|A[1-6]-[0-9]{1,2}|C2-[0-9])\b"
    r"|finding #|task card|coordinator finding|\bdecision S[0-9]+"
)

_SKIP_SCAN_SUFFIXES = frozenset({".pyc", ".png", ".jpg", ".jpeg", ".gif", ".webp"})

_TEXT_SUFFIXES = frozenset(
    {
        ".py",
        ".md",
        ".yaml",
        ".yml",
        ".json",
        ".example",
        ".toml",
        ".sh",
        "",
    }
)

_ROOT_FILES = (
    "README.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "setup.sh",
    "Dockerfile",
    "pyproject.toml",
)


def _is_text_candidate(path: Path) -> bool:
    if path in _SKIP_PATHS:
        return False
    if path.suffix in _SKIP_SCAN_SUFFIXES:
        return False
    if "internal" in path.parts:
        return False
    if "frozen-baseline" in path.name:
        return False
    name = path.name
    if name.startswith("docker-compose") and name.endswith((".yml", ".yaml")):
        return True
    if name in _ROOT_FILES:
        return True
    return path.suffix in _TEXT_SUFFIXES


def _iter_scan_paths() -> list[Path]:
    roots: list[Path] = [
        REPO_ROOT / "src",
        REPO_ROOT / "tests",
        REPO_ROOT / "docs",
        REPO_ROOT / "examples",
        REPO_ROOT / "config",
        REPO_ROOT / "scripts",
        REPO_ROOT / ".github",
    ]
    paths: list[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.is_file() and _is_text_candidate(path):
                paths.append(path)
    for name in _ROOT_FILES:
        candidate = REPO_ROOT / name
        if candidate.is_file() and _is_text_candidate(candidate):
            paths.append(candidate)
    for candidate in REPO_ROOT.glob("docker-compose*.yml"):
        if candidate.is_file() and _is_text_candidate(candidate):
            paths.append(candidate)
    return sorted(set(paths))


def _scan_file(path: Path, patterns: dict[re.Pattern[str], str]) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    rel = path.relative_to(REPO_ROOT)
    hits: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for regex, reason in patterns.items():
            if regex.search(line):
                match = regex.search(line)
                assert match is not None
                hits.append(f"{rel}:{lineno}: {match.group(0)!r} — {reason}")
    return hits


_COMPILED = {re.compile(p): r for p, r in FORBIDDEN.items()}


def test_no_legacy_terms_in_repository():
    all_hits: list[str] = []
    for path in _iter_scan_paths():
        all_hits.extend(_scan_file(path, _COMPILED))
    if all_hits:
        pytest.fail("\n".join(sorted(all_hits)))


_PATTERN_SAMPLES: list[tuple[str, str]] = [
    (r"Model[ -]?M\b", "Model M"),
    (r"\bM[-_][BEDU]\b", "M_B"),
    (r"\bK[34]\b", "K3"),
    (r"eph_codec|EPH_PREFIX|\beph:", "eph:"),
    (r"\bdet_internal\b|DetInternal", "det_internal"),
    (r"chat_attachment|ChatAttachment|CmaSession", "CmaSession"),
    (r"\bS2S\b|SYS-scope|OQ-\d|trust_mcp", "S2S"),
    (r"(?i)\bcontour\b", "contour"),
    (r"(?i)anthropic broker", "Anthropic broker"),
    (r"\bMD-\d+|\bADR-\d+", "ADR-42"),
    (r"doc-ingestion|catalog_advance|mcp-users", "mcp-users"),
    (r"(?i)\.xlsx\b|\bExcel\b", "Excel"),
    (r"\bintended_project_id\b", "intended_project_id"),
]


def test_forbidden_patterns_compile_and_catch():
    for pattern, sample in _PATTERN_SAMPLES:
        regex = re.compile(pattern)
        assert regex.search(sample), f"pattern {pattern!r} did not match {sample!r}"


def test_no_internal_card_ids_in_public_files():
    hits: list[str] = []
    for path in _iter_scan_paths():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(REPO_ROOT)
        for lineno, line in enumerate(text.splitlines(), start=1):
            match = _INTERNAL_CARD_ID.search(line)
            if match is not None:
                hits.append(f"{rel}:{lineno}: {match.group(0)!r}")
    if hits:
        pytest.fail("\n".join(sorted(hits)))
