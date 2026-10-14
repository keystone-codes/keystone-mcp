"""Private fastmcp/mcp imports stay in the approved modules."""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src" / "keystone_mcp"

ALLOWED_MODULES = frozenset(
    {
        "router/upstream_call.py",
        "router/upstream_content.py",
        "router/proxy_components.py",
        "surface/client_sessions.py",
        "server.py",
    }
)


def _type_checking_ranges(tree: ast.AST) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.If) and isinstance(node.test, ast.Name):
            if node.test.id == "TYPE_CHECKING":
                start = node.lineno
                end = max(getattr(n, "lineno", start) for n in ast.walk(node))
                ranges.append((start, end))
    return ranges


def _in_type_checking(lineno: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= lineno <= end for start, end in ranges)


def _private_runtime_imports(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    tc_ranges = _type_checking_ranges(tree)
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.module is None:
            continue
        if _in_type_checking(node.lineno, tc_ranges):
            continue
        module = node.module
        if not (module.startswith("fastmcp") or module.startswith("mcp")):
            continue
        if "._" in module:
            found.append((node.lineno, f"from {module!r}"))
        for alias in node.names:
            if alias.name.startswith("_"):
                found.append((node.lineno, f"import {alias.name!r} from {module!r}"))
    return found


def test_private_fastmcp_and_mcp_names_only_in_allowed_modules() -> None:
    violations: list[str] = []
    for path in sorted(SRC_ROOT.rglob("*.py")):
        rel = path.relative_to(SRC_ROOT).as_posix()
        for lineno, detail in _private_runtime_imports(path):
            if rel not in ALLOWED_MODULES:
                violations.append(f"{rel}:{lineno}: {detail}")
    assert not violations, "private fastmcp/mcp imports outside allowed modules:\n" + "\n".join(
        violations
    )
