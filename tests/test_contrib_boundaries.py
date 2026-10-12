"""Core code must never import keystone_mcp.contrib.

contrib is reference code for forks: Keystone-MCP registers nothing from it
by itself, and it is not covered by docs/compatibility.md. If a module under
src/keystone_mcp/ outside contrib/ imported from it, an ordinary install
(contrib included, since it ships in the same package) would start depending
on reference code that is allowed to change in a minor release. The reverse
direction (contrib importing core) is fine and expected.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "keystone_mcp"
CONTRIB_ROOT = SRC_ROOT / "contrib"


def _imports_contrib(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "keystone_mcp.contrib" or alias.name.startswith(
                    "keystone_mcp.contrib."
                ):
                    return True
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "keystone_mcp.contrib" or module.startswith("keystone_mcp.contrib."):
                return True
    return False


def _core_modules() -> list[Path]:
    return [
        path
        for path in SRC_ROOT.rglob("*.py")
        if CONTRIB_ROOT not in path.parents and path != CONTRIB_ROOT
    ]


def test_core_never_imports_contrib() -> None:
    offenders = [
        path.relative_to(REPO_ROOT).as_posix() for path in _core_modules() if _imports_contrib(path)
    ]
    assert not offenders, f"core modules import keystone_mcp.contrib: {offenders}"
