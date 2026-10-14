"""AST-based extraction of ``KEYSTONE_MCP_*`` variable names from source."""

from __future__ import annotations

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SRC_ROOT = REPO_ROOT / "src" / "keystone_mcp"

ENV_EXAMPLE_VARIABLE_PATTERN = re.compile(
    r"^\s*#?\s*(KEYSTONE_MCP_[A-Z0-9_]+)=",
    re.MULTILINE,
)

DOCS_VARIABLE_PATTERN = re.compile(
    r"^\|\s*`(KEYSTONE_MCP_[A-Z0-9_]+)`\s*\|",
    re.MULTILINE,
)

CONTRIB_ROOT = SRC_ROOT / "contrib"


def _is_contrib_path(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False
    return bool(rel.parts) and rel.parts[0] == "contrib"


ENV_LITERAL_EXEMPTIONS: dict[str, str] = {
    "KEYSTONE_MCP_UPSTREAM_": "prefix required for registry bearer_env names",
    "KEYSTONE_MCP_CONTRIB_": "contrib namespace",
    "KEYSTONE_MCP_": "own prefix constant in the env-file loader",
}

NOT_IN_ENV_EXAMPLE: dict[str, str] = {
    "KEYSTONE_MCP_ENV_FILE": "selects the file itself; set it in the process environment",
}

_ENV_VAR_NAME = re.compile(r"^KEYSTONE_MCP_[A-Z0-9_]+$")


def _is_env_reader(func: ast.AST) -> bool:
    if isinstance(func, ast.Name) and func.id.startswith("_env"):
        return True
    if isinstance(func, ast.Attribute) and func.attr == "getenv":
        return isinstance(func.value, ast.Name) and func.value.id == "os"
    if isinstance(func, ast.Attribute) and func.attr == "get":
        if isinstance(func.value, ast.Attribute) and func.value.attr == "environ":
            return True
        if isinstance(func.value, ast.Name) and func.value.id == "environ":
            return True
    return False


def _resolve_string(node: ast.AST | None, constants: dict[str, str]) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


class _EnvReadVisitor(ast.NodeVisitor):
    def __init__(self, constants: dict[str, str]) -> None:
        self.constants = constants
        self.reads: set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        if _is_env_reader(node.func):
            if node.args:
                name = _resolve_string(node.args[0], self.constants)
                if name and _ENV_VAR_NAME.match(name):
                    self.reads.add(name)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        value = node.value
        is_environ = False
        if isinstance(value, ast.Attribute) and value.attr == "environ":
            is_environ = True
        if isinstance(value, ast.Name) and value.id == "environ":
            is_environ = True
        if is_environ:
            name = _resolve_string(node.slice, self.constants)
            if name and _ENV_VAR_NAME.match(name):
                self.reads.add(name)
        self.generic_visit(node)


def _module_constants(tree: ast.Module) -> dict[str, str]:
    constants: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            value = _resolve_string(node.value, constants)
            if value is not None:
                constants[node.targets[0].id] = value
    return constants


def reads_in_source(text: str) -> set[str]:
    tree = ast.parse(text)
    constants = _module_constants(tree)
    visitor = _EnvReadVisitor(constants)
    visitor.visit(tree)
    return visitor.reads


def _secret_file_variables() -> set[str]:
    config_path = SRC_ROOT / "config.py"
    tree = ast.parse(config_path.read_text(encoding="utf-8"))
    def _tuple_from(node: ast.AST | None) -> ast.Tuple | None:
        if isinstance(node, ast.Tuple):
            return node
        return None

    for node in tree.body:
        value_node: ast.AST | None = None
        target_name: str | None = None
        if isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                target_name = node.targets[0].id
                value_node = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_name = node.target.id
            value_node = node.value
        if target_name != "SECRET_VARIABLES":
            continue
        tuple_node = _tuple_from(value_node)
        if tuple_node is None:
            continue
        names: set[str] = set()
        for elt in tuple_node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                names.add(f"{elt.value}_FILE")
        return names
    return set()


def code_variables(root: Path = SRC_ROOT) -> set[str]:
    names: set[str] = set()
    for path in root.rglob("*.py"):
        if _is_contrib_path(path, root):
            continue
        names.update(reads_in_source(path.read_text(encoding="utf-8")))
    names.update(_secret_file_variables())
    return names


def env_literals(root: Path = SRC_ROOT) -> list[tuple[Path, int, str]]:
    found: list[tuple[Path, int, str]] = []
    for path in root.rglob("*.py"):
        if _is_contrib_path(path, root):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if _ENV_VAR_NAME.match(node.value):
                    found.append((path, node.lineno, node.value))
    return found


def is_exempt_literal(name: str, *, removed_names: set[str] | None = None) -> bool:
    if removed_names is None:
        from keystone_mcp.config import REMOVED_VARIABLES

        removed_names = set(REMOVED_VARIABLES)
    if name in removed_names:
        return True
    for key, _reason in ENV_LITERAL_EXEMPTIONS.items():
        if key.endswith("_"):
            if name.startswith(key):
                return True
        elif name == key:
            return True
    return False


def contrib_variables() -> set[str]:
    names: set[str] = set()
    for path in CONTRIB_ROOT.rglob("*.py"):
        names.update(reads_in_source(path.read_text(encoding="utf-8")))
    return names


def contrib_doc_variables(root: Path | None = None) -> set[str]:
    docs_root = root if root is not None else REPO_ROOT / "docs" / "contrib"
    names: set[str] = set()
    for path in docs_root.glob("*.md"):
        text = path.read_text(encoding="utf-8")
        names.update(DOCS_VARIABLE_PATTERN.findall(text))
    return names


def env_example_variables(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return set(ENV_EXAMPLE_VARIABLE_PATTERN.findall(text))


def environment_md_variables(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return set(DOCS_VARIABLE_PATTERN.findall(text))
