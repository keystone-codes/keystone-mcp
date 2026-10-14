"""AST helpers for built-in admin tool error code contracts."""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SRC_ROOT = REPO_ROOT / "src"

_DIRECTORY_ERROR_MODULES = (
    "keystone_mcp.user_directory.errors",
    "keystone_mcp.users.errors",
    "keystone_mcp.user_directory.http",
)

_READ_PATH_DIRECTORY_CODES = frozenset(
    {
        "catalog_unavailable",
        "catalog_timeout",
        "revision_unavailable",
        "circuit_open",
    }
)

_ADAPTER_BY_FAMILY: dict[str, tuple[str, str | None]] = {
    "users": ("keystone_mcp.adapters.users_admin", "USERS_ADMIN_ERROR_CODES"),
    "service_accounts": (
        "keystone_mcp.adapters.service_accounts_admin",
        "SERVICE_ACCOUNTS_ADMIN_ERROR_CODES",
    ),
    "api_keys": ("keystone_mcp.adapters.api_keys_admin", "API_KEYS_ADMIN_ERROR_CODES"),
    "policy": ("keystone_mcp.adapters.policy_admin", "POLICY_ADMIN_ERROR_CODES"),
}


def _resolve_string(node: ast.AST | None, constants: dict[str, str]) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def _module_constants(tree: ast.Module) -> dict[str, str]:
    constants: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                value = _resolve_string(node.value, constants)
                if value is not None:
                    constants[target.id] = value
    return constants


class _ErrorCodeVisitor(ast.NodeVisitor):
    def __init__(self, constants: dict[str, str]) -> None:
        self.constants = constants
        self.codes: set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        for keyword in node.keywords:
            if keyword.arg == "code":
                value = _resolve_string(keyword.value, self.constants)
                if value:
                    self.codes.add(value)
        if isinstance(node.func, ast.Name) and node.func.id in (
            "UsersError",
            "UserDirectoryUnavailableError",
        ):
            for keyword in node.keywords:
                if keyword.arg == "code":
                    value = _resolve_string(keyword.value, self.constants)
                    if value:
                        self.codes.add(value)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        for key_node, value_node in zip(node.keys, node.values, strict=False):
            key = _resolve_string(key_node, self.constants)
            if key == "code":
                value = _resolve_string(value_node, self.constants)
                if value:
                    self.codes.add(value)
        self.generic_visit(node)


def collect_error_codes_from_source(text: str) -> set[str]:
    tree = ast.parse(text)
    constants = _module_constants(tree)
    visitor = _ErrorCodeVisitor(constants)
    visitor.visit(tree)
    return visitor.codes


def collect_error_codes_from_path(path: Path) -> set[str]:
    return collect_error_codes_from_source(path.read_text(encoding="utf-8"))


def adapter_module_path(family: str) -> Path:
    module_name, _ = _ADAPTER_BY_FAMILY[family]
    rel = module_name.removeprefix("keystone_mcp.").replace(".", "/") + ".py"
    return SRC_ROOT / "keystone_mcp" / rel


def collect_adapter_literal_codes(family: str, *, src_root: Path = SRC_ROOT) -> set[str]:
    module_name, _ = _ADAPTER_BY_FAMILY[family]
    rel = module_name.removeprefix("keystone_mcp.").replace(".", "/") + ".py"
    path = src_root / "keystone_mcp" / rel
    return collect_error_codes_from_path(path)


def collect_directory_error_codes(*, src_root: Path = SRC_ROOT) -> set[str]:
    codes: set[str] = set()
    for module_name in _DIRECTORY_ERROR_MODULES:
        rel = module_name.removeprefix("keystone_mcp.").replace(".", "/") + ".py"
        path = src_root / "keystone_mcp" / rel
        if path.is_file():
            codes |= collect_error_codes_from_path(path)
    return codes


def directory_codes_for_family(family: str, *, src_root: Path = SRC_ROOT) -> set[str]:
    if family == "policy":
        return set()
    return collect_directory_error_codes(src_root=src_root) - _READ_PATH_DIRECTORY_CODES


def adapter_error_codes_from_ast(family: str, *, src_root: Path = SRC_ROOT) -> frozenset[str]:
    literals = collect_adapter_literal_codes(family, src_root=src_root)
    if family == "policy":
        return frozenset(literals)
    return frozenset(
        literals | directory_codes_for_family(family, src_root=src_root) | {"forbidden"}
    )


def load_adapter_constants(family: str) -> frozenset[str] | None:
    module_name, constant_name = _ADAPTER_BY_FAMILY[family]
    if constant_name is None:
        return None
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError:
        return None
    value = getattr(module, constant_name, None)
    if isinstance(value, frozenset):
        return value
    return None


def adapter_error_codes(family: str, *, src_root: Path = SRC_ROOT) -> frozenset[str]:
    constants = load_adapter_constants(family)
    if constants is not None:
        return constants
    return adapter_error_codes_from_ast(family, src_root=src_root)


def assert_constants_cover_ast(family: str, *, src_root: Path = SRC_ROOT) -> None:
    constants = load_adapter_constants(family)
    assert constants is not None, f"missing error code constant for {family}"
    expected = adapter_error_codes_from_ast(family, src_root=src_root)
    missing = expected - constants
    assert not missing, f"{family} error code constant missing: {sorted(missing)}"
