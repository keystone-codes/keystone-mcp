"""Extract Settings environment defaults for contract freeze snapshots."""

from __future__ import annotations

import ast
import dataclasses
import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = REPO_ROOT / "src" / "keystone_mcp" / "config.py"

_MACHINE_SENSITIVE = frozenset(
    {
        "KEYSTONE_MCP_HOST",
        "KEYSTONE_MCP_USERS_DB_URL",
    }
)


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


def _env_call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name) and func.id.startswith("_env"):
        if node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return arg.value
    return None


def _env_name_in_factory(node: ast.AST) -> str | None:
    if isinstance(node, ast.Lambda):
        return _env_name_in_factory(node.body)
    if isinstance(node, ast.Call):
        direct = _env_call_name(node)
        if direct:
            return direct
        if isinstance(node.func, ast.Name) and node.func.id == "_resolve_rbac_mode":
            return "KEYSTONE_MCP_RBAC_MODE"
        for arg in node.args:
            found = _env_name_in_factory(arg)
            if found:
                return found
    return None


def settings_env_bindings(config_text: str | None = None) -> dict[str, str]:
    """Map KEYSTONE_MCP_* variable names to Settings field names."""
    text = config_text if config_text is not None else CONFIG_PATH.read_text(encoding="utf-8")
    tree = ast.parse(text)
    bindings: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "Settings":
            continue
        for item in node.body:
            if not isinstance(item, ast.AnnAssign) or item.value is None:
                continue
            if not isinstance(item.target, ast.Name):
                continue
            field_name = item.target.id
            call = item.value
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
                continue
            if call.func.id != "field":
                continue
            for keyword in call.keywords:
                if keyword.arg != "default_factory":
                    continue
                env_name = _env_name_in_factory(keyword.value)
                if env_name:
                    bindings[env_name] = field_name
    return bindings


def _literal_allowed(annotation: ast.AST | None) -> str | None:
    if annotation is None:
        return None
    if isinstance(annotation, ast.Subscript):
        if isinstance(annotation.value, ast.Name) and annotation.value.id == "Literal":
            values: list[str] = []
            slice_node = annotation.slice
            if isinstance(slice_node, ast.Tuple):
                for elt in slice_node.elts:
                    if isinstance(elt, ast.Constant):
                        values.append(str(elt.value))
            elif isinstance(slice_node, ast.Constant):
                values.append(str(slice_node.value))
            if values:
                return ",".join(values)
    return None


def settings_literal_allowed(config_text: str | None = None) -> dict[str, str]:
    text = config_text if config_text is not None else CONFIG_PATH.read_text(encoding="utf-8")
    tree = ast.parse(text)
    allowed: dict[str, str] = {}
    bindings = settings_env_bindings(text)
    field_to_env = {field: env for env, field in bindings.items()}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "Settings":
            continue
        for item in node.body:
            if not isinstance(item, ast.AnnAssign) or not isinstance(item.target, ast.Name):
                continue
            field_name = item.target.id
            env_name = field_to_env.get(field_name)
            if env_name is None:
                continue
            values = _literal_allowed(item.annotation)
            if values:
                allowed[env_name] = values
    return allowed


def normalize_default(env_name: str, value: object) -> str:
    if env_name in _MACHINE_SENSITIVE:
        return "<machine>"
    if env_name == "KEYSTONE_MCP_BASE_URL" and isinstance(value, str):
        if "localhost" not in value and "127.0.0.1" not in value:
            return "<machine>"
    return repr(value)


def collect_default_rows(
    *, strip_env: bool = True, config_path: Path | None = None
) -> dict[str, str]:
    from keystone_mcp.config import Settings

    path = config_path or CONFIG_PATH
    config_text = path.read_text(encoding="utf-8")

    if strip_env:
        saved = {k: v for k, v in os.environ.items() if k.startswith("KEYSTONE_MCP_")}
        for key in saved:
            del os.environ[key]
    else:
        saved = {}
    try:
        settings = Settings()
        rows: dict[str, str] = {}
        bindings = settings_env_bindings(config_text)
        allowed_map = settings_literal_allowed(config_text)
        fields = {field.name for field in dataclasses.fields(Settings)}
        for env_name, field_name in sorted(bindings.items()):
            if field_name not in fields:
                continue
            value = getattr(settings, field_name)
            attrs = f"default={normalize_default(env_name, value)}"
            if env_name in allowed_map:
                attrs += f" allowed={allowed_map[env_name]}"
            rows[env_name] = attrs
        return rows
    finally:
        for key, value in saved.items():
            os.environ[key] = value
