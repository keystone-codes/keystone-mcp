"""Upstream registry field keys accepted by load/validate."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REGISTRY_SOURCES = (
    REPO_ROOT / "src" / "keystone_mcp" / "upstream_registry" / "load.py",
    REPO_ROOT / "src" / "keystone_mcp" / "upstream_registry" / "validate.py",
)

_STDIO_ONLY = frozenset({"command", "args", "env", "cwd"})
_AUTH_FIELDS = frozenset({"bearer_env", "identity_secret_env", "identity_alg"})


def _collect_keys_from_source(text: str) -> set[str]:
    keys: set[str] = set()
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_get = isinstance(func, ast.Attribute) and func.attr == "get"
        if is_get and len(node.args) >= 1:
            key = node.args[0]
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                keys.add(key.value)
        if isinstance(func, ast.Attribute) and func.attr in {"get", "__getitem__"}:
            continue
    for match in re.finditer(r'["\']([a-z_]+)["\']\s+in\s+(?:auth|item|entry)\b', text):
        keys.add(match.group(1))
    return keys


def collect_registry_field_keys(*, src_root: Path | None = None) -> set[str]:
    root = src_root or (REPO_ROOT / "src")
    keys: set[str] = set()
    for rel in (
        "keystone_mcp/upstream_registry/load.py",
        "keystone_mcp/upstream_registry/validate.py",
    ):
        path = root / rel
        if path.is_file():
            keys |= _collect_keys_from_source(path.read_text(encoding="utf-8"))
    keys.discard("entries")
    keys.discard("schema_version")
    keys.discard("auth")
    return keys


def _snapshot_key(field: str) -> str:
    if field in _STDIO_ONLY:
        return f"stdio.{field}"
    if field in _AUTH_FIELDS:
        return f"auth.{field}"
    return field


def _minimal_http_entry(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": "snap",
        "namespace": "snapns",
        "url": "https://example.com/mcp",
        "transport": "http",
    }
    if extra:
        entry.update(extra)
    return entry


def _minimal_stdio_entry(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": "stdio-snap",
        "namespace": "stdio-ns",
        "transport": "stdio",
        "command": "echo",
    }
    if extra:
        entry.update(extra)
    return entry


def _field_required(field: str) -> str:
    if field in {"name", "namespace", "url", "command"}:
        return "yes"
    return "no"


def collect_registry_field_rows() -> dict[str, str]:
    rows: dict[str, str] = {"schema_version": "required=yes"}
    for field in sorted(collect_registry_field_keys()):
        key = _snapshot_key(field)
        rows[key] = f"required={_field_required(field)}"
    return rows
