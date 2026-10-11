"""JSON Schema → router Param conversion for upstream tool discovery."""

from __future__ import annotations

from typing import Any

from keystone_mcp.router.registry import Param

_TYPE_MAP: dict[str, type] = {
    "string": str,
    "integer": int,
    "number": float,
    "boolean": bool,
    "object": dict,
    "array": list,
}


def _resolve_json_type(spec: dict[str, Any]) -> str:
    json_type = spec.get("type", "string")
    if isinstance(json_type, list):
        for candidate in json_type:
            if candidate != "null":
                return str(candidate)
        return "string"
    return str(json_type)


def schema_allows_null(spec: dict[str, Any]) -> bool:
    """Return True when the upstream JSON Schema explicitly permits null."""
    any_of = spec.get("anyOf")
    if isinstance(any_of, list):
        for entry in any_of:
            if not isinstance(entry, dict):
                continue
            entry_type = entry.get("type")
            if entry_type == "null":
                return True
            if isinstance(entry_type, list) and "null" in entry_type:
                return True
    json_type = spec.get("type")
    if isinstance(json_type, list) and "null" in json_type:
        return True
    return False


def _collect_anyof_types(any_of: list[Any]) -> tuple[list[type], bool]:
    mapped: list[type] = []
    allows_null = False
    for entry in any_of:
        if not isinstance(entry, dict):
            continue
        entry_type = entry.get("type")
        if entry_type == "null":
            allows_null = True
            continue
        if isinstance(entry_type, list):
            for candidate in entry_type:
                if candidate == "null":
                    allows_null = True
                elif candidate in _TYPE_MAP:
                    mapped.append(_TYPE_MAP[str(candidate)])
            continue
        if entry_type in _TYPE_MAP:
            mapped.append(_TYPE_MAP[str(entry_type)])
    return mapped, allows_null


def _resolve_param_type(spec: dict[str, Any], *, required: bool) -> type:
    """Map one JSON Schema property to a Python type for FastMCP tool signatures."""
    any_of = spec.get("anyOf")
    if isinstance(any_of, list):
        mapped, allows_null = _collect_anyof_types(any_of)
        if mapped:
            base: type = mapped[0]
            for candidate in mapped[1:]:
                base = base | candidate
            return base | None if allows_null or not required else base

    py_type = _TYPE_MAP.get(_resolve_json_type(spec), str)
    if not required or spec.get("default") is None:
        return py_type | None
    return py_type


def schema_to_params(input_schema: dict[str, Any] | None) -> list[Param]:
    """Build router Params from an MCP tool inputSchema."""
    if not input_schema:
        return []
    properties = input_schema.get("properties") or {}
    required = set(input_schema.get("required") or [])
    params: list[Param] = []
    for name, spec in properties.items():
        if not isinstance(spec, dict):
            spec = {}
        is_required = name in required
        allows_null = schema_allows_null(spec)
        py_type = _resolve_param_type(spec, required=is_required)
        params.append(
            Param(
                name=name,
                type=py_type,
                required=is_required,
                # Upstream defaults are not copied: the upstream applies its own
                # when a param is omitted, and omit_implicit_null_args below
                # drops the nulls a client sends for optional fields.
                default=None,
                description=spec.get("description"),
                allows_null=allows_null,
            )
        )
    return params


def omit_implicit_null_args(
    args: dict[str, Any],
    params: list[Param],
) -> dict[str, Any]:
    """Drop null values for optional params unless upstream schema allows null.

      Clients may send explicit ``null`` for omitted optional fields; upstream tools
    that use ``T`` with a default (not ``T | null``) must not receive ``null``.
    """
    allows_null_by_name = {param.name: param.allows_null for param in params}
    return {
        key: value
        for key, value in args.items()
        if value is not None or allows_null_by_name.get(key, False)
    }
