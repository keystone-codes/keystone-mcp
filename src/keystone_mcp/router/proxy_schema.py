"""Deployment patches for upstream MCP tool input schemas.

Keystone discovers a proxied tool's ``inputSchema`` from the upstream's
``list_tools()``. When an upstream advertises a schema that is behind its own
runtime (a published image lagging the deployed code, or a framework that omits
optional parameters), a deployment can declare the missing properties here so
MCP clients see the full contract without waiting on the upstream.

This is deployment configuration, not core behaviour: the built-in table is
empty and patches are read from the JSON file named by
``KEYSTONE_MCP_PROXY_SCHEMA_PATCHES`` (unset means "no patches").

File format — namespace, then upstream tool name, then the properties to merge
into that tool's ``inputSchema.properties``. Each property maps to a JSON Schema
fragment that is used verbatim (deep-copied per call), so anything valid in a
schema property works: ``type``, ``anyOf``, ``default``, ``description``,
``enum``, and so on::

    {
      "<namespace>": {
        "<upstream_tool_name>": {
          "<property_name>": {
            "anyOf": [{"type": "boolean"}, {"type": "null"}],
            "default": null
          },
          "<other_property>": {"type": "integer", "description": "page size"}
        }
      }
    }

Merging is additive and last-writer-wins per property: a patched property
replaces one of the same name in the upstream schema; every other property, and
the schema's ``required`` list, is left untouched. A patch for a tool the
upstream does not expose is simply never applied.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

# (namespace, upstream_tool_name) -> {property_name: JSON Schema fragment}
PatchTable = dict[tuple[str, str], dict[str, dict[str, Any]]]

# Core ships no patches; a deployment supplies them via
# KEYSTONE_MCP_PROXY_SCHEMA_PATCHES.
PROXY_SCHEMA_PROPERTY_PATCHES: PatchTable = {}


class ProxySchemaPatchError(ValueError):
    """Raised when the proxy schema patch file is missing or malformed."""


def load_proxy_schema_patches(path: str | Path) -> PatchTable:
    """Read a patch file into the ``(namespace, tool) -> properties`` table.

    An empty path yields an empty table. Anything that does not match the
    documented shape raises :class:`ProxySchemaPatchError` so a deployment
    typo fails at startup rather than silently publishing a thin schema.
    """
    raw_path = str(path).strip()
    if not raw_path:
        return {}

    file_path = Path(raw_path)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProxySchemaPatchError(
            f"proxy schema patch file cannot be read: {raw_path}: {exc}"
        ) from exc

    return parse_proxy_schema_patches(raw, source=raw_path)


def parse_proxy_schema_patches(raw: str, *, source: str = "<string>") -> PatchTable:
    """Parse patch-file JSON text into the flat patch table."""
    if not raw.strip():
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProxySchemaPatchError(
            f"proxy schema patch file is not valid JSON: {source}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise ProxySchemaPatchError(
            f"proxy schema patch file must be a JSON object keyed by namespace: {source}"
        )

    table: PatchTable = {}
    for namespace, tools in payload.items():
        if not isinstance(tools, dict):
            raise ProxySchemaPatchError(
                f"{source}: namespace {namespace!r} must map to an object of tool names"
            )
        for tool_name, properties in tools.items():
            if not isinstance(properties, dict):
                raise ProxySchemaPatchError(
                    f"{source}: {namespace}.{tool_name} must map to an object of property names"
                )
            for property_name, fragment in properties.items():
                if not isinstance(fragment, dict):
                    raise ProxySchemaPatchError(
                        f"{source}: {namespace}.{tool_name}.{property_name} must be a "
                        f"JSON Schema fragment object; got {type(fragment).__name__}"
                    )
            table[(str(namespace), str(tool_name))] = {
                str(name): fragment for name, fragment in properties.items()
            }
    return table


def apply_proxy_schema_patches(
    namespace: str,
    tool_name: str,
    input_schema: dict[str, Any] | None,
    *,
    patches: PatchTable | None = None,
) -> dict[str, Any] | None:
    """Merge deployment property patches into an upstream tool inputSchema.

    Returns *input_schema* unchanged (same object) when no patch applies.
    """
    table = PROXY_SCHEMA_PROPERTY_PATCHES if patches is None else patches
    patch = table.get((namespace, tool_name))
    if not patch:
        return input_schema

    merged: dict[str, Any] = copy.deepcopy(input_schema) if input_schema else {"type": "object"}
    merged.setdefault("type", "object")
    properties = merged.setdefault("properties", {})
    if not isinstance(properties, dict):
        properties = {}
        merged["properties"] = properties
    for key, spec in patch.items():
        properties[key] = copy.deepcopy(spec)
    return merged
