"""Published tool family labels for metrics aggregation."""

from __future__ import annotations


def tool_family(tool_name: str) -> str:
    """Derive a coarse family from the published tool name."""
    if not tool_name:
        return "list_tools"
    if "_" not in tool_name:
        return tool_name
    return tool_name.split("_", 1)[0]
