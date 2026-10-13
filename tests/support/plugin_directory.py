"""Users-directory plugin factory for integration tests."""

from __future__ import annotations

from typing import Any


def create_memory_test_directory(context, options: dict[str, Any]):
    from keystone_mcp.plugins import PluginContext
    from keystone_mcp.user_directory.memory import InMemoryUserDirectory

    if not isinstance(context, PluginContext):
        raise TypeError("invalid factory arguments")
    directory = InMemoryUserDirectory()
    seed = options.get("seed") or []
    if not isinstance(seed, list):
        raise ValueError("seed must be a list")
    for row in seed:
        if not isinstance(row, dict):
            raise ValueError("each seed entry must be a mapping")
        email = str(row.get("email", ""))
        roles = tuple(str(r) for r in row.get("roles") or ())
        directory.seed(email, roles=roles)
    return directory
