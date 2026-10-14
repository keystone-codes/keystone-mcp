"""The server's own (non-proxied) tool routes."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from keystone_mcp.catalog.builtin import register_catalog

__all__ = ["register_catalog"]


def __getattr__(name: str) -> object:
    if name == "register_catalog":
        from keystone_mcp.catalog.builtin import register_catalog as _register_catalog

        return _register_catalog
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
