"""The server's own (non-proxied) tool routes."""

from keystone_mcp.catalog.builtin import register_catalog

__all__ = ["register_catalog"]
