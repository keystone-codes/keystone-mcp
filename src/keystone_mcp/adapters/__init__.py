"""Router target adapters.

Each adapter talks to one server-side target on behalf of the verified identity:

    stub          canonical status-envelope stub by pattern (default before "live")
    mcp_proxy     downstream MCP server over streamable HTTP (upstream 1:1 proxy)

Reference adapters for forks (``WebhookAdapter``, ``ExternalHttpAdapter``) live
in ``keystone_mcp.contrib.adapters``: see docs/contrib/adapters.md. They are
not part of this package and not covered by docs/compatibility.md.
"""

from keystone_mcp.adapters.base import Adapter, Pattern, stub_response
from keystone_mcp.adapters.mcp_proxy import McpProxyAdapter
from keystone_mcp.adapters.stub import StubAdapter

__all__ = [
    "Adapter",
    "Pattern",
    "stub_response",
    "StubAdapter",
    "McpProxyAdapter",
]
