"""Router target adapters.

Each adapter talks to one server-side target on behalf of the verified identity:

    stub          canonical Model-M response by pattern (default before "live")
    webhook       async submit to a webhook API + peek + long-poll
    external_http arbitrary external API, GET|POST, identity carried downstream
    file_ref      mint a signed file-download reference (Model M pattern M-D)
    mcp_proxy     downstream MCP server over streamable HTTP (upstream 1:1 proxy)
"""

from keystone_mcp.adapters.base import Adapter, Pattern, stub_response
from keystone_mcp.adapters.external_http import ExternalHttpAdapter
from keystone_mcp.adapters.file_ref import FileRefAdapter
from keystone_mcp.adapters.mcp_proxy import McpProxyAdapter
from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.adapters.webhook import WebhookAdapter

__all__ = [
    "Adapter",
    "Pattern",
    "stub_response",
    "StubAdapter",
    "WebhookAdapter",
    "ExternalHttpAdapter",
    "FileRefAdapter",
    "McpProxyAdapter",
]
