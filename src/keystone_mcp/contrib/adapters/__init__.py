"""Reference adapters for forks.

Not registered by Keystone-MCP; a fork registers a route with one of them as
the target. Not covered by docs/compatibility.md.
"""

from keystone_mcp.contrib.adapters.external_http import ExternalHttpAdapter
from keystone_mcp.contrib.adapters.webhook import WebhookAdapter, WebhookSettings

__all__ = [
    "WebhookAdapter",
    "WebhookSettings",
    "ExternalHttpAdapter",
]
