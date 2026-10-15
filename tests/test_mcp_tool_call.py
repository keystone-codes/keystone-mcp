"""End-to-end MCP tool call over the OAuth connector (deliverable 1).

Connects a real FastMCP client with the bearer token obtained from the full
OAuth flow and calls a tool, proving the connector path works and the verified
identity drives the engine (deterministic task_id). Also asserts an
unauthenticated client is rejected.
"""

from __future__ import annotations

import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from mcp.shared.exceptions import MCPError

from support.oauth_harness import obtain_access_token


async def test_tool_call_over_oauth_bearer(harness):
    from keystone_mcp.adapters.stub import StubAdapter
    from keystone_mcp.router.registry import Param

    # Ephemeral stub route: exercises the OAuth->engine->task_id path over the
    # wire without depending on a live backend (the catalog only ships live tools).
    harness.registry.add_route(
        "ping",
        StubAdapter(),
        params=[Param("value", str, required=False, default=None)],
        description="Test-only stub route.",
    )

    res = await obtain_access_token(harness.client, harness.settings.resource_url)
    token = res["body"]["access_token"]

    transport = StreamableHttpTransport(
        harness.settings.transport_url,
        auth=token,
        httpx_client_factory=harness.mcp_client_factory(),
    )

    async with Client(transport) as client:
        tools = await client.list_tools()
        names = {t.name for t in tools}
        assert "ping" in names
        result = await client.call_tool("ping", {"value": "x"})
        assert result.data["state"] == "done"
        assert result.data["stub"] is True
        assert result.data["task_id"].startswith("t_")


async def test_tool_call_without_token_is_rejected(harness):
    transport = StreamableHttpTransport(
        harness.settings.transport_url,
        httpx_client_factory=harness.mcp_client_factory(),
    )
    with pytest.raises(MCPError, match="error response"):
        async with Client(transport) as client:
            await client.list_tools()
