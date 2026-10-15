"""E2E MCP calls through production HTTP middleware (Host guard, access log)."""

from __future__ import annotations

import logging

import httpx2
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.router.registry import Param
from support.oauth_harness import obtain_access_token

pytestmark = pytest.mark.asyncio


async def test_tool_call_through_production_middleware(production_http_harness):
    production_http_harness.registry.add_route(
        "ping",
        StubAdapter(),
        params=[Param("value", str, required=False, default=None)],
        description="Test-only stub route.",
    )

    res = await obtain_access_token(
        production_http_harness.client, production_http_harness.settings.resource_url
    )
    token = res["body"]["access_token"]

    transport = StreamableHttpTransport(
        production_http_harness.settings.transport_url,
        auth=token,
        httpx_client_factory=production_http_harness.mcp_client_factory(),
    )

    async with Client(transport) as client:
        tools = await client.list_tools()
        names = {t.name for t in tools}
        assert "ping" in names
        result = await client.call_tool("ping", {"value": "x"})
        assert result.data["state"] == "done"


async def test_foreign_host_is_refused_before_mcp(production_http_harness):
    settings = production_http_harness.settings
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=production_http_harness.running.app),
        base_url="http://localhost:8080",
    ) as client:
        response = await client.post(
            settings.http_path,
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            headers={
                "Host": "evil.example",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
    assert response.status_code == 421
    assert "jsonrpc" not in response.text.lower()


async def test_access_log_line_written(production_http_harness, caplog: pytest.LogCaptureFixture):
    access_logger = logging.getLogger("keystone_mcp.access")
    access_logger.addHandler(caplog.handler)
    access_logger.setLevel(logging.INFO)
    caplog.set_level(logging.INFO, logger="keystone_mcp.access")

    production_http_harness.registry.add_route(
        "ping",
        StubAdapter(),
        params=[Param("value", str, required=False, default=None)],
        description="Test-only stub route.",
    )

    res = await obtain_access_token(
        production_http_harness.client, production_http_harness.settings.resource_url
    )
    token = res["body"]["access_token"]

    transport = StreamableHttpTransport(
        production_http_harness.settings.transport_url,
        auth=token,
        httpx_client_factory=production_http_harness.mcp_client_factory(),
    )

    async with Client(transport) as client:
        await client.list_tools()

    access_records = [r for r in caplog.records if r.name == "keystone_mcp.access"]
    assert access_records
    log_blob = "\n".join(record.getMessage() for record in caplog.records)
    assert "Authorization" not in log_blob
