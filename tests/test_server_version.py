"""MCP initialize reports the Keystone package version in serverInfo."""

from __future__ import annotations

import pytest
from fastmcp import Client

import keystone_mcp
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server


@pytest.mark.asyncio
async def test_initialize_reports_keystone_version() -> None:
    settings = Settings(base_url="http://localhost:8080", refresh_interval_seconds=0)
    mcp, *_rest = build_server(settings=settings)
    async with Client(mcp, mode="legacy") as client:
        result = await client.initialize()
    server_info = getattr(result, "server_info", None) or result.serverInfo
    assert server_info.version == keystone_mcp.__version__
