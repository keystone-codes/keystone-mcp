"""Bearer API keys for service accounts through the full MCP server."""

from __future__ import annotations

import logging

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from mcp.shared.exceptions import MCPError

from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.users import service
from keystone_mcp.users.db import make_session_factory, session_scope
from support.service_bearer import ADMIN, service_bearer_harness


async def test_service_account_calls_tool_with_bearer_key(tmp_path) -> None:
    async with service_bearer_harness(tmp_path) as harness:
        async with Client(harness.bearer_transport(harness.service_key)) as client:
            result = await client.call_tool_mcp("hello_greet", {"name": "CI"})
        assert result.is_error is False
        assert harness.observed["headers"].get("x-keystone-subject") == "svc:ci"


async def test_service_account_refused_on_human_tool(tmp_path) -> None:
    async with service_bearer_harness(tmp_path) as harness:
        async with Client(harness.bearer_transport(harness.service_key)) as client:
            with pytest.raises(ToolError):
                await client.call_tool("human_only", {})


async def test_revoked_key_stops_immediately(tmp_path) -> None:
    async with service_bearer_harness(tmp_path) as harness:
        route = harness.registry.get("api_keys_revoke")
        engine = RouterEngine(harness.settings)
        await engine.execute(route, {"key_id": harness.key_id}, identity=ADMIN)

        with pytest.raises(MCPError):
            async with Client(harness.bearer_transport(harness.service_key)) as client:
                await client.call_tool("hello_greet", {"name": "CI"})


async def test_blocked_service_account_key_is_refused_even_with_rbac_off(tmp_path) -> None:
    async with service_bearer_harness(tmp_path, rbac_mode="off", block_service=True) as harness:
        with pytest.raises(MCPError):
            async with Client(harness.bearer_transport(harness.service_key)) as client:
                await client.call_tool("hello_greet", {"name": "CI"})


async def test_human_key_is_refused_as_bearer(tmp_path, caplog: pytest.LogCaptureFixture) -> None:
    async with service_bearer_harness(tmp_path) as harness:
        factory = make_session_factory(harness.store._engine)  # noqa: SLF001
        with session_scope(factory) as session:
            service.create_user(
                session,
                email="human@example.com",
                full_name="Human",
                roles=["machine"],
                note=None,
                created_by="test",
                allowed_roles=None,
            )
            row, human_key = service.issue_api_key(
                session,
                subject="human@example.com",
                label="laptop",
                expires_in_days=90,
                created_by="test",
            )
        key_id = row.key_id
        secret = human_key.split("_", 2)[-1]

        caplog.set_level(logging.INFO, logger="keystone_mcp.auth.keystone_oauth_provider")
        with pytest.raises(MCPError):
            async with Client(harness.bearer_transport(human_key)) as client:
                await client.call_tool("hello_greet", {"name": "Human"})

        joined = caplog.text
        assert key_id in joined
        assert secret not in joined


async def test_strict_resource_mode_accepts_service_key(tmp_path) -> None:
    async with service_bearer_harness(tmp_path, require_resource_indicator=True) as harness:
        verified = await harness.oauth.verify_token(harness.service_key)
        assert verified is not None
        async with Client(harness.bearer_transport(harness.service_key)) as client:
            result = await client.call_tool_mcp("hello_greet", {"name": "CI"})
        assert result.is_error is False
