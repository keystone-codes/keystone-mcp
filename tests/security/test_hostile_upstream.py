"""SEC-30…SEC-39: hostile upstream MCP servers."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.client.elicitation import ElicitResult
from fastmcp.exceptions import ToolError
from tests.security.helpers import obtain_bearer_token
from tests.security.hostile_upstream import poll_healthz_while

from keystone_mcp.router.stdio_process import StdioUpstreamProcess

pytestmark = pytest.mark.security

GIANT_STDERR = str(Path(__file__).resolve().parents[1] / "support" / "giant_stderr_line_upstream.py")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hostile_attacker_stand",
    ["bad_tool_names", "redos_schema", "deep_schema", "external_ref"],
    indirect=True,
)
async def test_hostile_upstream_catalog_attacks_keep_process_healthy(hostile_attacker_stand):
    stand, mode = hostile_attacker_stand
    token = await obtain_bearer_token(stand, email="member@sec.test")
    transport = stand.mcp_transport(token)

    async def list_tools():
        async with Client(transport) as client:
            await client.list_tools()

    await poll_healthz_while(stand.app, list_tools(), max_latency=1.0)


@pytest.mark.asyncio
@pytest.mark.parametrize("hostile_attacker_stand", ["bad_tool_names"], indirect=True)
async def test_hostile_upstream_builtin_tools_not_shadowed(hostile_attacker_stand):
    stand, _mode = hostile_attacker_stand
    token = await obtain_bearer_token(stand, email="admin@sec.test")
    transport = stand.mcp_transport(token)
    async with Client(transport) as client:
        tools = await client.list_tools()
        names = {t.name for t in tools}
        assert "users_add" in names
        assert "hello_greet" in names


@pytest.mark.asyncio
@pytest.mark.parametrize("hostile_attacker_stand", ["giant_response"], indirect=True)
async def test_hostile_upstream_giant_response_rejected(hostile_attacker_stand):
    stand, _mode = hostile_attacker_stand
    token = await obtain_bearer_token(stand, email="member@sec.test")
    transport = stand.mcp_transport(token)
    async with Client(transport) as client:
        tools = await client.list_tools()
        published = next(t for t in tools if t.name.endswith("_big"))
        with pytest.raises((ToolError, Exception)):
            await client.call_tool(published.name, {})


@pytest.mark.asyncio
@pytest.mark.parametrize("hostile_attacker_stand", ["input_required_loop"], indirect=True)
async def test_hostile_upstream_input_required_capped(hostile_attacker_stand):
    stand, _mode = hostile_attacker_stand
    token = await obtain_bearer_token(stand, email="member@sec.test")
    transport = stand.mcp_transport(token)

    async def elicitation_handler(message, response_type, params, _context):
        return ElicitResult(action="accept", content={"ok": True})

    async with Client(transport, elicitation_handler=elicitation_handler) as client:
        tools = await client.list_tools()
        ask = next(t for t in tools if "ask" in t.name)
        with pytest.raises((ToolError, Exception)):
            await client.call_tool(ask.name, {})


@pytest.mark.asyncio
@pytest.mark.parametrize("hostile_attacker_stand", ["resource_hijack"], indirect=True)
async def test_hostile_upstream_resource_template_hijack_blocked(hostile_attacker_stand):
    stand, _mode = hostile_attacker_stand
    token = await obtain_bearer_token(stand, email="member@sec.test")
    transport = stand.mcp_transport(token)
    async with Client(transport) as client:
        templates = await client.list_resource_templates()
        uris = [t.uriTemplate for t in templates]
        assert not any("other-upstream" in u for u in uris)


@pytest.mark.asyncio
@pytest.mark.parametrize("hostile_attacker_stand", ["meta_injection"], indirect=True)
async def test_hostile_upstream_meta_keys_stripped(hostile_attacker_stand):
    stand, _mode = hostile_attacker_stand
    token = await obtain_bearer_token(stand, email="member@sec.test")
    transport = stand.mcp_transport(token)
    async with Client(transport) as client:
        tools = await client.list_tools()
        tool = next(t for t in tools if t.name.endswith("_meta"))
        result = await client.call_tool(tool.name, {})
        blob = str(result.content) + str(getattr(result, "structured_content", ""))
        assert "keystone-mcp" not in blob


@pytest.mark.asyncio
@pytest.mark.parametrize("hostile_attacker_stand", ["list_changed_flood"], indirect=True)
async def test_hostile_upstream_list_changed_flood_keeps_healthz(hostile_attacker_stand):
    stand, _mode = hostile_attacker_stand
    token = await obtain_bearer_token(stand, email="member@sec.test")
    transport = stand.mcp_transport(token)

    async def hold_open_session() -> None:
        async with Client(transport) as client:
            await client.list_tools()
            await asyncio.sleep(2.5)

    await poll_healthz_while(stand.app, hold_open_session(), max_latency=1.0)


@pytest.mark.asyncio
@pytest.mark.parametrize("hostile_attacker_stand", ["header_echo"], indirect=True)
async def test_hostile_upstream_does_not_see_client_secrets(hostile_attacker_stand):
    stand, _mode = hostile_attacker_stand
    token = await obtain_bearer_token(stand, email="member@sec.test")
    extra = {
        "Authorization": "Bearer stolen",
        "Cookie": "session=evil",
        "X-Keystone-Identity": "other-upstream",
    }
    transport = stand.mcp_transport(token, extra_headers=extra)
    async with Client(transport) as client:
        tools = await client.list_tools()
        who = next(t for t in tools if t.name.endswith("_whoami"))
        await client.call_tool(who.name, {})
    headers = stand.observed.get("call_headers") or stand.observed.get("headers") or {}
    assert headers.get("authorization") not in ("Bearer stolen", "bearer stolen")
    assert "cookie" not in headers


@pytest.mark.asyncio
async def test_hostile_stdio_giant_stderr_survives_supervision():
    proc = StdioUpstreamProcess(
        namespace="hostile",
        command=sys.executable,
        args=[GIANT_STDERR],
        env={},
        cwd=None,
        init_timeout=15,
    )
    try:
        assert await proc.start(wait=15) is True
        async with proc.client() as client:
            result = await client.call_tool("pid", {})
            assert result.content[0].text.isdigit()
    finally:
        await proc.stop()
