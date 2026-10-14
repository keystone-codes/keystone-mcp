"""SEC-09: administration tools without appropriate roles."""

from __future__ import annotations

import json

import pytest
from fastmcp import Client
from tests.security.conftest import ADMIN_EMAIL, MEMBER_EMAIL
from tests.security.helpers import obtain_bearer_token

pytestmark = pytest.mark.security


async def test_member_cannot_call_users_add(attacker_stand) -> None:
    token = await obtain_bearer_token(attacker_stand, email=MEMBER_EMAIL)
    transport = attacker_stand.mcp_transport(token)
    async with Client(transport) as mcp:
        result = await mcp.call_tool(
            "users_add",
            {"email": "new@sec.test", "roles": ["member"]},
            raise_on_error=False,
        )
    payload = {}
    if result.content and result.content[0].text:
        try:
            payload = json.loads(result.content[0].text)
        except json.JSONDecodeError:
            payload = {}
    code = (result.structured_content or {}).get("code") or payload.get("code")
    blob = str(result.content).lower()
    assert code in ("forbidden", "not_found") or "forbidden" in blob or "access denied" in blob


async def test_machine_wildcard_role_cannot_mutate_users(attacker_stand) -> None:
    transport = attacker_stand.mcp_transport(attacker_stand.machine_api_key)
    async with Client(transport) as mcp:
        result = await mcp.call_tool(
            "users_add",
            {
                "email": "bot-created@sec.test",
                "full_name": "Bot Created",
                "roles": ["member"],
            },
            raise_on_error=False,
        )
    payload = {}
    if result.content and result.content[0].text:
        try:
            payload = json.loads(result.content[0].text)
        except json.JSONDecodeError:
            payload = {}
    code = (result.structured_content or {}).get("code") or payload.get("code")
    blob = str(result.content).lower()
    assert code in ("forbidden", "not_found") or "forbidden" in blob or "access denied" in blob


async def test_administrator_can_list_users(attacker_stand) -> None:
    token = await obtain_bearer_token(attacker_stand, email=ADMIN_EMAIL)
    transport = attacker_stand.mcp_transport(token)
    async with Client(transport) as mcp:
        result = await mcp.call_tool("users_list", {}, raise_on_error=False)
    assert not result.is_error
