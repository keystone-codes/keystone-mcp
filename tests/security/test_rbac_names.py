"""SEC-08: RBAC bypass via tool-name tricks."""

from __future__ import annotations

import pytest
from fastmcp import Client

from security.conftest import MEMBER_EMAIL
from security.helpers import obtain_bearer_token

pytestmark = pytest.mark.security


@pytest.mark.parametrize(
    "tool_name",
    [
        "users_add",
        "Users_Add",
        " users_add ",
        "users__add",
        "hello_users_add",
        "users_%61dd",
        "users_add%00",
        "users_a?d",
        "users_[a]dd",
    ],
)
async def test_admin_tool_names_are_not_reachable(attacker_stand, tool_name: str) -> None:
    token = await obtain_bearer_token(attacker_stand, email=MEMBER_EMAIL)
    transport = attacker_stand.mcp_transport(token)
    async with Client(transport) as mcp:
        result = await mcp.call_tool(tool_name, {"email": "x@y.z", "role": "member"}, raise_on_error=False)
    assert result.is_error or (
        result.structured_content and result.structured_content.get("code") in ("forbidden", "not_found")
    )


async def test_wildcard_tool_name_does_not_call_real_tool(attacker_stand) -> None:
    token = await obtain_bearer_token(attacker_stand, email=MEMBER_EMAIL)
    transport = attacker_stand.mcp_transport(token)
    async with Client(transport) as mcp:
        result = await mcp.call_tool("*", {}, raise_on_error=False)
    assert result.is_error
