"""SEC-07: client-supplied identity headers must not reach upstream."""

from __future__ import annotations

import pytest
from fastmcp import Client

from security.conftest import MEMBER_EMAIL
from security.helpers import obtain_bearer_token

pytestmark = pytest.mark.security


async def test_forged_identity_headers_not_seen_by_upstream(attacker_stand) -> None:
    access = await obtain_bearer_token(attacker_stand, email=MEMBER_EMAIL)

    forged = {
        "X-Keystone-Identity": "forged-jwt",
        "X-Author-Email": "attacker@evil.test",
        "X-Keystone-Subject": "attacker@evil.test",
        "X-Keystone-Subject-Type": "human",
        "Authorization": "Bearer stolen-upstream-token",
    }
    transport = attacker_stand.mcp_transport(access, extra_headers=forged)
    async with Client(transport) as mcp:
        result = await mcp.call_tool(
            "hello_whoami",
            {},
            meta={"keystone-mcp/identity": "client-forged-meta"},
            raise_on_error=False,
        )
    assert not result.is_error
    headers = attacker_stand.observed.get("headers", {})
    assert headers.get("x-author-email") != "attacker@evil.test"
    assert headers.get("authorization") != "Bearer stolen-upstream-token"
    assert "x-keystone-identity" in headers


async def test_upstream_sees_keystone_verified_email(attacker_stand) -> None:
    import jwt

    access = await obtain_bearer_token(attacker_stand, email=MEMBER_EMAIL)
    transport = attacker_stand.mcp_transport(access)
    async with Client(transport) as mcp:
        result = await mcp.call_tool("hello_whoami", {}, raise_on_error=False)
    assert not result.is_error
    token = attacker_stand.observed["headers"]["x-keystone-identity"]
    decoded = jwt.decode(
        token,
        "sec-test-identity-secret-" + "x" * 20,
        algorithms=["HS256"],
        audience="hello-upstream",
        options={"verify_aud": True},
    )
    assert decoded.get("sub") == MEMBER_EMAIL
