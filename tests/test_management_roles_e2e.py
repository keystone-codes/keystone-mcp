"""Management-role refusals over MCP."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from httpx2 import ASGITransport, AsyncClient
from mcp.server.auth.provider import AccessToken

import keystone_mcp.server as server_module
from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import bootstrap_platform, build_server
from support.oauth_harness import BASE_URL
from support.test_env import require_redis_url, users_revision_key

POLICY = """\
version: "mgmt-e2e"
default_deny: true
roles:
  administrator: {allow: ["*"]}
  owner: {allow: ["*"]}
  hr: {allow: ["users_*"]}
  member: {allow: ["docs_read"]}
requires_human_identity: []
critical_tools: []
"""


@pytest.fixture
async def hr_stack(tmp_path: Path):
    redis_url = os.environ.get("KEYSTONE_MCP_REDIS_URL")
    if not redis_url:
        require_redis_url()

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(POLICY, encoding="utf-8")
    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        redis_url=redis_url,
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/users.db",
        users_redis_revision_key=f"{users_revision_key('mgmt-e2e')}:{uuid4().hex}",
    )
    oauth_store = InMemoryOAuthStore()
    mcp, registry, _oauth, upstreams, policy_manager, observability, _rec = build_server(
        settings=settings,
        oauth_store=oauth_store,
    )
    registry.add_route("docs_read", StubAdapter(), mode="live")
    users_store = server_module._users_store_holder["store"]
    await bootstrap_platform(
        upstreams,
        registry,
        settings,
        policy_manager,
        observability=observability,
        users_store=users_store,
    )
    await users_store.create_user(
        email="hr@example.com",
        full_name="HR",
        roles=["hr"],
        note=None,
        created_by="system:test",
        allowed_roles=None,
    )
    await users_store.create_user(
        email="admin@example.com",
        full_name="Admin",
        roles=["administrator"],
        note=None,
        created_by="system:test",
        allowed_roles=None,
    )
    token = AccessToken(
        token="hr-interactive-token",
        client_id="test-client",
        scopes=[],
        expires_at=None,
        resource=None,
        claims={"interactive": True, "sub": "hr@example.com", "email": "hr@example.com"},
    )
    await oauth_store.put_access_token(token)
    http_app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(http_app):
        transport = StreamableHttpTransport(
            settings.transport_url,
            auth=token.token,
            httpx_client_factory=lambda **kw: AsyncClient(
                transport=ASGITransport(app=http_app),
                base_url=BASE_URL,
                **kw,
            ),
        )
        async with Client(transport) as client:
            yield client


@pytest.mark.asyncio
async def test_hr_cannot_touch_administrators_over_mcp(hr_stack) -> None:
    client = hr_stack
    block = await client.call_tool(
        "users_block", {"email": "admin@example.com"}, raise_on_error=False
    )
    assert block.structured_content["code"] == "forbidden"
    grant = await client.call_tool(
        "users_grant_role",
        {"email": "hr@example.com", "role": "owner"},
        raise_on_error=False,
    )
    assert grant.structured_content["code"] == "forbidden"
    add = await client.call_tool(
        "users_add",
        {"email": "new@example.com", "full_name": "New", "roles": ["member"]},
        raise_on_error=False,
    )
    assert add.structured_content["state"] == "done"
