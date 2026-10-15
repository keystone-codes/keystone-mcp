"""E2E: service-account API key cannot mutate administration over MCP."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from httpx2 import ASGITransport, AsyncClient

import keystone_mcp.server as server_module
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.catalog.names import MUTATING_ADMIN_TOOL_NAMES
from keystone_mcp.config import Settings
from keystone_mcp.server import bootstrap_platform, build_server
from support.oauth_harness import BASE_URL

POLICY = """\
version: "svc-boundary"
default_deny: true
roles:
  administrator:
    allow: ["*"]
  robot:
    allow: ["*"]
requires_human_identity: []
critical_tools: []
"""

MUTATING_CALLS: tuple[tuple[str, dict], ...] = (
    ("users_add", {"email": "attacker@evil.example", "full_name": "x", "roles": ["administrator"]}),
    ("users_grant_role", {"email": "admin@example.com", "role": "robot"}),
    ("users_block", {"email": "admin@example.com"}),
    ("users_logout", {"email": "admin@example.com"}),
    ("users_export", {"email": "admin@example.com"}),
    ("users_delete", {"email": "admin@example.com"}),
    ("service_accounts_add", {"name": "evil", "roles": ["robot"]}),
    ("service_accounts_update", {"name": "ci", "description": "pwned"}),
    ("api_keys_issue", {"subject": "svc:ci"}),
    ("api_keys_revoke", {"key_id": "00000000-0000-0000-0000-000000000001"}),
    ("policy_role_set", {"role": "robot", "allow": ["*"]}),
)


@pytest.fixture
async def admin_boundary_stack(tmp_path: Path):
    redis_url = os.environ.get("KEYSTONE_MCP_REDIS_URL")
    if not redis_url:
        pytest.skip("KEYSTONE_MCP_REDIS_URL is not set")

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(POLICY, encoding="utf-8")
    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        policy_tools="full",
        redis_url=redis_url,
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/users.db",
        users_redis_revision_key=f"km:users:revision:a01:{uuid4().hex}",
        deployment_profile="local",
    )
    oauth_store = InMemoryOAuthStore()
    mcp, registry, _oauth, upstreams, policy_manager, observability, _rec = build_server(
        settings=settings,
        oauth_store=oauth_store,
    )
    users_store = server_module._users_store_holder["store"]
    await bootstrap_platform(
        upstreams,
        registry,
        settings,
        policy_manager,
        observability=observability,
        users_store=users_store,
    )
    await users_store.create_service_account(
        name="ci",
        description="CI",
        roles=["robot"],
        created_by="system:test",
    )
    issued = await users_store.issue_api_key(
        subject="svc:ci",
        label="ci",
        expires_in_days=30,
        created_by="system:test",
    )
    http_app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(http_app):
        transport = StreamableHttpTransport(
            settings.transport_url,
            auth=issued.key,
            httpx_client_factory=lambda **kw: AsyncClient(
                transport=ASGITransport(app=http_app),
                base_url=BASE_URL,
                **kw,
            ),
        )
        async with Client(transport) as client:
            yield client, users_store


async def test_service_account_key_cannot_change_admin_state(admin_boundary_stack) -> None:
    client, store = admin_boundary_stack
    for name, args in MUTATING_CALLS:
        result = await client.call_tool(name, args, raise_on_error=False)
        payload = result.structured_content or {}
        assert payload.get("state") == "error", name
        assert payload.get("code") == "forbidden", name
    resolved = await store.resolve("attacker@evil.example")
    assert resolved.exists is False


async def test_service_account_key_can_read_admin_lists(admin_boundary_stack) -> None:
    client, _store = admin_boundary_stack
    for name in ("users_list", "service_accounts_list", "api_keys_list", "policy_read"):
        result = await client.call_tool(name, {}, raise_on_error=False)
        payload = result.structured_content or {}
        assert payload.get("state") == "done", name


async def test_service_account_does_not_see_mutating_admin_tools(admin_boundary_stack) -> None:
    client, _store = admin_boundary_stack
    tools = {tool.name for tool in await client.list_tools()}
    assert not (MUTATING_ADMIN_TOOL_NAMES & tools)
    assert "users_list" in tools
