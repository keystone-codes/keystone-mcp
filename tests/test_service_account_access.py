"""RBAC and upstream headers for service account identities."""

from __future__ import annotations

import os
import time
from pathlib import Path
from uuid import uuid4

import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from httpx2 import ASGITransport, AsyncClient
from mcp.server.auth.provider import AccessToken

import keystone_mcp.server as server_module
from conftest import BASE_URL
from keystone_mcp.adapters.base import Pattern
from keystone_mcp.adapters.mcp_proxy import McpProxyAdapter
from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.identity import SUBJECT_HEADER, SUBJECT_TYPE_HEADER, VerifiedIdentity
from keystone_mcp.router.context import RouteContext
from keystone_mcp.router.route import Route
from keystone_mcp.server import bootstrap_platform, build_server

SERVICE_TOKEN = "svc-test-access-token"
POLICY = """\
version: "svc-access"
default_deny: true
roles:
  robot:
    allow: ["hello_*"]
requires_human_identity: ["hello_greet"]
critical_tools: []
"""


@pytest.fixture
async def enforce_stack(tmp_path: Path):
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
        redis_url=redis_url,
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/users.db",
        users_redis_revision_key=f"km:users:revision:svc:{uuid4().hex}",
    )
    oauth_store = InMemoryOAuthStore()
    mcp, registry, _oauth, upstreams, policy_manager, observability, _rec = build_server(
        settings=settings,
        oauth_store=oauth_store,
    )
    registry.add_route("hello_search", StubAdapter(), mode="live")
    registry.add_route("hello_greet", StubAdapter(), mode="live")
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
        description="CI bot",
        roles=["robot"],
        created_by="system:test",
    )
    await oauth_store.put_access_token(
        AccessToken(
            token=SERVICE_TOKEN,
            client_id="test-client",
            scopes=[],
            expires_at=int(time.time()) + 3600,
            subject="svc:ci",
            claims={
                "subject": "svc:ci",
                "subject_type": "service",
                "interactive": True,
                "auth_method": "api_key",
            },
        )
    )
    http_app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(http_app):
        transport = StreamableHttpTransport(
            settings.transport_url,
            auth=SERVICE_TOKEN,
            httpx_client_factory=lambda **kw: AsyncClient(
                transport=ASGITransport(app=http_app),
                base_url=BASE_URL,
                **kw,
            ),
        )
        async with Client(transport) as client:
            yield client, users_store, oauth_store, settings, http_app


async def test_service_account_calls_allowed_tool(enforce_stack):
    client, *_rest = enforce_stack
    result = await client.call_tool("hello_search", {})
    assert result.is_error is False


async def test_service_account_refused_on_human_tool_even_if_claim_says_interactive(enforce_stack):
    client, *_rest = enforce_stack
    with pytest.raises(ToolError, match="access denied"):
        await client.call_tool("hello_greet", {})


async def test_blocked_service_account_is_refused(enforce_stack):
    client, store, *_rest = enforce_stack
    await store.update_service_account(name="ci", is_blocked=True, actor="admin")
    with pytest.raises(ToolError, match="access denied"):
        await client.call_tool("hello_search", {})


async def test_subject_type_mismatch_is_refused(enforce_stack):
    _client, _store, oauth_store, settings, http_app = enforce_stack
    await oauth_store.put_access_token(
        AccessToken(
            token="mismatch-token",
            client_id="test-client",
            scopes=[],
            expires_at=int(time.time()) + 3600,
            subject="svc:ci",
            claims={
                "subject": "svc:ci",
                "subject_type": "human",
                "interactive": False,
                "auth_method": "api_key",
            },
        )
    )
    transport = StreamableHttpTransport(
        settings.transport_url,
        auth="mismatch-token",
        httpx_client_factory=lambda **kw: AsyncClient(
            transport=ASGITransport(app=http_app),
            base_url=BASE_URL,
            **kw,
        ),
    )
    async with Client(transport) as mismatch_client:
        with pytest.raises(ToolError, match="access denied"):
            await mismatch_client.call_tool("hello_search", {})


async def test_upstream_receives_subject_headers():
    captured: dict = {}

    def factory(**kwargs):
        captured.update(kwargs)
        downstream = FastMCP("upstream")

        @downstream.tool()
        def whoami() -> str:
            return "ok"

        return Client(downstream)

    adapter = McpProxyAdapter("http://unused", client_factory=factory)
    svc = VerifiedIdentity(
        "svc:ci",
        claims={"subject_type": "service", "auth_method": "api_key"},
        subject_type="service",
    )
    human = VerifiedIdentity(email="person@example.com")
    route = Route(name="whoami", target=adapter, upstream_tool="whoami", mode="live")
    settings = Settings(base_url="http://localhost:8080")
    for identity, expect_email in ((svc, False), (human, True)):
        captured.clear()
        ctx = RouteContext(
            verified_identity=identity,
            task_id="t_hdr",
            canonical_args="{}",
            tool_name="whoami",
            pattern=Pattern.M_B,
            settings=settings,
        )
        await adapter.execute(route, ctx, {}, None)
        headers = {k.lower(): v for k, v in captured["headers"].items()}
        assert headers["x-keystone-subject"] == identity.subject
        assert headers["x-keystone-subject-type"] == identity.subject_type
        if expect_email:
            assert headers.get("x-author-email") == identity.email
        else:
            assert "x-author-email" not in headers


async def test_client_cannot_inject_subject_headers():
    captured: dict = {}

    def factory(**kwargs):
        captured.update(kwargs)
        downstream = FastMCP("upstream")

        @downstream.tool()
        def whoami() -> str:
            return "ok"

        return Client(downstream)

    adapter = McpProxyAdapter(
        "http://unused",
        extra_headers={
            SUBJECT_HEADER: "svc:root",
            SUBJECT_TYPE_HEADER: "service",
        },
        client_factory=factory,
    )
    identity = VerifiedIdentity(
        "svc:ci",
        claims={"subject_type": "service"},
        subject_type="service",
    )
    route = Route(name="whoami", target=adapter, upstream_tool="whoami", mode="live")
    ctx = RouteContext(
        verified_identity=identity,
        task_id="t_inj",
        canonical_args="{}",
        tool_name="whoami",
        pattern=Pattern.M_B,
        settings=Settings(base_url="http://localhost:8080"),
    )
    await adapter.execute(route, ctx, {}, None)
    headers = {k.lower(): v for k, v in captured["headers"].items()}
    assert headers["x-keystone-subject"] == "svc:ci"
