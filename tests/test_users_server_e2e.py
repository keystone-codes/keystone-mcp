"""Full-stack smoke test: fresh server, administrator seeded, adds a member.

This is the release's readiness criterion in miniature (U05): a server that
has never run before starts against an empty users database, the configured
``KEYSTONE_MCP_SUPERADMIN_EMAIL`` can log in and sees the ``users_*`` tools,
can create a new user with an ordinary role, and that new user cannot see any
``users_*`` tool once they log in themselves.

The shipped default policy (``config/rbac-policy.yaml``) only declares the
``administrator`` role -- the built-in ``member`` example role was removed
when the always-on file tools were gated behind an opt-in variable (see
``a7cccb1``); those file tools and the variable gating them were later
removed outright (0.5.0, Z03). A non-administrator role must still be
declared in the *active* policy for ``users_add
roles=["member"]`` to be accepted (role names are validated against
``RbacPolicyManager.active_policy.role_names``), so this test uses its own
temporary policy file with both roles, plus one harmless extra route that
"member" may reach -- RBAC policy validation otherwise rejects a role whose
allow pattern matches nothing in the live catalog.
"""

from __future__ import annotations

import os
from pathlib import Path

import httpx2
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from httpx2 import ASGITransport, AsyncClient

import keystone_mcp.server as server
from conftest import BASE_URL, obtain_access_token
from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import bootstrap_platform, build_server
from support.login import dev_token_login
from support.test_env import require_redis_url, users_revision_key

VALID_TOKEN = "valid-test-token"
ADMIN_EMAIL = "admin@example.com"
MEMBER_EMAIL = "member@example.com"

POLICY_YAML = """\
version: "u05-server-e2e"
default_deny: true
roles:
  administrator:
    description: "Full access, including user administration."
    allow:
      - "*"
  member:
    description: "Ordinary workspace member; no admin tools."
    allow:
      - "member_probe"
requires_human_identity: []
critical_tools: []
"""


def _mcp_client_factory(app):
    def factory(headers=None, timeout=None, auth=None, **_kw):
        return AsyncClient(
            transport=ASGITransport(app=app),
            base_url=BASE_URL,
            headers=headers,
            timeout=timeout or httpx2.Timeout(30.0),
            auth=auth,
            follow_redirects=True,
        )

    return factory


def _transport_for(app, settings: Settings, token: str) -> StreamableHttpTransport:
    return StreamableHttpTransport(
        settings.transport_url,
        auth=token,
        httpx_client_factory=_mcp_client_factory(app),
    )


async def test_fresh_server_admin_adds_member_who_cannot_see_users_tools(
    tmp_path: Path,
) -> None:
    redis_url = os.environ.get("KEYSTONE_MCP_REDIS_URL")
    if not redis_url:
        require_redis_url()

    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(POLICY_YAML, encoding="utf-8")

    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        redis_url=redis_url,
        rbac_audit_subject_salt="test-salt",
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/keystone-users.db",
        superadmin_email=ADMIN_EMAIL,
        users_redis_revision_key=users_revision_key("e2e"),
    )

    _login = dev_token_login({VALID_TOKEN})
    oauth_store = InMemoryOAuthStore()

    mcp, registry, _oauth, upstreams, policy_manager, observability, _reconciler = build_server(
        login_providers=[_login],
        settings=settings,
        oauth_store=oauth_store,
    )
    # A harmless route "member" is allowed to reach, so the temporary
    # policy's "member" role has at least one allow pattern that matches
    # something in the live catalog (see module docstring).
    registry.add_route(
        "member_probe",
        StubAdapter(),
        mode="live",
        description="Test-only route reachable by the member role.",
    )

    await bootstrap_platform(
        upstreams,
        registry,
        settings,
        policy_manager,
        observability=observability,
        users_store=server._users_store_holder["store"],
    )

    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL) as http_client:
            admin_token_response = await obtain_access_token(
                http_client, settings.resource_url, email=ADMIN_EMAIL
            )
            admin_token = admin_token_response["body"]["access_token"]

            async with Client(_transport_for(app, settings, admin_token)) as client:
                tools = await client.list_tools()
                tool_names = {t.name for t in tools}
                assert "users_add" in tool_names

                added = await client.call_tool(
                    "users_add",
                    {
                        "email": MEMBER_EMAIL,
                        "full_name": "Member",
                        "roles": ["member"],
                    },
                )
                assert added.data["state"] == "done"

                rejected = await client.call_tool(
                    "users_add",
                    {
                        "email": "ghost-user@example.com",
                        "full_name": "Ghost",
                        "roles": ["ghost"],
                    },
                )
                assert rejected.data["state"] == "error"
                assert rejected.data["code"] == "validation_error"

            member_token_response = await obtain_access_token(
                http_client, settings.resource_url, email=MEMBER_EMAIL
            )
            member_token = member_token_response["body"]["access_token"]

            async with Client(_transport_for(app, settings, member_token)) as client:
                tools = await client.list_tools()
                member_tool_names = {t.name for t in tools}
                assert not any(name.startswith("users_") for name in member_tool_names)
