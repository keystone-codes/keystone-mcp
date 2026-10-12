"""Block and users_logout revoke OAuth sessions end to end."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import AsyncMock

import httpx2
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from httpx2 import ASGITransport, AsyncClient
from redis.exceptions import RedisError

import keystone_mcp.server as server_module
from conftest import BASE_URL, obtain_access_token, refresh_access_token
from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.adapters.users_admin import UsersAdminAdapter
from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.login_pending_store import InMemoryLoginPendingStore
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.auth.sessions import SessionRevoker
from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.server import bootstrap_platform, build_server
from keystone_mcp.user_directory.local import LocalUserDirectory
from support.users_store import make_users_store

VALID_TOKEN = "valid-test-token"
ADMIN = VerifiedIdentity(email="admin@example.com")
VICTIM_EMAIL = "victim@example.com"

POLICY_YAML = """\
version: "y10-sessions"
default_deny: true
roles:
  administrator:
    allow: ["*"]
  member:
    allow: ["member_ping"]
requires_human_identity: []
critical_tools: []
"""


def _transport(app, settings: Settings, token: str):
    def factory(headers=None, timeout=None, auth=None, **_kw):
        return AsyncClient(
            transport=ASGITransport(app=app),
            base_url=BASE_URL,
            headers=headers,
            timeout=timeout or httpx2.Timeout(30.0),
            auth=auth,
            follow_redirects=True,
        )

    return StreamableHttpTransport(
        settings.transport_url,
        auth=token,
        httpx_client_factory=factory,
    )


@pytest_asyncio.fixture
async def session_harness(tmp_path: Path):
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(POLICY_YAML, encoding="utf-8")

    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_backend="local",
        redis_url="redis://localhost:6379/0",
        rbac_audit_subject_salt="test-salt",
        superadmin_email=ADMIN.email,
        users_db_url=f"sqlite:///{tmp_path}/keystone-users.db",
    )

    oauth_store = InMemoryOAuthStore()
    pending = InMemoryLoginPendingStore()
    idp = StaticIdentityProvider({VALID_TOKEN})

    mcp, registry, _oauth, upstreams, policy_manager, observability, _recon = build_server(
        identity_provider=idp,
        settings=settings,
        oauth_store=oauth_store,
        login_pending_store=pending,
    )
    registry.add_route("member_ping", StubAdapter(), mode="live")
    await bootstrap_platform(
        upstreams,
        registry,
        settings,
        policy_manager,
        observability=observability,
        users_store=server_module._users_store_holder["store"],
    )

    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL) as http_client:
            admin_res = await obtain_access_token(
                http_client, settings.resource_url, email=ADMIN.email
            )
            admin_token = admin_res["body"]["access_token"]

            async with Client(_transport(app, settings, admin_token)) as admin_client:
                added = await admin_client.call_tool(
                    "users_add",
                    {
                        "email": VICTIM_EMAIL,
                        "full_name": "Victim",
                        "roles": ["member"],
                    },
                )
                assert added.data["state"] == "done"

            victim_res = await obtain_access_token(
                http_client, settings.resource_url, email=VICTIM_EMAIL
            )
            yield {
                "app": app,
                "settings": settings,
                "http_client": http_client,
                "admin_token": admin_token,
                "victim_access": victim_res["body"]["access_token"],
                "victim_refresh": victim_res["body"]["refresh_token"],
                "victim_client_id": victim_res["client_id"],
                "oauth_store": oauth_store,
            }


async def test_blocked_user_is_rejected_on_next_request(session_harness):
    h = session_harness
    async with Client(_transport(h["app"], h["settings"], h["admin_token"])) as admin_client:
        blocked = await admin_client.call_tool("users_block", {"email": VICTIM_EMAIL})
        assert blocked.data["state"] == "done"
        assert blocked.data["revoked_tokens"] >= 2

    transport = _transport(h["app"], h["settings"], h["victim_access"])
    with pytest.raises(Exception):
        async with Client(transport) as victim_client:
            await victim_client.call_tool("member_ping", {})

    refresh = await refresh_access_token(
        h["http_client"],
        h["victim_client_id"],
        h["victim_refresh"],
        h["settings"].resource_url,
    )
    assert refresh["status"] in (400, 401)
    assert refresh["body"].get("error") == "invalid_grant"


async def test_unblock_does_not_restore_old_tokens(session_harness):
    h = session_harness
    async with Client(_transport(h["app"], h["settings"], h["admin_token"])) as admin_client:
        await admin_client.call_tool("users_block", {"email": VICTIM_EMAIL})
        unblocked = await admin_client.call_tool("users_unblock", {"email": VICTIM_EMAIL})
        assert unblocked.data["state"] == "done"

    with pytest.raises(Exception):
        async with Client(_transport(h["app"], h["settings"], h["victim_access"])) as victim_client:
            await victim_client.call_tool("member_ping", {})

    new_login = await obtain_access_token(
        h["http_client"], h["settings"].resource_url, email=VICTIM_EMAIL
    )
    assert new_login["status"] == 200
    async with Client(
        _transport(h["app"], h["settings"], new_login["body"]["access_token"])
    ) as victim_client:
        result = await victim_client.call_tool("member_ping", {})
        assert result.data["state"] == "done"


async def test_logout_ends_sessions_but_allows_new_sign_in(session_harness):
    h = session_harness
    async with Client(_transport(h["app"], h["settings"], h["admin_token"])) as admin_client:
        logout = await admin_client.call_tool("users_logout", {"email": VICTIM_EMAIL})
        assert logout.data["state"] == "done"
        assert logout.data["revoked_tokens"] >= 2

    with pytest.raises(Exception):
        async with Client(_transport(h["app"], h["settings"], h["victim_access"])) as victim_client:
            await victim_client.call_tool("member_ping", {})

    new_login = await obtain_access_token(
        h["http_client"], h["settings"].resource_url, email=VICTIM_EMAIL
    )
    assert new_login["status"] == 200


async def test_logout_unknown_email_is_done_with_zero(tmp_path: Path):
    store, _ = await make_users_store(tmp_path)
    directory = LocalUserDirectory(store)
    revoker = SessionRevoker(InMemoryOAuthStore(), InMemoryLoginPendingStore())
    adapter = UsersAdminAdapter(directory=directory, session_revoker=revoker)
    engine = RouterEngine(Settings(base_url=BASE_URL, users_backend="local", rbac_mode="off"))
    reg = RouterRegistry(engine)
    route = reg.add_route("users_logout", adapter, mode="live")
    out = await engine.execute(route, {"email": "nobody@example.com"}, identity=ADMIN)
    assert out["state"] == "done"
    assert out["revoked_tokens"] == 0


async def test_block_when_token_store_down_still_blocks(tmp_path: Path):
    store, _ = await make_users_store(tmp_path)
    await store.create_user(
        email=VICTIM_EMAIL,
        full_name="Victim",
        roles=["member"],
        note=None,
        created_by=ADMIN.email,
        allowed_roles=None,
    )
    directory = LocalUserDirectory(store)
    failing = AsyncMock(spec=SessionRevoker)
    failing.revoke_subject.side_effect = RedisError("down")
    adapter = UsersAdminAdapter(directory=directory, session_revoker=failing)
    engine = RouterEngine(Settings(base_url=BASE_URL, users_backend="local", rbac_mode="off"))
    reg = RouterRegistry(engine)
    route = reg.add_route("users_block", adapter, mode="live")
    out = await engine.execute(route, {"email": VICTIM_EMAIL}, identity=ADMIN)
    assert out["state"] == "done"
    assert out["revoked_tokens"] is None
    rows = await store.list_users(is_blocked=True)
    assert any(row.email == VICTIM_EMAIL for row in rows)


async def test_logout_when_token_store_down_is_service_unavailable(tmp_path: Path):
    store, _ = await make_users_store(tmp_path)
    directory = LocalUserDirectory(store)
    failing = AsyncMock(spec=SessionRevoker)
    failing.revoke_subject.side_effect = RedisError("down")
    adapter = UsersAdminAdapter(directory=directory, session_revoker=failing)
    engine = RouterEngine(Settings(base_url=BASE_URL, users_backend="local", rbac_mode="off"))
    reg = RouterRegistry(engine)
    route = reg.add_route("users_logout", adapter, mode="live")
    out = await engine.execute(route, {"email": VICTIM_EMAIL}, identity=ADMIN)
    assert out["state"] == "error"
    assert out["code"] == "service_unavailable"


async def test_rbac_off_block_via_store_revokes_too(tmp_path: Path):
    store, _ = await make_users_store(tmp_path)
    await store.create_user(
        email=VICTIM_EMAIL,
        full_name="Victim",
        roles=["member"],
        note=None,
        created_by=ADMIN.email,
        allowed_roles=None,
    )
    oauth_store = InMemoryOAuthStore()
    pending = InMemoryLoginPendingStore()
    revoker = SessionRevoker(oauth_store, pending)
    directory = LocalUserDirectory(store)
    adapter = UsersAdminAdapter(directory=directory, session_revoker=revoker)
    engine = RouterEngine(Settings(base_url=BASE_URL, users_backend="local", rbac_mode="off"))
    from keystone_mcp.router.registry import RouterRegistry

    now = int(time.time())
    at = "km_at_test"
    rt = "km_rt_test"
    from mcp.server.auth.provider import AccessToken, RefreshToken

    await oauth_store.put_access_token(
        AccessToken(
            token=at,
            client_id="c1",
            scopes=[],
            expires_at=now + 3600,
            subject=VICTIM_EMAIL,
            claims={"email": VICTIM_EMAIL, "iat": now},
        )
    )
    await oauth_store.put_refresh_token(
        RefreshToken(
            token=rt,
            client_id="c1",
            scopes=[],
            expires_at=now + 3000,
            subject=VICTIM_EMAIL,
        )
    )

    reg = RouterRegistry(engine)
    route = reg.add_route("users_block", adapter, mode="live")
    out = await engine.execute(route, {"email": VICTIM_EMAIL}, identity=ADMIN)
    assert out["state"] == "done"
    assert out["revoked_tokens"] == 2
    assert await oauth_store.get_access_token(at) is None
    assert await oauth_store.get_refresh_token(rt) is None


def test_users_logout_published_only_when_enforce(tmp_path: Path):
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(POLICY_YAML, encoding="utf-8")
    from keystone_mcp.user_directory.memory import InMemoryUserDirectory

    enforce = Settings(
        base_url=BASE_URL,
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_backend="local",
        redis_url="redis://localhost:6379/0",
    )
    off = Settings(base_url=BASE_URL, rbac_mode="off", users_backend="local")
    directory = InMemoryUserDirectory()
    revoker = SessionRevoker(InMemoryOAuthStore(), InMemoryLoginPendingStore())

    engine = RouterEngine(enforce)
    reg_enforce = RouterRegistry(engine)
    register_catalog(reg_enforce, enforce, directory=directory, session_revoker=revoker)
    assert reg_enforce.get("users_logout") is not None

    engine_off = RouterEngine(off)
    reg_off = RouterRegistry(engine_off)
    register_catalog(reg_off, off, directory=directory, session_revoker=revoker)
    assert reg_off.get("users_logout") is None
