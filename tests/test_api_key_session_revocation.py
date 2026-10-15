"""Revoking an API key ends sign-in sessions opened with it."""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from httpx import ASGITransport, AsyncClient
from redis.exceptions import RedisError

from keystone_mcp.auth.keystone_oauth_provider import RefreshMeta, encode_refresh_meta
from keystone_mcp.auth.login_pending_store import InMemoryLoginPendingStore
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.auth.sessions import SessionRevoker
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.server import bootstrap_platform, build_server
from keystone_mcp.users import service
from keystone_mcp.users.db import make_session_factory, session_scope
from support.login import dev_token_login
from support.oauth_harness import BASE_URL, obtain_access_token, refresh_access_token
from support.test_env import require_redis_url
from support.users_store import make_users_store

VALID_TOKEN = "valid-test-token"
ADMIN = VerifiedIdentity(email="admin@example.com")
HUMAN = "human@example.com"
HUMAN2 = "human2@example.com"

POLICY_YAML = """\
version: "b03-keys"
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
            timeout=timeout or httpx.Timeout(30.0),
            auth=auth,
            follow_redirects=True,
        )

    return StreamableHttpTransport(
        settings.transport_url,
        auth=token,
        httpx_client_factory=factory,
    )


@pytest_asyncio.fixture
async def api_key_session_harness(tmp_path: Path, oauth_store_backend):
    store, pending, base_settings, _backend = oauth_store_backend
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(POLICY_YAML, encoding="utf-8")

    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_backend="local",
        redis_url=require_redis_url(),
        rbac_audit_subject_salt="test-salt",
        superadmin_email=ADMIN.email,
        users_db_url=f"sqlite:///{tmp_path}/keystone-users.db",
        session_max_age_seconds=0,
        dev_tokens=VALID_TOKEN,
        enabled_login_methods=frozenset({"api_key", "dev_token"}),
    )

    import keystone_mcp.server as server_module

    mcp, registry, _oauth, upstreams, policy_manager, observability, _recon = build_server(
        settings=settings,
        oauth_store=store,
        login_pending_store=pending,
        login_providers=[dev_token_login({VALID_TOKEN})],
    )
    from keystone_mcp.adapters.stub import StubAdapter

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
                for email, name in ((HUMAN, "One"), (HUMAN2, "Two")):
                    added = await admin_client.call_tool(
                        "users_add",
                        {"email": email, "full_name": name, "roles": ["member"]},
                    )
                    assert added.data["state"] == "done"

                key1 = await admin_client.call_tool(
                    "api_keys_issue",
                    {"subject": HUMAN, "expires_in_days": 90},
                )
                assert key1.data["state"] == "done"
                k1 = key1.data["api_key"]["key"]

                key2 = await admin_client.call_tool(
                    "api_keys_issue",
                    {"subject": HUMAN2, "expires_in_days": 90},
                )
                assert key2.data["state"] == "done"
                k2 = key2.data["api_key"]["key"]
                kid1 = key1.data["api_key"]["key_id"]

            human1 = await obtain_access_token(
                http_client, settings.resource_url, api_token=k1, email=HUMAN
            )
            human2 = await obtain_access_token(
                http_client, settings.resource_url, api_token=k2, email=HUMAN2
            )

            yield {
                "app": app,
                "settings": settings,
                "http_client": http_client,
                "admin_token": admin_token,
                "admin_client_factory": lambda: Client(_transport(app, settings, admin_token)),
                "human1": human1,
                "human2": human2,
                "kid1": kid1,
                "store": store,
                "pending": pending,
            }


pytest_plugins = ("support.oauth_stores",)

pytestmark = pytest.mark.asyncio


async def test_revoke_key_ends_sessions_opened_with_it(api_key_session_harness):
    h = api_key_session_harness
    async with h["admin_client_factory"]() as admin_client:
        revoked = await admin_client.call_tool("api_keys_revoke", {"key_id": h["kid1"]})
        assert revoked.data["state"] == "done"
        assert revoked.data["revoked_tokens"] >= 2

    with pytest.raises(ToolError):
        async with Client(_transport(h["app"], h["settings"], h["human1"]["body"]["access_token"])):
            pass

    refresh = await refresh_access_token(
        h["http_client"],
        h["human1"]["client_id"],
        h["human1"]["body"]["refresh_token"],
        h["settings"].resource_url,
    )
    assert refresh["body"].get("error") == "invalid_grant"


async def test_revoke_key_keeps_sessions_of_other_key(api_key_session_harness):
    h = api_key_session_harness
    async with h["admin_client_factory"]() as admin_client:
        await admin_client.call_tool("api_keys_revoke", {"key_id": h["kid1"]})

    async with Client(
        _transport(h["app"], h["settings"], h["human2"]["body"]["access_token"])
    ) as client:
        result = await client.call_tool("member_ping", {})
        assert result.data["state"] == "done"


async def test_revoke_key_falls_back_to_subject_for_legacy_marker(api_key_session_harness):
    h = api_key_session_harness
    pending = h["pending"]
    rt_legacy = h["human1"]["body"]["refresh_token"]
    await pending.put(
        "refresh_auth",
        rt_legacy,
        encode_refresh_meta(
            RefreshMeta(
                auth_method="api_key",
                resource=h["settings"].resource_url,
                interactive=False,
                auth_time=int(time.time()),
                key_id=None,
                key_id_known=False,
                key_expires_at=None,
            )
        ),
        3600,
    )
    dev_res = await obtain_access_token(
        h["http_client"], h["settings"].resource_url, email=HUMAN, api_token=VALID_TOKEN
    )

    async with h["admin_client_factory"]() as admin_client:
        await admin_client.call_tool("api_keys_revoke", {"key_id": h["kid1"]})

    with pytest.raises(ToolError):
        async with Client(_transport(h["app"], h["settings"], dev_res["body"]["access_token"])):
            pass
    refresh = await refresh_access_token(
        h["http_client"],
        dev_res["client_id"],
        dev_res["body"]["refresh_token"],
        h["settings"].resource_url,
    )
    assert refresh["body"].get("error") == "invalid_grant"


async def test_revoke_key_twice_retries_session_revocation(api_key_session_harness):
    h = api_key_session_harness
    store = h["store"]
    calls = {"n": 0}
    real_revoke = store.revoke_tokens

    async def flaky_revoke(*args, **kwargs):  # noqa: ANN002
        calls["n"] += 1
        if calls["n"] == 1:
            raise RedisError("down")
        return await real_revoke(*args, **kwargs)

    async with h["admin_client_factory"]() as admin_client:
        with patch.object(store, "revoke_tokens", side_effect=flaky_revoke):
            first = await admin_client.call_tool("api_keys_revoke", {"key_id": h["kid1"]})
        assert first.data["state"] == "error"
        assert first.data["code"] == "service_unavailable"

        second = await admin_client.call_tool("api_keys_revoke", {"key_id": h["kid1"]})
        assert second.data["state"] == "done"
        assert second.data["revoked_tokens"] >= 2


async def test_cli_keys_revoke_ends_sessions(api_key_session_harness, tmp_path, monkeypatch):
    h = api_key_session_harness
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", h["settings"].users_db_url)
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", BASE_URL)

    from keystone_mcp.users import api_keys_cli

    exit_code = api_keys_cli._cmd_revoke(  # noqa: SLF001
        type("NS", (), {"key_id": h["kid1"]})()
    )
    assert exit_code == 0

    refresh = await refresh_access_token(
        h["http_client"],
        h["human1"]["client_id"],
        h["human1"]["body"]["refresh_token"],
        h["settings"].resource_url,
    )
    assert refresh["body"].get("error") == "invalid_grant"


async def test_service_account_key_revoke_unchanged(tmp_path):
    store, _ = await make_users_store(tmp_path)
    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_service_account(
            session,
            name="bot",
            description=None,
            roles=["member"],
            created_by="test",
        )
        row, svc_key = service.issue_api_key(
            session,
            subject="svc:bot",
            label=None,
            expires_in_days=90,
            created_by="test",
        )

    oauth_store = InMemoryOAuthStore()
    pending = InMemoryLoginPendingStore()
    revoker = SessionRevoker(oauth_store, pending)
    from keystone_mcp.adapters.api_keys_admin import ApiKeysAdminAdapter
    from keystone_mcp.router.engine import RouterEngine
    from keystone_mcp.router.registry import RouterRegistry
    from keystone_mcp.user_directory.local import LocalUserDirectory

    directory = LocalUserDirectory(store)
    adapter = ApiKeysAdminAdapter(directory=directory, session_revoker=revoker)
    engine = RouterEngine(Settings(base_url=BASE_URL, users_backend="local", rbac_mode="off"))
    reg = RouterRegistry(engine)
    route = reg.add_route("api_keys_revoke", adapter, mode="live")
    out = await engine.execute(route, {"key_id": row.key_id}, identity=ADMIN)
    assert out["state"] == "done"
    assert out.get("revoked_tokens", 0) == 0
