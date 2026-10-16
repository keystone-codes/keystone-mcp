"""Acceptance tests for ``users_delete``."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from redis.exceptions import RedisError
from sqlalchemy import inspect, text

from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.observability.service import RbacObservability
from keystone_mcp.observability.subject import hash_subject
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory.errors import UsersError as DirectoryUsersError
from keystone_mcp.user_directory.http import HttpUserDirectory
from support.admin_harness import build_admin_harness, build_delegation_harness, run_admin_tool
from support.test_env import UNUSED_REDIS_URL, require_redis_url

ADMIN = VerifiedIdentity(email="admin@example.com")
HR = VerifiedIdentity(email="hr@corp.example")
SERVICE = VerifiedIdentity(
    "svc:ci",
    subject_type="service",
    claims={"subject_type": "service"},
)

SALT = "test-salt"


async def _delete(harness, email: str, *, confirmation: str | None = None, identity=ADMIN):
    args: dict = {"email": email}
    if confirmation is not None:
        args["confirmation"] = confirmation
    return await run_admin_tool(harness, "users_delete", args, identity)


@pytest.mark.asyncio
async def test_first_call_returns_summary_and_code(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    before = await harness.directory.list_users()
    out = await _delete(harness, "u@example.com")
    assert out["state"] == "confirmation_required"
    summary = out["summary"]
    assert "member" in summary["roles"]
    assert summary["api_keys_total"] >= 1
    assert out["confirmation"]
    assert out["expires_in"] == 300
    after = await harness.directory.list_users()
    assert len(after) == len(before)


@pytest.mark.asyncio
async def test_anonymize_flow(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    email = "u@example.com"
    first = await _delete(harness, email)
    second = await _delete(harness, email, confirmation=first["confirmation"])
    assert second["state"] == "done"
    pseudonym = hash_subject(email, salt=SALT)
    assert second["pseudonym"] == pseudonym
    engine = harness.users_store._engine  # noqa: SLF001
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT email, full_name, is_blocked FROM keystone_user WHERE email = :e"),
            {"e": f"deleted:{pseudonym}"},
        ).one()
        assert row.full_name == ""
        assert bool(row.is_blocked) is True
        assert (
            conn.execute(text("SELECT 1 FROM keystone_user WHERE email = :e"), {"e": email}).first()
            is None
        )
    listed = await harness.directory.list_users(is_blocked=None)
    assert all(u.email != f"deleted:{pseudonym}" for u in listed)


@pytest.mark.asyncio
async def test_delete_flow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DELETE_MODE", "delete")
    harness = await build_admin_harness(tmp_path)
    route = harness.registry.get("users_delete")
    assert route is not None
    route.target._users_delete_mode = "delete"  # noqa: SLF001
    email = "u@example.com"
    first = await _delete(harness, email)
    second = await _delete(harness, email, confirmation=first["confirmation"])
    assert second["state"] == "done"
    assert second["mode"] == "delete"
    engine = harness.users_store._engine  # noqa: SLF001
    with engine.connect() as conn:
        assert (
            conn.execute(text("SELECT 1 FROM keystone_user WHERE email = :e"), {"e": email}).first()
            is None
        )


@pytest.mark.asyncio
async def test_references_are_rewritten(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    creator = "creator@corp.example"
    await harness.directory.create_user(
        email=creator,
        full_name="Creator",
        roles=["member"],
        note=None,
        actor=ADMIN.email,
    )
    await harness.directory.create_user(
        email="child@corp.example",
        full_name="Child",
        roles=["member"],
        note=None,
        actor=creator,
    )
    await harness.directory.create_service_account(
        name="made-by-creator",
        description="x",
        roles=["member"],
        actor=creator,
    )
    issued = await harness.directory.issue_api_key(
        subject="u@example.com", label="k", expires_in_days=30, actor=ADMIN.email
    )
    await harness.directory.revoke_api_key(key_id=issued.record.key_id, actor=creator)
    first = await _delete(harness, creator)
    out = await _delete(harness, creator, confirmation=first["confirmation"])
    pseudonym = out["pseudonym"]
    marker = f"deleted:{pseudonym}"
    engine = harness.users_store._engine  # noqa: SLF001
    with engine.connect() as conn:
        for table in inspect(engine).get_table_names():
            if not table.startswith("keystone_"):
                continue
            for col in inspect(engine).get_columns(table):
                if col["type"].python_type is not str:
                    continue
                name = col["name"]
                hits = conn.execute(
                    text(f"SELECT COUNT(*) FROM {table} WHERE {name} = :email"),
                    {"email": creator},
                ).scalar_one()
                assert hits == 0, f"{table}.{name} still has raw email"
        child = conn.execute(
            text("SELECT created_by FROM keystone_user WHERE email = 'child@corp.example'")
        ).one()
        assert child.created_by == marker


@pytest.mark.asyncio
async def test_audit_pseudonym_unchanged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    observability = RbacObservability(
        Settings(
            base_url="http://localhost:8080",
            rbac_mode="enforce",
            rbac_policy_path=str(tmp_path / "p.yaml"),
            rbac_audit_enabled=True,
            rbac_audit_subject_salt=SALT,
        )
    )
    (tmp_path / "p.yaml").write_text(
        'version: "1"\ndefault_deny: true\nroles:\n  administrator:\n    allow: ["*"]\n',
        encoding="utf-8",
    )
    harness = await build_admin_harness(tmp_path, observability=observability)
    email = "u@example.com"
    block_route = harness.registry.get("users_block")
    await harness.engine.execute(block_route, {"email": email}, identity=ADMIN)
    first = await _delete(harness, email)
    await _delete(harness, email, confirmation=first["confirmation"])
    events = [
        json.loads(record.message.removeprefix("rbac audit "))
        for record in caplog.records
        if record.message.startswith("rbac audit ") and "rbac_users_mutation" in record.message
    ]
    targets = [e["target"] for e in events if e.get("target")]
    pseudonym = hash_subject(email, salt=SALT)
    assert pseudonym in targets
    assert all(t == pseudonym for t in targets if t)


@pytest.mark.asyncio
async def test_code_is_single_use_and_bound(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    await harness.directory.create_user(
        email="other@corp.example",
        full_name="Other",
        roles=["administrator"],
        note=None,
        actor=ADMIN.email,
    )
    await harness.directory.create_user(
        email="member@corp.example",
        full_name="Member",
        roles=["member"],
        note=None,
        actor=ADMIN.email,
    )
    victim = "u@example.com"
    first = await _delete(harness, victim)
    code = first["confirmation"]
    not_full_admin = await _delete(
        harness,
        victim,
        confirmation=code,
        identity=VerifiedIdentity("member@corp.example"),
    )
    assert not_full_admin["code"] == "forbidden"
    done = await _delete(harness, victim, confirmation=code)
    assert done["state"] == "done"
    repeat = await _delete(harness, victim, confirmation=code)
    assert repeat["code"] == "validation_error"
    first_b = await _delete(harness, "other@corp.example")
    wrong_target = await _delete(harness, "other@corp.example", confirmation=first["confirmation"])
    assert wrong_target["code"] == "validation_error"
    assert first_b["confirmation"] != code


@pytest.mark.asyncio
async def test_expired_confirmation_code_rejected(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    first = await _delete(harness, "u@example.com")
    code = first["confirmation"]
    route = harness.registry.get("users_delete")
    pending = route.target._login_pending_store  # noqa: SLF001
    for entry in pending._entries.values():
        entry.expires_at = 0
    out = await _delete(harness, "u@example.com", confirmation=code)
    assert out["code"] == "validation_error"


@pytest.mark.asyncio
async def test_last_full_administrator_cannot_be_deleted(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    await harness.directory.create_user(
        email="peer@corp.example",
        full_name="Peer",
        roles=["member"],
        note=None,
        actor=ADMIN.email,
    )
    with pytest.raises(DirectoryUsersError) as exc:
        await harness.users_store.delete_user(
            email="admin@example.com",
            actor="peer@corp.example",
            mode="delete",
            pseudonym="sub_deadbeef",
        )
    assert exc.value.code == "last_administrator"


@pytest.mark.asyncio
async def test_self_delete_forbidden(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    out = await _delete(harness, "admin@example.com", identity=ADMIN)
    assert out["code"] == "self_admin_mutation_forbidden"


@pytest.mark.asyncio
async def test_not_full_administrator_forbidden(tmp_path: Path) -> None:
    harness = await build_delegation_harness(tmp_path)
    out = await _delete(harness, "m@corp.example", identity=HR)
    assert out["code"] == "forbidden"


@pytest.mark.asyncio
async def test_service_account_forbidden(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    out = await _delete(harness, "u@example.com", identity=SERVICE)
    assert out["code"] == "forbidden"


@pytest.mark.asyncio
async def test_redis_down_after_delete_reports_service_unavailable(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    route = harness.registry.get("users_delete")
    adapter = route.target
    adapter._session_revoker = AsyncMock()  # noqa: SLF001
    adapter._session_revoker.revoke_subject.side_effect = RedisError("down")
    email = "u@example.com"
    first = await harness.engine.execute(route, {"email": email}, identity=ADMIN)
    out = await harness.engine.execute(
        route,
        {"email": email, "confirmation": first["confirmation"]},
        identity=ADMIN,
    )
    assert out["code"] == "service_unavailable"
    assert "users_logout" in out["message"]
    resolved = await harness.directory.resolve_user(email)
    assert resolved.exists is False


@pytest.mark.asyncio
async def test_not_published_without_capability(tmp_path: Path) -> None:
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(tmp_path / "p.yaml"),
        redis_url=UNUSED_REDIS_URL,
    )
    (tmp_path / "p.yaml").write_text(
        'version: "1"\ndefault_deny: true\nroles:\n  administrator:\n    allow: ["*"]\n',
        encoding="utf-8",
    )
    directory = HttpUserDirectory(
        base_url="http://users:8000",
        service_token="token",
        timeout_seconds=1.0,
    )
    reg = RouterRegistry(RouterEngine(settings))
    register_catalog(reg, settings, directory=directory)
    assert reg.get("users_delete") is None


@pytest.mark.asyncio
async def test_empty_salt_adds_warning(tmp_path: Path) -> None:
    harness = await build_admin_harness(
        tmp_path,
        policy_yaml='version: "1"\ndefault_deny: true\nroles:\n  administrator:\n    allow: ["*"]\n',
    )
    harness.settings = Settings(**{**harness.settings.__dict__, "rbac_audit_subject_salt": ""})
    route = harness.registry.get("users_delete")
    route.target._rbac_audit_subject_salt = ""  # noqa: SLF001
    email = "u@example.com"
    first = await harness.engine.execute(route, {"email": email}, identity=ADMIN)
    out = await harness.engine.execute(
        route,
        {"email": email, "confirmation": first["confirmation"]},
        identity=ADMIN,
    )
    assert out["state"] == "done"
    assert "warning" in out


@pytest.mark.asyncio
async def test_no_email_in_logs(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO)
    harness = await build_admin_harness(tmp_path)
    victim = "victim-no-log@example.com"
    await harness.directory.create_user(
        email=victim,
        full_name="V",
        roles=["member"],
        note=None,
        actor=ADMIN.email,
    )
    first = await _delete(harness, victim)
    await _delete(harness, victim, confirmation=first["confirmation"])
    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert victim not in blob


pytest_plugins = ("support.oauth_stores",)

VALID_TOKEN = "valid-test-token"
VICTIM = "delete-victim@example.com"


def _delete_transport(app, settings: Settings, token: str):
    from support.fastmcp_transport import streamable_http_transport_to_app

    return streamable_http_transport_to_app(app, settings.transport_url, token)


@pytest.mark.asyncio
async def test_sessions_and_keys_are_revoked(tmp_path: Path, oauth_store_backend) -> None:
    from asgi_lifespan import LifespanManager
    from fastmcp import Client
    from httpx import ASGITransport, AsyncClient
    from mcp.shared.exceptions import MCPError

    import keystone_mcp.server as server_module
    from keystone_mcp.adapters.stub import StubAdapter
    from keystone_mcp.server import bootstrap_platform, build_server
    from support.login import dev_token_login
    from support.oauth_harness import BASE_URL, obtain_access_token, refresh_access_token

    oauth_store, pending, _base, _backend = oauth_store_backend
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(
        'version: "f06-delete"\ndefault_deny: true\nroles:\n  administrator:\n    allow: ["*"]\n'
        '  member:\n    allow: ["member_ping"]\n',
        encoding="utf-8",
    )
    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_backend="local",
        redis_url=require_redis_url(),
        rbac_audit_subject_salt=SALT,
        superadmin_email=ADMIN.email,
        users_db_url=f"sqlite:///{tmp_path}/keystone-users.db",
        dev_tokens=VALID_TOKEN,
        enabled_login_methods=frozenset({"api_key", "dev_token"}),
    )
    mcp, registry, _oauth, upstreams, policy_manager, observability, _recon = build_server(
        settings=settings,
        oauth_store=oauth_store,
        login_pending_store=pending,
        login_providers=[dev_token_login({VALID_TOKEN})],
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
            async with Client(_delete_transport(app, settings, admin_token)) as admin_client:
                added = await admin_client.call_tool(
                    "users_add",
                    {"email": VICTIM, "full_name": "Victim", "roles": ["member"]},
                )
                assert added.data["state"] == "done"
                key_out = await admin_client.call_tool(
                    "api_keys_issue",
                    {"subject": VICTIM, "expires_in_days": 30},
                )
                assert key_out.data["state"] == "done"
                api_key = key_out.data["api_key"]["key"]

            key_login = await obtain_access_token(
                http_client, settings.resource_url, api_token=api_key, email=VICTIM
            )
            email_login = await obtain_access_token(
                http_client, settings.resource_url, email=VICTIM, api_token=VALID_TOKEN
            )

            async with Client(_delete_transport(app, settings, admin_token)) as admin_client:
                first = await admin_client.call_tool("users_delete", {"email": VICTIM})
                assert first.data["state"] == "confirmation_required"
                done = await admin_client.call_tool(
                    "users_delete",
                    {"email": VICTIM, "confirmation": first.data["confirmation"]},
                )
                assert done.data["state"] == "done"

            with pytest.raises(MCPError):
                async with Client(
                    _delete_transport(app, settings, key_login["body"]["access_token"])
                ) as victim_client:
                    await victim_client.call_tool("member_ping", {})

            with pytest.raises(MCPError):
                async with Client(
                    _delete_transport(app, settings, email_login["body"]["access_token"])
                ) as victim_client:
                    await victim_client.call_tool("member_ping", {})

            refresh = await refresh_access_token(
                http_client,
                key_login["client_id"],
                key_login["body"]["refresh_token"],
                settings.resource_url,
            )
            assert refresh["body"].get("error") == "invalid_grant"

            retry_key = await obtain_access_token(
                http_client,
                settings.resource_url,
                api_token=api_key,
                email=VICTIM,
            )
            assert retry_key["status"] != 200

            retry_email = await obtain_access_token(
                http_client,
                settings.resource_url,
                email=VICTIM,
                api_token=VALID_TOKEN,
            )
            assert retry_email["status"] != 200
