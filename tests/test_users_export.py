"""Acceptance tests for ``users_export``."""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
from mcp.server.auth.provider import AccessToken, RefreshToken

from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.observability.subject import hash_subject
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory.http import HttpUserDirectory
from support.admin_harness import build_admin_harness, build_delegation_harness, run_admin_tool
from support.fake_users_service import build_fake_users_service
from support.test_env import UNUSED_REDIS_URL
from support.users_store import make_users_store

ADMIN = VerifiedIdentity(email="admin@example.com")
HR = VerifiedIdentity(email="hr@corp.example")
SERVICE = VerifiedIdentity(
    "svc:ci",
    subject_type="service",
    claims={"subject_type": "service"},
)

SALT = "test-salt"
TOKEN = "test-service-token"


async def _export(harness, email: str, *, identity=ADMIN):
    return await run_admin_tool(harness, "users_export", {"email": email}, identity)


async def _put_session_pair(oauth_store, email: str) -> None:
    now = int(time.time())
    at = f"km_at_{uuid.uuid4().hex}"
    rt = f"km_rt_{uuid.uuid4().hex}"
    await oauth_store.put_access_token(
        AccessToken(
            token=at,
            client_id="c1",
            scopes=[],
            expires_at=now + 3600,
            subject=email,
            claims={"email": email, "iat": now},
        )
    )
    await oauth_store.put_refresh_token(
        RefreshToken(
            token=rt,
            client_id="c1",
            scopes=[],
            expires_at=now + 3000,
            subject=email,
        )
    )


@pytest.mark.asyncio
async def test_export_contains_record_roles_keys_sessions(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    email = "export-subject@example.com"
    await harness.directory.create_user(
        email=email,
        full_name="Export Me",
        roles=["member"],
        note="note",
        actor=ADMIN.email,
    )
    await harness.directory.grant_role(email=email, role="unused", actor=ADMIN.email)
    await harness.directory.issue_api_key(
        subject=email, label="active", expires_in_days=30, actor=ADMIN.email
    )
    revoked = await harness.directory.issue_api_key(
        subject=email, label="old", expires_in_days=30, actor=ADMIN.email
    )
    await harness.directory.revoke_api_key(key_id=revoked.record.key_id, actor=ADMIN.email)

    route = harness.registry.get("users_export")
    oauth_store = route.target._oauth_store  # noqa: SLF001
    await _put_session_pair(oauth_store, email)
    await _put_session_pair(oauth_store, email)

    out = await _export(harness, email)
    assert out["state"] == "done"
    doc = out["export"]
    assert doc["format"] == "keystone-person-export/1"
    assert doc["email"] == email
    record = doc["directory"]["record"]
    assert set(record["roles"]) == {"member", "unused"}
    assert record["full_name"] == "Export Me"
    assert len(doc["api_keys"]) == 2
    assert doc["sessions"]["open"] == 2
    assert doc["authored_records"] is not None


@pytest.mark.asyncio
async def test_export_has_no_secrets(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    out = await _export(harness, "u@example.com")
    blob = json.dumps(out["export"])
    assert "secret_hash" not in blob
    assert "ksk_" not in blob
    assert "km_at_" not in blob
    assert "km_rt_" not in blob


@pytest.mark.asyncio
async def test_export_pseudonym_matches_audit(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    email = "u@example.com"
    out = await _export(harness, email)
    expected = hash_subject(email, salt=SALT)
    assert out["export"]["audit"]["pseudonym"] == expected


@pytest.mark.asyncio
async def test_export_unknown_user(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    out = await _export(harness, "missing@example.com")
    assert out["code"] == "user_not_found"


@pytest.mark.asyncio
async def test_export_requires_full_administrator(tmp_path: Path) -> None:
    harness = await build_delegation_harness(tmp_path)
    out = await _export(harness, "m@corp.example", identity=HR)
    assert out["code"] == "forbidden"

    harness_admin = await build_admin_harness(tmp_path)
    out_svc = await _export(harness_admin, "u@example.com", identity=SERVICE)
    assert out_svc["code"] == "forbidden"


@pytest.mark.asyncio
async def test_export_with_http_directory_marks_unknown_fields(tmp_path: Path) -> None:
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(
        'version: "1"\ndefault_deny: true\nroles:\n  administrator:\n    allow: ["*"]\n',
        encoding="utf-8",
    )
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        redis_url=UNUSED_REDIS_URL,
        rbac_audit_subject_salt=SALT,
    )
    store, _revision = await make_users_store(tmp_path)
    await store.create_user(
        email="admin@example.com",
        full_name="Admin",
        roles=["administrator"],
        note=None,
        created_by="system",
        allowed_roles=None,
    )
    await store.create_user(
        email="u@example.com",
        full_name="User",
        roles=["member"],
        note=None,
        created_by="system",
        allowed_roles=None,
    )
    app = build_fake_users_service(store, token=TOKEN)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://fake-users.test",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    directory = HttpUserDirectory(
        base_url="http://fake-users.test",
        service_token=TOKEN,
        timeout_seconds=5.0,
        client=client,
    )
    from keystone_mcp.rbac.loader import RbacPolicyManager
    from keystone_mcp.rbac.management import snapshot_and_file_management_source
    from keystone_mcp.server import policy_role_source

    engine = RouterEngine(settings)
    reg = RouterRegistry(engine)
    manager = RbacPolicyManager(settings)
    manager.load_initial(reg)
    register_catalog(
        reg,
        settings,
        directory=directory,
        oauth_store=None,
        role_source=policy_role_source(manager),
        management_source=snapshot_and_file_management_source(manager),
    )
    manager.reload(reg)
    route = reg.get("users_export")
    assert route is not None
    out = await engine.execute(route, {"email": "u@example.com"}, identity=ADMIN)
    assert out["state"] == "done"
    doc = out["export"]
    assert doc["api_keys"] is None
    assert "the users directory does not report API keys" in doc["not_held"]
    assert doc["authored_records"] is None
    await directory.aclose()


@pytest.mark.asyncio
async def test_export_redis_down_sessions_null(tmp_path: Path) -> None:
    harness = await build_admin_harness(tmp_path)
    route = harness.registry.get("users_export")
    adapter = route.target
    adapter._oauth_store = AsyncMock()  # noqa: SLF001
    adapter._oauth_store.subject_tokens.side_effect = OSError("down")
    out = await _export(harness, "u@example.com")
    assert out["export"]["sessions"] == {"open": None, "reason": "token store unavailable"}


