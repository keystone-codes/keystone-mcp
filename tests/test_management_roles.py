"""Management-role guards on built-in administration tools."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastmcp import FastMCP

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.rbac.management import snapshot_and_file_management_source
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.server import policy_role_source
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.users.revision import NullRevisionWriter
from support.test_env import UNUSED_REDIS_URL
from support.users_store import make_users_store

MANAGEMENT_POLICY = """\
version: "mgmt-test"
default_deny: true
roles:
  administrator:
    allow: ["*"]
  owner:
    allow: ["*"]
  hr:
    allow: ["users_*"]
  sam:
    allow: ["service_accounts_*", "users_list"]
  keys:
    allow: ["api_keys_*"]
  member:
    allow: ["docs_read"]
requires_human_identity: []
critical_tools: []
"""


async def _build_harness(
    tmp_path: Path,
    *,
    policy_yaml: str = MANAGEMENT_POLICY,
    observability: object | None = None,
    manager: RbacPolicyManager | None = None,
):
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(policy_yaml, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/users.db",
        redis_url=UNUSED_REDIS_URL,
    )
    store, _revision = await make_users_store(tmp_path, revision=NullRevisionWriter())
    directory = LocalUserDirectory(store)
    for email, roles in [
        ("a1@corp.example", ["administrator"]),
        ("a2@corp.example", ["administrator"]),
        ("a3@corp.example", ["administrator"]),
        ("hr@corp.example", ["hr"]),
        ("m@corp.example", ["member"]),
        ("sam@corp.example", ["sam"]),
        ("keys@corp.example", ["keys"]),
    ]:
        await directory.create_user(
            email=email,
            full_name=email,
            roles=roles,
            note=None,
            actor="system:test",
        )
    await store.create_service_account(
        name="bot",
        description="bot",
        roles=["member"],
        created_by="system:test",
    )
    owner_sa = await store.create_service_account(
        name="owner-bot",
        description="owner",
        roles=["owner"],
        created_by="system:test",
    )
    _ = owner_sa
    key_a1 = await store.issue_api_key(
        subject="a1@corp.example", label="a1", expires_in_days=30, created_by="system:test"
    )
    key_m = await store.issue_api_key(
        subject="m@corp.example", label="m", expires_in_days=30, created_by="system:test"
    )
    await store.set_blocked(email="a1@corp.example", blocked=True, actor_email="system:test")

    engine = RouterEngine(settings)
    mcp = FastMCP("mgmt-test")
    registry = RouterRegistry(engine, mcp)
    registry.add_route("docs_read", StubAdapter(), mode="live")
    if manager is None:
        manager = RbacPolicyManager(settings)
    register_catalog(
        registry,
        settings,
        directory=directory,
        observability=observability,
        role_source=policy_role_source(manager),
        management_source=snapshot_and_file_management_source(manager),
    )
    if manager.snapshot is None:
        manager.load_initial(registry)
    else:
        manager.reload(registry)
    return {
        "engine": engine,
        "registry": registry,
        "directory": directory,
        "store": store,
        "manager": manager,
        "settings": settings,
        "policy_path": policy_path,
        "key_a1": key_a1.record.key_id,
        "key_m": key_m.record.key_id,
    }


async def _run(engine, registry, tool: str, args: dict, identity: VerifiedIdentity):
    route = registry.get(tool)
    assert route is not None
    return await engine.execute(route, args, identity=identity)


@pytest.mark.asyncio
async def test_delegated_users_role_cannot_touch_administrators(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    hr = VerifiedIdentity(email="hr@corp.example")
    steps = [
        ("users_block", {"email": "a2@corp.example"}),
        ("users_revoke_role", {"email": "a3@corp.example", "role": "administrator"}),
        ("users_unblock", {"email": "a2@corp.example"}),
        ("users_update", {"email": "a1@corp.example", "full_name": "x"}),
        ("users_logout", {"email": "a1@corp.example"}),
        ("users_set_roles", {"email": "a1@corp.example", "roles": ["administrator"]}),
    ]
    for tool, args in steps:
        out = await _run(h["engine"], h["registry"], tool, args, hr)
        assert out.get("code") == "forbidden", tool
    a1 = await h["directory"].resolve_user("a1@corp.example")
    a2 = await h["directory"].resolve_user("a2@corp.example")
    a3 = await h["directory"].resolve_user("a3@corp.example")
    assert a1.is_blocked
    assert "administrator" in a2.roles
    assert "administrator" in a3.roles


@pytest.mark.asyncio
async def test_delegated_users_role_cannot_grant_management_roles(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    hr = VerifiedIdentity(email="hr@corp.example")
    for tool, args in [
        ("users_grant_role", {"email": "hr@corp.example", "role": "owner"}),
        ("users_grant_role", {"email": "hr@corp.example", "role": "administrator"}),
        ("users_grant_role", {"email": "hr@corp.example", "role": "hr"}),
        (
            "users_add",
            {
                "email": "new@corp.example",
                "full_name": "New",
                "roles": ["owner"],
            },
        ),
    ]:
        out = await _run(h["engine"], h["registry"], tool, args, hr)
        assert out.get("code") == "forbidden", tool


@pytest.mark.asyncio
async def test_delegated_users_role_manages_ordinary_people(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    hr = VerifiedIdentity(email="hr@corp.example")
    out = await _run(
        h["engine"],
        h["registry"],
        "users_add",
        {"email": "x@corp.example", "full_name": "X", "roles": ["member"]},
        hr,
    )
    assert out["state"] == "done"
    out = await _run(h["engine"], h["registry"], "users_block", {"email": "m@corp.example"}, hr)
    assert out["state"] == "done"
    out = await _run(h["engine"], h["registry"], "users_unblock", {"email": "m@corp.example"}, hr)
    assert out["state"] == "done"
    out = await _run(
        h["engine"],
        h["registry"],
        "users_grant_role",
        {"email": "m@corp.example", "role": "member"},
        hr,
    )
    assert out["state"] == "done"


@pytest.mark.asyncio
async def test_full_administrator_manages_management_roles(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    admin = VerifiedIdentity(email="a2@corp.example")
    out = await _run(
        h["engine"],
        h["registry"],
        "users_grant_role",
        {"email": "m@corp.example", "role": "owner"},
        admin,
    )
    assert out["state"] == "done"
    out = await _run(h["engine"], h["registry"], "users_block", {"email": "hr@corp.example"}, admin)
    assert out["state"] == "done"


@pytest.mark.asyncio
async def test_full_administrator_is_defined_by_roles_not_by_name(tmp_path: Path) -> None:
    policy = """\
version: "owner-only"
default_deny: true
roles:
  owner: {allow: ["*"]}
  member: {allow: ["docs_read"]}
  hr: {allow: ["users_*"]}
"""
    h = await _build_harness(tmp_path, policy_yaml=policy)
    owner_holder = VerifiedIdentity(email="a1@corp.example")
    await h["directory"].replace_roles(
        email="a1@corp.example", roles=["owner"], actor="system:test"
    )
    await h["store"].set_blocked(email="a1@corp.example", blocked=False, actor_email="system:test")
    out = await _run(
        h["engine"],
        h["registry"],
        "users_grant_role",
        {"email": "m@corp.example", "role": "owner"},
        owner_holder,
    )
    assert out["state"] == "done"
    hr = VerifiedIdentity(email="hr@corp.example")
    out = await _run(
        h["engine"],
        h["registry"],
        "users_grant_role",
        {"email": "m@corp.example", "role": "owner"},
        hr,
    )
    assert out.get("code") == "forbidden"


@pytest.mark.asyncio
async def test_service_account_roles_need_full_administrator(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    sam = VerifiedIdentity(email="sam@corp.example")
    out = await _run(
        h["engine"],
        h["registry"],
        "service_accounts_add",
        {"name": "evil", "roles": ["owner"]},
        sam,
    )
    assert out.get("code") == "forbidden"
    out = await _run(
        h["engine"],
        h["registry"],
        "service_accounts_add",
        {"name": "ok-bot", "roles": ["member"]},
        sam,
    )
    assert out["state"] == "done"
    out = await _run(
        h["engine"],
        h["registry"],
        "service_accounts_update",
        {"name": "owner-bot", "description": "touch"},
        sam,
    )
    assert out.get("code") == "forbidden"


@pytest.mark.asyncio
async def test_api_keys_of_management_holders_need_full_administrator(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    keys = VerifiedIdentity(email="keys@corp.example")
    out = await _run(
        h["engine"],
        h["registry"],
        "api_keys_issue",
        {"subject": "a1@corp.example"},
        keys,
    )
    assert out.get("code") == "forbidden"
    out = await _run(
        h["engine"],
        h["registry"],
        "api_keys_issue",
        {"subject": "m@corp.example"},
        keys,
    )
    assert out["state"] == "done"
    out = await _run(
        h["engine"],
        h["registry"],
        "api_keys_revoke",
        {"key_id": h["key_a1"]},
        keys,
    )
    assert out.get("code") == "forbidden"
    out = await _run(
        h["engine"],
        h["registry"],
        "api_keys_revoke",
        {"key_id": h["key_m"]},
        keys,
    )
    assert out["state"] == "done"


@pytest.mark.asyncio
async def test_management_check_sees_policy_file_newer_than_snapshot(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    manager2 = RbacPolicyManager(h["settings"])
    h["policy_path"].write_text(
        """\
version: "mgmt-test"
default_deny: true
roles:
  administrator: {allow: ["*"]}
  owner: {allow: ["*"]}
  hr: {allow: ["users_*"]}
  sam: {allow: ["service_accounts_*", "users_list"]}
  keys: {allow: ["api_keys_*"]}
  member: {allow: ["docs_read", "users_block"]}
""",
        encoding="utf-8",
    )
    manager2.load_initial(h["registry"])
    register_catalog(
        h["registry"],
        h["settings"],
        directory=h["directory"],
        role_source=policy_role_source(manager2),
        management_source=snapshot_and_file_management_source(manager2),
    )
    manager2.reload(h["registry"])
    hr = VerifiedIdentity(email="hr@corp.example")
    out = await _run(
        h["engine"],
        h["registry"],
        "users_grant_role",
        {"email": "m@corp.example", "role": "member"},
        hr,
    )
    assert out.get("code") == "forbidden"


@pytest.mark.asyncio
async def test_management_refusal_is_audited_and_counted(tmp_path: Path) -> None:
    observability = MagicMock()
    h = await _build_harness(tmp_path, observability=observability)
    hr = VerifiedIdentity(email="hr@corp.example")
    await _run(
        h["engine"],
        h["registry"],
        "users_block",
        {"email": "a2@corp.example"},
        hr,
    )
    observability.record_users_mutation.assert_called()
    assert observability.record_users_mutation.call_args.kwargs["code"] == "forbidden"
    observability.record_admin_refusal.assert_called_with(
        operation="users_block",
        reason="management_role",
    )


@pytest.mark.asyncio
async def test_directory_down_during_management_check_is_service_unavailable(
    tmp_path: Path,
) -> None:
    h = await _build_harness(tmp_path)
    h["directory"].resolve_user = AsyncMock(side_effect=RuntimeError("down"))  # type: ignore[method-assign]
    hr = VerifiedIdentity(email="hr@corp.example")
    out = await _run(
        h["engine"],
        h["registry"],
        "users_block",
        {"email": "m@corp.example"},
        hr,
    )
    assert out.get("code") == "service_unavailable"
