"""Full-administrator gate on policy changes that touch administration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastmcp import FastMCP

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.rbac.management import snapshot_and_file_management_source
from keystone_mcp.rbac.policy import hash_policy_bytes
from keystone_mcp.rbac.policy_document import RoleSet
from keystone_mcp.rbac.policy_store import PolicyStore
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.server import policy_role_source
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.users.revision import NullRevisionWriter
from support.test_env import UNUSED_REDIS_URL
from support.users_store import make_users_store

POLICY_YAML = """\
version: "a04-policy-mgmt"
default_deny: true
roles:
  administrator:
    allow: ["*"]
  pol:
    allow: ["policy_*", "docs_*"]
  analyst:
    allow: ["docs_read"]
  ops:
    allow: ["*"]
  temp:
    allow: ["docs_search"]
  boss:
    allow: ["*"]
requires_human_identity: []
critical_tools: []
"""

A1 = VerifiedIdentity(email="a1@example.com")
A2 = VerifiedIdentity(email="a2@example.com")
PE = VerifiedIdentity(email="pe@example.com")
BOB = VerifiedIdentity(email="bob@example.com")
BOSS = VerifiedIdentity(email="boss@example.com")


async def _build_harness(
    tmp_path: Path,
    *,
    policy_yaml: str = POLICY_YAML,
    observability: object | None = None,
) -> dict:
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(policy_yaml, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        policy_tools="full",
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/users.db",
        redis_url=UNUSED_REDIS_URL,
    )
    store, _revision = await make_users_store(tmp_path, revision=NullRevisionWriter())
    directory = LocalUserDirectory(store)
    for email, roles in [
        ("a1@example.com", ["administrator"]),
        ("a2@example.com", ["administrator"]),
        ("pe@example.com", ["pol"]),
        ("bob@example.com", ["analyst"]),
        ("boss@example.com", ["boss"]),
    ]:
        await directory.create_user(
            email=email,
            full_name=email,
            roles=roles,
            note=None,
            actor="system:test",
        )
    engine = RouterEngine(settings)
    mcp = FastMCP("policy-mgmt-rule")
    registry = RouterRegistry(engine, mcp)
    registry.add_route("docs_read", StubAdapter(), mode="live")
    registry.add_route("docs_search", StubAdapter(), mode="live")
    manager = RbacPolicyManager(settings)
    policy_store = PolicyStore(
        settings=settings,
        policy_manager=manager,
        registry=registry,
        observability=observability,
        directory=directory,
    )
    register_catalog(
        registry,
        settings,
        directory=directory,
        observability=observability,
        role_source=policy_role_source(manager),
        management_source=snapshot_and_file_management_source(manager),
        policy_store=policy_store,
    )
    manager.load_initial(registry)
    manager.reload(registry)
    return {
        "engine": engine,
        "registry": registry,
        "settings": settings,
        "policy_path": policy_path,
        "manager": manager,
        "policy_store": policy_store,
        "directory": directory,
    }


async def _run(engine, registry, tool: str, args: dict, identity: VerifiedIdentity) -> dict:
    route = registry.get(tool)
    assert route is not None, tool
    return await engine.execute(route, args, identity=identity)


async def _file_hash(h: dict) -> str:
    out = await _run(h["engine"], h["registry"], "policy_read", {}, A1)
    assert out["state"] == "done"
    return out["file_hash"]


@pytest.mark.asyncio
async def test_policy_editor_cannot_extend_own_management_role(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    before = h["policy_path"].read_text(encoding="utf-8")
    out = await _run(
        h["engine"],
        h["registry"],
        "policy_allow_add",
        {"role": "pol", "patterns": ["users_*"], "expected_hash": await _file_hash(h)},
        PE,
    )
    assert out.get("code") == "forbidden"
    assert h["policy_path"].read_text(encoding="utf-8") == before


@pytest.mark.asyncio
async def test_policy_editor_cannot_cut_the_administrator_role(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    out = await _run(
        h["engine"],
        h["registry"],
        "policy_role_set",
        {
            "role": "administrator",
            "allow": ["users_*", "policy_*", "service_accounts_*"],
            "expected_hash": await _file_hash(h),
        },
        PE,
    )
    assert out.get("code") == "forbidden"


@pytest.mark.asyncio
async def test_policy_editor_cannot_make_a_role_management(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    out = await _run(
        h["engine"],
        h["registry"],
        "policy_allow_add",
        {
            "role": "analyst",
            "patterns": ["users_block"],
            "expected_hash": await _file_hash(h),
        },
        PE,
    )
    assert out.get("code") == "forbidden"


@pytest.mark.asyncio
async def test_policy_editor_cannot_delete_a_management_role(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    out = await _run(
        h["engine"],
        h["registry"],
        "policy_role_delete",
        {"role": "ops", "expected_hash": await _file_hash(h)},
        PE,
    )
    assert out.get("code") == "forbidden"


@pytest.mark.asyncio
async def test_policy_editor_cannot_change_deny_or_admin_human_gate(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    file_hash = await _file_hash(h)
    deny = await _run(
        h["engine"],
        h["registry"],
        "policy_list_set",
        {"list": "deny", "patterns": ["docs_read"], "expected_hash": file_hash},
        PE,
    )
    assert deny.get("code") == "forbidden"
    human = await _run(
        h["engine"],
        h["registry"],
        "policy_list_set",
        {
            "list": "requires_human_identity",
            "patterns": ["users_*"],
            "expected_hash": file_hash,
        },
        PE,
    )
    assert human.get("code") == "forbidden"


@pytest.mark.asyncio
async def test_policy_editor_edits_ordinary_roles(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    steps = [
        ("policy_allow_add", {"role": "analyst", "patterns": ["docs_search"]}),
        ("policy_role_set", {"role": "reader", "allow": ["docs_read"]}),
        ("policy_role_delete", {"role": "temp"}),
        ("policy_list_set", {"list": "critical_tools", "patterns": ["docs_read"]}),
        (
            "policy_list_set",
            {"list": "requires_human_identity", "patterns": ["docs_read"]},
        ),
        ("policy_allow_add", {"role": "analyst", "patterns": ["users_list"]}),
    ]
    for tool, args in steps:
        args = {**args, "expected_hash": await _file_hash(h)}
        out = await _run(h["engine"], h["registry"], tool, args, PE)
        assert out.get("state") == "done", (tool, out)


@pytest.mark.asyncio
async def test_policy_editor_cannot_roll_back_a_management_change(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    file_hash = await _file_hash(h)
    mgmt = await _run(
        h["engine"],
        h["registry"],
        "policy_allow_add",
        {
            "role": "analyst",
            "patterns": ["users_block"],
            "expected_hash": file_hash,
        },
        A1,
    )
    assert mgmt.get("state") == "done"
    rollback_mgmt = await _run(
        h["engine"],
        h["registry"],
        "policy_rollback",
        {"expected_hash": await _file_hash(h)},
        PE,
    )
    assert rollback_mgmt.get("code") == "forbidden"

    ordinary = await _run(
        h["engine"],
        h["registry"],
        "policy_allow_add",
        {"role": "temp", "patterns": ["docs_read"], "expected_hash": await _file_hash(h)},
        A1,
    )
    assert ordinary.get("state") == "done"
    rollback_ok = await _run(
        h["engine"],
        h["registry"],
        "policy_rollback",
        {"expected_hash": await _file_hash(h)},
        PE,
    )
    assert rollback_ok.get("state") == "done"


@pytest.mark.asyncio
async def test_full_administrator_makes_every_change(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    steps = [
        ("policy_allow_add", {"role": "pol", "patterns": ["users_*"]}),
        ("policy_allow_add", {"role": "analyst", "patterns": ["users_block"]}),
        ("policy_role_delete", {"role": "ops"}),
        ("policy_list_set", {"list": "deny", "patterns": ["docs_read"]}),
        (
            "policy_list_set",
            {"list": "requires_human_identity", "patterns": ["users_*"]},
        ),
        (
            "policy_role_set",
            {
                "role": "administrator",
                "allow": ["users_*", "policy_*", "service_accounts_*"],
            },
        ),
    ]
    for tool, args in steps:
        args = {**args, "expected_hash": await _file_hash(h)}
        out = await _run(h["engine"], h["registry"], tool, args, A1)
        assert out.get("state") == "done", (tool, out)


@pytest.mark.asyncio
async def test_full_administrator_by_roles_not_name(tmp_path: Path) -> None:
    policy = """\
version: "owner-only"
default_deny: true
roles:
  owner:
    allow: ["*"]
  analyst:
    allow: ["docs_read"]
requires_human_identity: []
critical_tools: []
"""
    h = await _build_harness(tmp_path, policy_yaml=policy)
    store = h["directory"]._store  # noqa: SLF001
    await store.create_user(
        email="owner@example.com",
        full_name="Owner",
        roles=["owner"],
        note=None,
        created_by="system:test",
        allowed_roles=None,
    )
    owner = VerifiedIdentity(email="owner@example.com")
    out = await _run(
        h["engine"],
        h["registry"],
        "policy_allow_add",
        {
            "role": "analyst",
            "patterns": ["users_block"],
            "expected_hash": await _file_hash(h),
        },
        owner,
    )
    assert out.get("state") == "done"


@pytest.mark.asyncio
async def test_full_admin_check_uses_file_read_under_lock(tmp_path: Path) -> None:
    h = await _build_harness(tmp_path)
    stale_manager = RbacPolicyManager(h["settings"])
    stale_manager.load_initial(h["registry"])
    stale_store = PolicyStore(
        settings=h["settings"],
        policy_manager=stale_manager,
        registry=h["registry"],
        directory=h["directory"],
    )
    file_hash = await _file_hash(h)
    await stale_store.change(
        changes=[RoleSet("boss", ["policy_*", "docs_read"])],
        actor="a1@example.com",
        actor_roles=frozenset({"administrator"}),
        expected_hash=file_hash,
        operation="policy_role_set",
        task_id="test",
    )
    out = await _run(
        h["engine"],
        h["registry"],
        "policy_allow_add",
        {
            "role": "analyst",
            "patterns": ["users_block"],
            "expected_hash": hash_policy_bytes(h["policy_path"].read_bytes()),
        },
        BOSS,
    )
    assert out.get("code") == "forbidden"


@pytest.mark.asyncio
async def test_management_refusal_is_audited_and_counted(tmp_path: Path) -> None:
    observability = MagicMock()
    h = await _build_harness(tmp_path, observability=observability)
    await _run(
        h["engine"],
        h["registry"],
        "policy_allow_add",
        {
            "role": "pol",
            "patterns": ["users_*"],
            "expected_hash": await _file_hash(h),
        },
        PE,
    )
    observability.record_policy_mutation.assert_called()
    assert observability.record_policy_mutation.call_args.kwargs["outcome"] == "refused"
    assert observability.record_policy_mutation.call_args.kwargs["code"] == "forbidden"
    observability.record_admin_refusal.assert_called_with(
        operation="policy_allow_add",
        reason="management_role",
    )
