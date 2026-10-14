"""Shared harness: every built-in admin tool on a local directory."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.login_pending_store import InMemoryLoginPendingStore
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.auth.sessions import SessionRevoker
from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import RbacPolicyManager, delegation_catalog_names
from keystone_mcp.rbac.management import snapshot_and_file_management_source
from keystone_mcp.rbac.policy_store import PolicyStore
from keystone_mcp.rbac.upstream_state import UpstreamCatalogState
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.server import policy_role_source
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.users.revision import NullRevisionWriter
from keystone_mcp.users.store import UsersStore
from support.test_env import UNUSED_REDIS_URL
from support.users_store import make_users_store

DEFAULT_POLICY_YAML = """\
version: "admin-harness"
default_deny: true
roles:
  administrator:
    allow: ["*"]
  member:
    allow:
      - docs_search
      - docs_read
  unused:
    allow:
      - docs_search
requires_human_identity: []
critical_tools: []
"""

OWNER_INVARIANTS_POLICY = """\
version: "owner-invariants"
default_deny: true
roles:
  owner:
    allow: ["*"]
  boss:
    allow: ["*"]
  member:
    allow:
      - docs_search
      - docs_read
requires_human_identity: []
critical_tools: []
"""

DELEGATION_POLICY = """\
version: "delegation-test"
default_deny: true
roles:
  administrator:
    allow: ["*"]
  hr:
    allow: ["users_*", "docs_read"]
  reader:
    allow: ["docs_read"]
  docsplus:
    allow: ["docs_*"]
  finance:
    allow: ["finance_*"]
  crm:
    allow: ["crm_*"]
  crmhr:
    allow: ["users_*", "crm_*"]
  sam:
    allow: ["service_accounts_*", "docs_read"]
requires_human_identity: []
critical_tools: []
"""


@dataclass
class AdminHarness:
    registry: RouterRegistry
    engine: RouterEngine
    settings: Settings
    directory: LocalUserDirectory
    users_store: UsersStore
    policy_store: PolicyStore
    policy_manager: RbacPolicyManager
    issued_key_id: str


async def build_admin_harness(
    tmp_path: Path,
    *,
    policy_yaml: str = DEFAULT_POLICY_YAML,
    deployment_profile: str = "local",
    observability: object | None = None,
) -> AdminHarness:
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(policy_yaml, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        deployment_profile=deployment_profile,
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        policy_tools="full",
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/keystone-users.db",
        redis_url=UNUSED_REDIS_URL,
        rbac_audit_subject_salt="test-salt",
    )
    store, _revision = await make_users_store(tmp_path, revision=NullRevisionWriter())
    await store.create_user(
        email="admin@example.com",
        full_name="Admin",
        roles=["administrator"],
        note=None,
        created_by="system:test",
        allowed_roles=None,
    )
    await store.create_user(
        email="u@example.com",
        full_name="Member",
        roles=["member"],
        note=None,
        created_by="system:test",
        allowed_roles=None,
    )
    await store.create_service_account(
        name="ci",
        description="CI",
        roles=["member"],
        created_by="system:test",
    )
    issued = await store.issue_api_key(
        subject="u@example.com",
        label="harness",
        expires_in_days=30,
        created_by="system:test",
    )
    directory = LocalUserDirectory(store)
    engine = RouterEngine(settings)
    mcp = FastMCP("admin-harness")
    registry = RouterRegistry(engine, mcp)
    stub = StubAdapter()
    registry.add_route("docs_search", stub, mode="live")
    registry.add_route("docs_read", stub, mode="live")
    manager = RbacPolicyManager(settings)
    manager.load_initial(registry)
    policy_store = PolicyStore(
        settings=settings,
        policy_manager=manager,
        registry=registry,
        observability=observability,
        directory=directory,
    )
    pending = InMemoryLoginPendingStore()
    oauth_store = InMemoryOAuthStore()
    session_revoker = SessionRevoker(oauth_store, pending)
    register_catalog(
        registry,
        settings,
        directory=directory,
        observability=observability,
        role_source=policy_role_source(manager),
        management_source=snapshot_and_file_management_source(manager),
        policy_store=policy_store,
        session_revoker=session_revoker,
        login_pending_store=pending,
        oauth_store=oauth_store,
    )
    manager.reload(registry)
    return AdminHarness(
        registry=registry,
        engine=engine,
        settings=settings,
        directory=directory,
        users_store=store,
        policy_store=policy_store,
        policy_manager=manager,
        issued_key_id=issued.record.key_id,
    )


async def build_delegation_harness(
    tmp_path: Path,
    *,
    observability: object | None = None,
    directory: LocalUserDirectory | None = None,
    store: object | None = None,
) -> dict[str, Any]:
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(DELEGATION_POLICY, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/users.db",
        redis_url=UNUSED_REDIS_URL,
        rbac_audit_subject_salt="test-salt",
    )
    if store is None:
        store, _revision = await make_users_store(tmp_path, revision=NullRevisionWriter())
    if directory is None:
        directory = LocalUserDirectory(store)
    for email, roles in [
        ("a1@corp.example", ["administrator"]),
        ("hr@corp.example", ["hr"]),
        ("m@corp.example", ["finance"]),
        ("bob@corp.example", ["reader"]),
        ("crmhr@corp.example", ["crmhr"]),
    ]:
        await directory.create_user(
            email=email,
            full_name=email,
            roles=roles,
            note=None,
            actor="system:test",
        )

    engine = RouterEngine(settings)
    mcp = FastMCP("delegation-test")
    registry = RouterRegistry(engine, mcp)
    for tool in ("docs_search", "docs_read", "finance_report"):
        registry.add_route(tool, StubAdapter(), mode="live")

    upstream_state = lambda: UpstreamCatalogState(  # noqa: E731
        namespaces=frozenset({"crm"}), unavailable=frozenset({"crm"})
    )
    manager = RbacPolicyManager(settings, upstream_catalog_state=upstream_state)

    def catalog_names_source() -> frozenset[str]:
        return delegation_catalog_names(manager, registry)

    pending = InMemoryLoginPendingStore()
    oauth_store = InMemoryOAuthStore()
    session_revoker = SessionRevoker(oauth_store, pending)
    register_catalog(
        registry,
        settings,
        directory=directory,
        observability=observability,
        role_source=policy_role_source(manager),
        management_source=snapshot_and_file_management_source(manager),
        catalog_names_source=catalog_names_source,
        session_revoker=session_revoker,
        login_pending_store=pending,
        oauth_store=oauth_store,
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
    }


async def run_admin_tool(
    harness: dict[str, Any] | AdminHarness,
    tool: str,
    args: dict[str, Any],
    identity: VerifiedIdentity,
) -> dict[str, Any]:
    if isinstance(harness, AdminHarness):
        registry = harness.registry
        engine = harness.engine
    else:
        registry = harness["registry"]
        engine = harness["engine"]
    route = registry.get(tool)
    assert route is not None
    return await engine.execute(route, args, identity=identity)


async def build_owner_invariants_harness(
    tmp_path: Path,
    *,
    policy_yaml: str = OWNER_INVARIANTS_POLICY,
    observability: object | None = None,
) -> AdminHarness:
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(policy_yaml, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        deployment_profile="local",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        policy_tools="full",
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/keystone-users.db",
        redis_url=UNUSED_REDIS_URL,
    )
    store, _revision = await make_users_store(tmp_path, revision=NullRevisionWriter())
    for email, roles in [
        ("o1@corp.example", ["owner"]),
        ("o2@corp.example", ["owner"]),
        ("member@corp.example", ["member"]),
    ]:
        await store.create_user(
            email=email,
            full_name=email,
            roles=roles,
            note=None,
            created_by="system:test",
            allowed_roles=None,
        )
    directory = LocalUserDirectory(store)
    engine = RouterEngine(settings)
    mcp = FastMCP("owner-invariants")
    registry = RouterRegistry(engine, mcp)
    stub = StubAdapter()
    registry.add_route("docs_search", stub, mode="live")
    registry.add_route("docs_read", stub, mode="live")
    manager = RbacPolicyManager(settings)
    manager.load_initial(registry)
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
    )
    manager.reload(registry)
    issued = await store.issue_api_key(
        subject="member@corp.example",
        label="harness",
        expires_in_days=30,
        created_by="system:test",
    )
    return AdminHarness(
        registry=registry,
        engine=engine,
        settings=settings,
        directory=directory,
        users_store=store,
        policy_store=policy_store,
        policy_manager=manager,
        issued_key_id=issued.record.key_id,
    )
