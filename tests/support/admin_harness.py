"""Shared harness: every built-in admin tool on a local directory."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastmcp import FastMCP

from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.rbac.policy_store import PolicyStore
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.server import policy_role_source
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.users.revision import NullRevisionWriter
from keystone_mcp.users.store import UsersStore
from support.test_env import require_redis_url
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
    from keystone_mcp.adapters.stub import StubAdapter

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
        redis_url=require_redis_url(),
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
    register_catalog(
        registry,
        settings,
        directory=directory,
        observability=observability,
        role_source=policy_role_source(manager),
        policy_store=policy_store,
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
