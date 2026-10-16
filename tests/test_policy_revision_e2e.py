"""E2E: policy change reaches a second replica without reconciler tick."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.observability.service import RbacObservability
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.rbac.policy_document import AllowRemove
from keystone_mcp.rbac.policy_revision import PolicyRevisionWatcher, RedisPolicyRevisionStore
from keystone_mcp.redis_client import redis_from_url
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.rbac_middleware import RbacMiddleware
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.server import _policy_store_holder, bootstrap_rbac_policy, build_server
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from keystone_mcp.users.factory import build_users_store
from support.test_env import policy_revision_key, require_redis_url

POLICY = """\
version: "1.0.0"
default_deny: true
roles:
  administrator:
    allow: ["*"]
  editor:
    allow:
      - docs_read
      - policy_allow_remove
      - policy_read
"""

EDITOR = VerifiedIdentity(email="editor@example.com")
ADMIN_ROLES = frozenset({"administrator"})


@pytest.mark.asyncio
async def test_policy_change_reaches_second_replica_without_tick(tmp_path: Path) -> None:
    require_redis_url()
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(POLICY, encoding="utf-8")
    rev_key = f"{policy_revision_key('e2e')}:{uuid4().hex}"
    settings_a = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        policy_tools="full",
        redis_url=require_redis_url(),
        refresh_interval_seconds=0,
        policy_redis_revision_key=rev_key,
        rbac_audit_subject_salt="e2e",
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/users-a.db",
    )
    settings_b = Settings(
        base_url="http://localhost:8081",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        policy_tools="full",
        redis_url=require_redis_url(),
        refresh_interval_seconds=0,
        policy_redis_revision_key=rev_key,
        rbac_audit_subject_salt="e2e",
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/users-b.db",
    )

    users_store = build_users_store(settings_a)
    await users_store.migrate()

    mcp_a, registry_a, _oauth_a, _up_a, pm_a, obs_a, _rec_a = build_server(
        settings=settings_a,
        users_store=users_store,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    del mcp_a
    for name in ("docs_read", "policy_allow_remove", "policy_read"):
        registry_a.add_route(name, StubAdapter(), mode="live")
    bootstrap_rbac_policy(pm_a, registry_a)
    store_a = _policy_store_holder["store"]
    assert store_a is not None
    await store_a.change(
        changes=[AllowRemove("editor", ["policy_allow_remove"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_remove",
        task_id="e2e-1",
    )

    redis_client = redis_from_url(require_redis_url())
    try:
        rev_store = RedisPolicyRevisionStore(redis_client, key=rev_key)
        registry_b = RouterRegistry(RouterEngine(settings_b), FastMCP("replica-b"))
        for name in ("docs_read", "policy_allow_remove", "policy_read"):
            registry_b.add_route(name, StubAdapter(), mode="live")
        resolver_b, backend_b, _ = build_in_memory_user_directory_resolver()
        backend_b.seed("editor@example.com", roles=("editor",))
        pm_b = RbacPolicyManager(settings_b)
        pm_b.load_initial(registry_b)
        obs_b = RbacObservability(settings_b, policy_manager=pm_b)
        watcher_b = PolicyRevisionWatcher(
            store=rev_store,
            policy_manager=pm_b,
            registry=registry_b,
            observability=obs_b,
            min_interval_seconds=0.0,
        )
        middleware_b = RbacMiddleware(
            pm_b,
            resolver_b,
            enforce=True,
            policy_revision_watcher=watcher_b,
        )

        async def call_next(_ctx):
            return {"ok": True}

        ctx = MiddlewareContext(message=type("Msg", (), {"name": "policy_allow_remove"})())
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
                lambda: EDITOR,
            )
            with pytest.raises(ToolError, match="access denied"):
                await middleware_b.on_call_tool(ctx, call_next)
    finally:
        await redis_client.aclose()
