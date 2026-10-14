"""build_server wires the built-in UsersStore and the active RBAC policy's
role names into the users_* tools, end to end.

The shipped default policy (``config/rbac-policy.yaml``) declares only the
``administrator`` role (always-on admin bypass), which is always accepted regardless of policy
and so would not exercise the policy-role-source wiring on its own. This test
therefore uses a temporary policy file with one additional role (``member``),
the same pattern already used by
``tests/test_users_admin_adapter.py::test_rbac_denies_users_tools_for_non_administrator``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.server import bootstrap_rbac_policy, build_server
from support.test_env import UNUSED_REDIS_URL
from support.users_store import make_users_store

ADMIN = VerifiedIdentity(email="admin@example.com")

POLICY_YAML = """\
version: "test-server-wiring"
default_deny: true
roles:
  administrator:
    description: admin
    allow: ["*"]
  member:
    description: member
    allow: ["users_add", "users_list"]
"""


@pytest.mark.asyncio
async def test_build_server_passes_store_and_policy_roles_to_users_tools(
    tmp_path: Path,
) -> None:
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(POLICY_YAML, encoding="utf-8")

    store, _revision = await make_users_store(tmp_path)
    await store.create_user(
        email="admin@example.com",
        full_name="Admin",
        roles=["administrator"],
        note=None,
        created_by="system:test",
        allowed_roles=None,
    )

    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_backend="local",
        redis_url=UNUSED_REDIS_URL,
        rbac_audit_subject_salt="test-salt",
    )

    _mcp, registry, _oauth, _upstreams, policy_manager, _observability, _reconciler = build_server(
        settings=settings,
        users_store=store,
        oauth_store=InMemoryOAuthStore(),
    )
    bootstrap_rbac_policy(policy_manager, registry)

    route = registry.get("users_add")
    assert route is not None
    engine = RouterEngine(settings)

    allowed = await engine.execute(
        route,
        {"email": "member@example.com", "full_name": "Member", "roles": ["member"]},
        identity=ADMIN,
    )
    assert allowed["state"] == "done"
    assert allowed["user"]["roles"] == ["member"]

    rejected = await engine.execute(
        route,
        {"email": "ghost@example.com", "full_name": "Ghost", "roles": ["ghost"]},
        identity=ADMIN,
    )
    assert rejected["state"] == "error"
    assert rejected["code"] == "validation_error"
    assert "unknown role" in rejected["message"]
