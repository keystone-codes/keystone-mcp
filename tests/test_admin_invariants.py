"""Full-administrator self-service guards (policy-derived, not role name)."""

from __future__ import annotations

from pathlib import Path

import pytest

from keystone_mcp.identity import VerifiedIdentity
from support.admin_harness import (
    OWNER_INVARIANTS_POLICY,
    build_owner_invariants_harness,
    run_admin_tool,
)

O1 = VerifiedIdentity(email="o1@corp.example")
O2 = VerifiedIdentity(email="o2@corp.example")
MEMBER = VerifiedIdentity(email="member@corp.example")


async def _roles(harness, email: str) -> tuple[str, ...]:
    resolved = await harness.directory.resolve_user(email)
    assert resolved.exists
    return resolved.roles


@pytest.mark.asyncio
async def test_owner_cannot_block_or_demote_self(tmp_path: Path) -> None:
    harness = await build_owner_invariants_harness(tmp_path)
    before_roles = await _roles(harness, O1.email)

    blocked = await run_admin_tool(harness, "users_block", {"email": O1.email}, O1)
    assert blocked["code"] == "self_admin_mutation_forbidden"
    assert await _roles(harness, O1.email) == before_roles

    revoked = await run_admin_tool(
        harness,
        "users_revoke_role",
        {"email": O1.email, "role": "owner"},
        O1,
    )
    assert revoked["code"] == "self_admin_mutation_forbidden"
    assert await _roles(harness, O1.email) == before_roles

    demoted = await run_admin_tool(
        harness,
        "users_set_roles",
        {"email": O1.email, "roles": ["member"]},
        O1,
    )
    assert demoted["code"] == "self_admin_mutation_forbidden"
    assert await _roles(harness, O1.email) == before_roles


@pytest.mark.asyncio
async def test_owner_keeps_self_when_another_role_still_gives_full_admin(
    tmp_path: Path,
) -> None:
    policy = OWNER_INVARIANTS_POLICY
    harness = await build_owner_invariants_harness(tmp_path, policy_yaml=policy)
    await harness.directory.grant_role(email=O1.email, role="boss", actor="system:test")
    out = await run_admin_tool(
        harness,
        "users_revoke_role",
        {"email": O1.email, "role": "owner"},
        O1,
    )
    assert out["state"] == "done"
    roles = await _roles(harness, O1.email)
    assert "boss" in roles
    assert "owner" not in roles


@pytest.mark.asyncio
async def test_owner_demotes_another_owner(tmp_path: Path) -> None:
    harness = await build_owner_invariants_harness(tmp_path)
    out = await run_admin_tool(
        harness,
        "users_revoke_role",
        {"email": O2.email, "role": "owner"},
        O1,
    )
    assert out["state"] == "done"
    roles = await _roles(harness, O2.email)
    assert "owner" not in roles


@pytest.mark.asyncio
async def test_self_rule_does_not_apply_to_other_targets(tmp_path: Path) -> None:
    harness = await build_owner_invariants_harness(tmp_path)
    out = await run_admin_tool(
        harness,
        "users_block",
        {"email": MEMBER.email},
        O1,
    )
    assert out["state"] == "done"
    resolved = await harness.directory.resolve_user(MEMBER.email)
    assert resolved.is_blocked
