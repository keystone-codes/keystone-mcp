"""Delegation rule: grant only roles within the actor's permissions."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from keystone_mcp.identity import VerifiedIdentity
from support.admin_harness import build_delegation_harness, run_admin_tool


@pytest.mark.asyncio
async def test_delegate_grants_roles_within_own_rights(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    hr = VerifiedIdentity(email="hr@corp.example")
    out = await run_admin_tool(
        h,
        "users_add",
        {"email": "new@corp.example", "full_name": "New", "roles": ["reader"]},
        hr,
    )
    assert out["state"] == "done"
    out = await run_admin_tool(
        h,
        "users_grant_role",
        {"email": "m@corp.example", "role": "reader"},
        hr,
    )
    assert out["state"] == "done"


@pytest.mark.asyncio
async def test_delegate_cannot_grant_roles_beyond_own_rights(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    hr = VerifiedIdentity(email="hr@corp.example")
    bob_before = await h["directory"].resolve_user("bob@corp.example")
    out = await run_admin_tool(
        h,
        "users_grant_role",
        {"email": "bob@corp.example", "role": "finance"},
        hr,
    )
    assert out.get("code") == "forbidden"
    assert "finance" in out.get("message", "")
    bob_after = await h["directory"].resolve_user("bob@corp.example")
    assert bob_after.roles == bob_before.roles
    out = await run_admin_tool(
        h,
        "users_add",
        {"email": "wide@corp.example", "full_name": "Wide", "roles": ["docsplus"]},
        hr,
    )
    assert out.get("code") == "forbidden"
    assert "docsplus" in out.get("message", "")


@pytest.mark.asyncio
async def test_set_roles_checks_only_added_roles(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    hr = VerifiedIdentity(email="hr@corp.example")
    out = await run_admin_tool(
        h,
        "users_set_roles",
        {"email": "m@corp.example", "roles": ["finance", "reader"]},
        hr,
    )
    assert out["state"] == "done"
    out = await run_admin_tool(
        h,
        "users_set_roles",
        {"email": "m@corp.example", "roles": ["docsplus"]},
        hr,
    )
    assert out.get("code") == "forbidden"
    assert "docsplus" in out.get("message", "")


@pytest.mark.asyncio
async def test_revoke_is_not_limited(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    hr = VerifiedIdentity(email="hr@corp.example")
    out = await run_admin_tool(
        h,
        "users_revoke_role",
        {"email": "m@corp.example", "role": "finance"},
        hr,
    )
    assert out["state"] == "done"


@pytest.mark.asyncio
async def test_unpublished_service_needs_the_literal_pattern(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    hr = VerifiedIdentity(email="hr@corp.example")
    out = await run_admin_tool(
        h,
        "users_grant_role",
        {"email": "bob@corp.example", "role": "crm"},
        hr,
    )
    assert out.get("code") == "forbidden"
    crmhr = VerifiedIdentity(email="crmhr@corp.example")
    out = await run_admin_tool(
        h,
        "users_grant_role",
        {"email": "bob@corp.example", "role": "crm"},
        crmhr,
    )
    assert out["state"] == "done"


@pytest.mark.asyncio
async def test_full_administrator_grants_anything(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    admin = VerifiedIdentity(email="a1@corp.example")
    for role in ("finance", "docsplus", "crm"):
        out = await run_admin_tool(
            h,
            "users_grant_role",
            {"email": "bob@corp.example", "role": role},
            admin,
        )
        assert out["state"] == "done", role


@pytest.mark.asyncio
async def test_service_account_roles_follow_the_same_rule(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    sam = VerifiedIdentity(email="sam@corp.example")
    await h["directory"].create_user(
        email="sam@corp.example",
        full_name="Sam",
        roles=["sam"],
        note=None,
        actor="system:test",
    )
    out = await run_admin_tool(
        h,
        "service_accounts_add",
        {"name": "bot-reader", "roles": ["reader"]},
        sam,
    )
    assert out["state"] == "done"
    out = await run_admin_tool(
        h,
        "service_accounts_add",
        {"name": "bot-finance", "roles": ["finance"]},
        sam,
    )
    assert out.get("code") == "forbidden"
    assert "finance" in out.get("message", "")


@pytest.mark.asyncio
async def test_delegation_refusal_is_audited_and_counted(tmp_path: Path) -> None:
    observability = MagicMock()
    h = await build_delegation_harness(tmp_path, observability=observability)
    hr = VerifiedIdentity(email="hr@corp.example")
    await run_admin_tool(
        h,
        "users_grant_role",
        {"email": "bob@corp.example", "role": "finance"},
        hr,
    )
    observability.record_users_mutation.assert_called()
    assert observability.record_users_mutation.call_args.kwargs["code"] == "forbidden"
    observability.record_admin_refusal.assert_called_with(
        operation="users_grant_role",
        reason="delegation",
    )


@pytest.mark.asyncio
async def test_one_directory_lookup_per_role_check(tmp_path: Path) -> None:
    h = await build_delegation_harness(tmp_path)
    directory = h["directory"]
    original = directory.resolve_user
    counter = {"n": 0}

    async def counting_resolve(subject: str):
        counter["n"] += 1
        return await original(subject)

    directory.resolve_user = counting_resolve  # type: ignore[method-assign]
    hr = VerifiedIdentity(email="hr@corp.example")
    await run_admin_tool(
        h,
        "users_grant_role",
        {"email": "bob@corp.example", "role": "reader"},
        hr,
    )
    assert counter["n"] == 2
