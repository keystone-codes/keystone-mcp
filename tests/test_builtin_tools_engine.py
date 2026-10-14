"""Every built-in administration tool runs through RouterEngine."""

from __future__ import annotations

from uuid import uuid4

import pytest

from keystone_mcp.catalog.names import BUILTIN_TOOL_NAMES
from keystone_mcp.identity import VerifiedIdentity
from support.admin_harness import build_admin_harness

ADMIN = VerifiedIdentity(email="admin@example.com")

_BUILTIN_TOOL_ARGS: dict[str, dict] = {
    "users_list": {},
    "users_add": {"email": "builtin-add@example.com", "full_name": "New", "roles": ["member"]},
    "users_update": {"email": "u@example.com", "full_name": "Updated"},
    "users_block": {"email": "u@example.com"},
    "users_unblock": {"email": "u@example.com"},
    "users_set_roles": {"email": "u@example.com", "roles": ["member"]},
    "users_grant_role": {"email": "u@example.com", "role": "member"},
    "users_revoke_role": {"email": "u@example.com", "role": "member"},
    "users_logout": {"email": "u@example.com"},
    "users_export": {"email": "u@example.com"},
    "users_delete": {"email": "u@example.com"},
    "service_accounts_list": {},
    "service_accounts_add": {"name": "helper", "roles": ["member"]},
    "service_accounts_update": {"name": "ci", "description": "updated"},
    "api_keys_issue": {"subject": "svc:ci", "label": "engine-test"},
    "api_keys_list": {},
    "api_keys_revoke": {},
    "policy_read": {},
    "policy_catalog": {},
    "policy_validate": {},
    "policy_role_set": {"role": "scratch", "allow": ["docs_read"]},
    "policy_role_delete": {"role": "unused"},
    "policy_allow_add": {"role": "member", "patterns": ["users_list"]},
    "policy_allow_remove": {"role": "member", "patterns": ["users_list"]},
    "policy_list_set": {"list": "critical_tools", "patterns": ["docs_search"]},
    "policy_rollback": {},
}


def test_args_table_covers_every_builtin_tool_name() -> None:
    assert set(_BUILTIN_TOOL_ARGS) == set(BUILTIN_TOOL_NAMES)


@pytest.mark.parametrize("tool_name", sorted(BUILTIN_TOOL_NAMES))
async def test_every_builtin_tool_runs_through_the_engine(tmp_path, tool_name: str) -> None:
    harness = await build_admin_harness(tmp_path)
    route = harness.registry.get(tool_name)
    assert route is not None, tool_name
    args = dict(_BUILTIN_TOOL_ARGS[tool_name])
    if tool_name == "users_add":
        args["email"] = f"user-{uuid4().hex[:8]}@example.com"
    if tool_name == "service_accounts_add":
        args["name"] = f"sa-{uuid4().hex[:8]}"
    if tool_name == "api_keys_revoke":
        issued = await harness.users_store.issue_api_key(
            subject="u@example.com",
            label="revoke-me",
            expires_in_days=1,
            created_by="system:test",
        )
        args["key_id"] = issued.record.key_id
    if tool_name == "policy_allow_remove":
        add_route = harness.registry.get("policy_allow_add")
        assert add_route is not None
        await harness.engine.execute(
            add_route,
            {"role": "member", "patterns": ["users_list"]},
            identity=ADMIN,
        )
    if tool_name == "users_delete":
        first = await harness.engine.execute(route, args, identity=ADMIN)
        assert first["state"] == "confirmation_required"
        args = {**args, "confirmation": first["confirmation"]}
    result = await harness.engine.execute(route, args, identity=ADMIN)
    assert isinstance(result, dict)
    if tool_name == "policy_rollback":
        assert result["state"] == "error"
        assert result["code"] == "nothing_to_rollback"
    else:
        assert result["state"] == "done", result
