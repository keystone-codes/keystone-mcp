"""Service accounts cannot mutate administration state."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from keystone_mcp.catalog.names import MUTATING_ADMIN_TOOL_NAMES, READ_ONLY_ADMIN_TOOL_NAMES
from keystone_mcp.identity import VerifiedIdentity
from support.admin_harness import build_admin_harness

ADMIN = VerifiedIdentity(email="admin@example.com")
SERVICE = VerifiedIdentity(
    "svc:ci",
    subject_type="service",
    claims={"subject_type": "service"},
)

_MUTATING_ARGS: dict[str, dict] = {
    "users_add": {
        "email": "new@example.com",
        "full_name": "Intruder",
        "roles": ["administrator"],
    },
    "users_update": {"email": "u@example.com", "full_name": "x"},
    "users_block": {"email": "u@example.com"},
    "users_unblock": {"email": "u@example.com"},
    "users_set_roles": {"email": "u@example.com", "roles": ["administrator"]},
    "users_grant_role": {"email": "u@example.com", "role": "administrator"},
    "users_revoke_role": {"email": "u@example.com", "role": "member"},
    "users_logout": {"email": "u@example.com"},
    "service_accounts_add": {"name": "evil", "roles": ["member"]},
    "service_accounts_update": {"name": "ci", "description": "pwned"},
    "api_keys_issue": {"subject": "svc:ci"},
    "api_keys_revoke": {"key_id": "placeholder"},
    "policy_role_set": {"role": "evil", "allow": ["*"]},
    "policy_role_delete": {"role": "member"},
    "policy_allow_add": {"role": "member", "patterns": ["*"]},
    "policy_allow_remove": {"role": "member", "patterns": ["docs_read"]},
    "policy_list_set": {"list": "deny", "patterns": ["*"]},
    "policy_rollback": {},
}


@pytest.mark.parametrize("tool_name", sorted(MUTATING_ADMIN_TOOL_NAMES))
async def test_service_account_is_refused_on_every_mutating_admin_tool(
    tmp_path, tool_name: str
) -> None:
    harness = await build_admin_harness(tmp_path)
    route = harness.registry.get(tool_name)
    assert route is not None
    args = dict(_MUTATING_ARGS[tool_name])
    if tool_name == "api_keys_revoke":
        args["key_id"] = harness.issued_key_id
    result = await harness.engine.execute(route, args, identity=SERVICE)
    assert result["code"] == "forbidden"
    if tool_name == "users_add":
        resolved = await harness.directory.resolve_user("new@example.com")
        assert resolved.exists is False


async def test_service_account_reads_admin_lists(tmp_path) -> None:
    harness = await build_admin_harness(tmp_path)
    for tool_name in sorted(READ_ONLY_ADMIN_TOOL_NAMES):
        route = harness.registry.get(tool_name)
        assert route is not None, tool_name
        result = await harness.engine.execute(route, {}, identity=SERVICE)
        assert result["state"] == "done", tool_name


async def test_machine_refusal_is_audited_with_subject_type(tmp_path) -> None:
    observability = MagicMock()
    harness = await build_admin_harness(tmp_path, observability=observability)
    users_route = harness.registry.get("users_add")
    assert users_route is not None
    await harness.engine.execute(
        users_route,
        _MUTATING_ARGS["users_add"],
        identity=SERVICE,
    )
    observability.record_users_mutation.assert_called()
    users_call = observability.record_users_mutation.call_args.kwargs
    assert users_call["code"] == "forbidden"
    assert users_call["actor_subject_type"] == "service"
    observability.record_admin_refusal.assert_called_with(
        operation="users_add",
        reason="service_account",
    )

    observability.reset_mock()
    policy_route = harness.registry.get("policy_role_set")
    assert policy_route is not None
    await harness.engine.execute(
        policy_route,
        _MUTATING_ARGS["policy_role_set"],
        identity=SERVICE,
    )
    observability.record_policy_mutation.assert_called()
    policy_call = observability.record_policy_mutation.call_args.kwargs
    assert policy_call["outcome"] == "refused"
    assert policy_call["code"] == "forbidden"
    assert policy_call["actor_subject_type"] == "service"
    observability.record_admin_refusal.assert_called_with(
        operation="policy_role_set",
        reason="service_account",
    )
