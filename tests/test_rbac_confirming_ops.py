"""Confirming operations expressed purely in policy data.

A "confirming operation" is a deployment convention, not a platform concept:
an irreversible write that a human must confirm, paired with a proposing half.
These tests exercise the mechanisms a deployment uses to express that pairing
(``requires_human_identity``, ``critical_tools``, ``tool_dispositions`` and the
role allow lists) against the fictional fixture policy.
"""

from __future__ import annotations

import pytest
import yaml
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext

from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.matrix_doc import tool_disposition
from keystone_mcp.rbac.policy import validate_policy_structure
from keystone_mcp.router.rbac_middleware import RbacDenialReason
from keystone_mcp.user_directory.critical import is_critical_tool
from support.rbac_conformance import (
    CONFORMANCE_EMAIL,
    CONFORMANCE_POLICY_PATH,
    DecisionRecorder,
    build_conformance_harness,
    conformance_policy,
    conformance_tool_names,
)

#: (confirming op, its proposing half) as the fixture policy declares them.
CONFIRM_PROPOSE_PAIRS = (("ledger_commit", "ledger_propose"),)

#: Roles the fixture grants the confirming half.
CONFIRMING_ROLES = ("administrator", "editor", "reviewer")


@pytest.fixture
def policy():
    return conformance_policy()


@pytest.fixture
def policy_raw():
    return yaml.safe_load(CONFORMANCE_POLICY_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def patch_machine_identity(monkeypatch):
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(
            email=CONFORMANCE_EMAIL,
            claims={"email": CONFORMANCE_EMAIL, "auth_method": "api_key"},
        ),
    )


async def _async_noop(_context):
    return {"ok": True}


def test_fixture_policy_is_structurally_valid(policy):
    validate_policy_structure(policy)
    assert policy.default_deny is True


def test_confirming_ops_are_declared_in_requires_human_identity(policy):
    for confirm, _propose in CONFIRM_PROPOSE_PAIRS:
        assert policy.requires_human_identity(confirm) is True


def test_proposing_halves_are_not_gated(policy):
    for _confirm, propose in CONFIRM_PROPOSE_PAIRS:
        assert policy.requires_human_identity(propose) is False


def test_every_role_holding_a_confirm_also_holds_its_propose(policy, policy_raw):
    """The invariant a deployment cares about, checked through the policy object."""
    for role_name, spec in policy_raw["roles"].items():
        allow = spec["allow"]
        wildcard = "*" in allow
        for confirm, propose in CONFIRM_PROPOSE_PAIRS:
            if wildcard or policy.allows_role(role_name, confirm):
                assert policy.allows_role(role_name, propose) is True, (
                    f"{role_name} allows {confirm} but not the paired {propose}"
                )


def test_confirming_ops_are_reachable_by_at_least_one_role(policy):
    for confirm, _propose in CONFIRM_PROPOSE_PAIRS:
        holders = [role for role in CONFIRMING_ROLES if policy.allows_role(role, confirm)]
        assert holders, f"no role can reach {confirm}"


def test_read_only_role_does_not_receive_confirming_ops(policy):
    for confirm, _propose in CONFIRM_PROPOSE_PAIRS:
        assert policy.allows_role("viewer", confirm) is False


def test_confirming_ops_are_tagged_destructive(policy):
    for confirm, _propose in CONFIRM_PROPOSE_PAIRS:
        assert tool_disposition(confirm, policy) == "D"


def test_confirming_ops_bypass_the_allow_cache(policy):
    for confirm, _propose in CONFIRM_PROPOSE_PAIRS:
        assert is_critical_tool(confirm, policy.critical_tool_patterns) is True


def test_confirming_ops_are_part_of_the_declared_catalog(policy):
    catalog = conformance_tool_names()
    for confirm, propose in CONFIRM_PROPOSE_PAIRS:
        assert confirm in catalog
        assert propose in catalog


@pytest.mark.parametrize(("confirm", "propose"), CONFIRM_PROPOSE_PAIRS)
@pytest.mark.asyncio
async def test_machine_token_may_propose_but_not_confirm(
    patch_machine_identity,
    confirm: str,
    propose: str,
):
    harness = build_conformance_harness(roles=("editor",))
    recorder = DecisionRecorder()
    recorder.attach(harness.middleware)

    propose_ctx = MiddlewareContext(message=type("Msg", (), {"name": propose})())
    assert await harness.middleware.on_call_tool(propose_ctx, _async_noop) == {"ok": True}

    confirm_ctx = MiddlewareContext(message=type("Msg", (), {"name": confirm})())
    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(confirm_ctx, _async_noop)
    assert recorder.last is not None
    assert recorder.last.reason == RbacDenialReason.HUMAN_IDENTITY_REQUIRED
