"""Human-identity gate: policy-declared tools need an interactive login."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext

from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.human_identity import (
    INTERACTIVE_AUTH_METHOD,
    has_interactive_human_identity,
    requires_human_identity,
)
from keystone_mcp.rbac.policy import parse_policy_yaml
from keystone_mcp.router.rbac_middleware import RbacDenialReason
from support.rbac_conformance import (
    CONFORMANCE_EMAIL,
    DecisionRecorder,
    build_conformance_harness,
    conformance_policy,
)

GATED_TOOLS = ("ledger_commit",)
UNGATED_TOOLS = ("ledger_propose", "documents_write", "reports_read")

POLICY_WITHOUT_GATE = """\
version: "no-gate"
default_deny: true
roles:
  administrator:
    allow: ["*"]
"""

POLICY_WITH_GLOB_GATE = """\
version: "glob-gate"
default_deny: true
roles:
  administrator:
    allow: ["*"]
requires_human_identity: ["ledger_*"]
"""


def _identity(auth_method: str) -> VerifiedIdentity:
    return VerifiedIdentity(
        email=CONFORMANCE_EMAIL,
        claims={"email": CONFORMANCE_EMAIL, "auth_method": auth_method},
    )


@pytest.fixture
def patch_api_key_identity(monkeypatch):
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: _identity("api_key"),
    )


@pytest.fixture
def patch_google_identity(monkeypatch):
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: _identity(INTERACTIVE_AUTH_METHOD),
    )


async def _async_noop(_context):
    return {"ok": True}


# --- unit ------------------------------------------------------------------------


def test_interactive_identity_detection():
    assert has_interactive_human_identity(None) is False
    assert has_interactive_human_identity(VerifiedIdentity(email="a@b.c")) is False
    assert has_interactive_human_identity(_identity("api_key")) is False
    assert has_interactive_human_identity(_identity(INTERACTIVE_AUTH_METHOD)) is True


def test_requires_human_identity_reads_the_policy():
    policy = conformance_policy()
    assert policy.requires_human_identity("ledger_commit") is True
    assert policy.requires_human_identity("ledger_propose") is False
    assert requires_human_identity("ledger_commit", policy) is True
    assert requires_human_identity("ledger_propose", policy) is False


def test_requires_human_identity_without_a_policy_is_false():
    assert requires_human_identity("ledger_commit", None) is False


def test_gate_supports_globs():
    policy = parse_policy_yaml(POLICY_WITH_GLOB_GATE)
    assert policy.requires_human_identity("ledger_commit") is True
    assert policy.requires_human_identity("ledger_read") is True
    assert policy.requires_human_identity("reports_read") is False


def test_absent_section_gates_nothing():
    policy = parse_policy_yaml(POLICY_WITHOUT_GATE)
    assert policy.human_identity_patterns == ()
    assert policy.requires_human_identity("ledger_commit") is False


# --- middleware ------------------------------------------------------------------


@pytest.mark.parametrize("tool", GATED_TOOLS)
@pytest.mark.asyncio
async def test_gated_tool_denied_for_machine_identity(patch_api_key_identity, tool: str):
    harness = build_conformance_harness(roles=("administrator",))
    ctx = MiddlewareContext(message=type("Msg", (), {"name": tool})())
    recorder = DecisionRecorder()
    recorder.attach(harness.middleware)

    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)

    assert recorder.last is not None
    assert recorder.last.reason == RbacDenialReason.HUMAN_IDENTITY_REQUIRED


@pytest.mark.parametrize("tool", GATED_TOOLS)
@pytest.mark.asyncio
async def test_gated_tool_allowed_for_interactive_identity(patch_google_identity, tool: str):
    harness = build_conformance_harness(roles=("administrator",))
    ctx = MiddlewareContext(message=type("Msg", (), {"name": tool})())
    assert await harness.middleware.on_call_tool(ctx, _async_noop) == {"ok": True}


@pytest.mark.parametrize("tool", UNGATED_TOOLS)
@pytest.mark.asyncio
async def test_ungated_tool_allows_machine_identity(patch_api_key_identity, tool: str):
    harness = build_conformance_harness(roles=("administrator",))
    ctx = MiddlewareContext(message=type("Msg", (), {"name": tool})())
    assert await harness.middleware.on_call_tool(ctx, _async_noop) == {"ok": True}


@pytest.mark.asyncio
async def test_gate_comes_from_the_policy_file_not_from_code(
    patch_api_key_identity,
    tmp_path,
):
    """The same tool passes with no requires_human_identity section."""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(POLICY_WITHOUT_GATE, encoding="utf-8")
    harness = build_conformance_harness(
        roles=("administrator",),
        policy_path=policy_path,
    )
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "ledger_commit"})())
    assert await harness.middleware.on_call_tool(ctx, _async_noop) == {"ok": True}


@pytest.mark.asyncio
async def test_yaml_declared_gate_is_enforced_by_the_middleware(
    patch_api_key_identity,
    tmp_path,
):
    """A tool gated only by YAML (never named in code) is refused."""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """\
version: "yaml-gate"
default_deny: true
roles:
  administrator:
    allow: ["*"]
requires_human_identity: ["documents_write"]
""",
        encoding="utf-8",
    )
    harness = build_conformance_harness(roles=("administrator",), policy_path=policy_path)
    recorder = DecisionRecorder()
    recorder.attach(harness.middleware)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "documents_write"})())

    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)
    assert recorder.last is not None
    assert recorder.last.reason == RbacDenialReason.HUMAN_IDENTITY_REQUIRED

    # A tool outside the gate still passes under the same identity.
    other = MiddlewareContext(message=type("Msg", (), {"name": "documents_read"})())
    assert await harness.middleware.on_call_tool(other, _async_noop) == {"ok": True}


@pytest.mark.asyncio
async def test_gate_applies_after_the_allow_check(patch_api_key_identity):
    """A role that cannot reach the tool is denied as not permitted, not as ungated."""
    harness = build_conformance_harness(roles=("viewer",))
    recorder = DecisionRecorder()
    recorder.attach(harness.middleware)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "ledger_commit"})())

    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)
    assert recorder.last is not None
    assert recorder.last.reason == RbacDenialReason.NOT_PERMITTED
