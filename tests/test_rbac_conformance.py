"""RBAC conformance matrix and regression suite.

Three oracle layers:

1. **Golden cases** — the hand-written tuples below, not derived from
   ``policy.allows()``. If policy and middleware drift together, these fail.
2. **Committed doc** — the generated per-tool matrix for the shipped default
   policy, re-checked against the runtime policy object.
3. **Policy coherence** — the whole fixture catalog: the middleware verdict must
   match the loaded policy for every role set.

Runtime: the real ``RbacMiddleware`` plus an in-memory user directory.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext

from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import assert_live_catalog_validation
from keystone_mcp.rbac.policy import load_policy
from keystone_mcp.router.rbac_middleware import CLIENT_DENIAL_MESSAGE, RbacDenialReason
from support.rbac_conformance import (
    CONFORMANCE_EMAIL,
    CONFORMANCE_ROLE_SETS,
    DecisionRecorder,
    build_conformance_harness,
    conformance_policy,
    conformance_snapshot,
    conformance_tool_names,
    expected_visible_tools,
    iter_policy_coherence_cases,
    live_tool_names,
    render_conformance_report,
    role_set_label,
)
from support.rbac_matrix_doc_oracle import (
    doc_allows,
    doc_roles,
    parse_committed_per_tool_matrix,
)

_PER_TOOL_MATRIX = Path(__file__).resolve().parents[1] / "docs" / "rbac-role-matrix-per-tool.md"
_COMMITTED_DOC = parse_committed_per_tool_matrix(_PER_TOOL_MATRIX)

_POLICY_COHERENCE_CASES = iter_policy_coherence_cases(
    conformance_policy(),
    conformance_tool_names(),
)

# --- Layer 1: hand-written golden oracle (role_set, tool, allowed) ---------------
GOLDEN_RUNTIME_CASES: tuple[tuple[tuple[str, ...], str, bool], ...] = (
    # administrator: everything except the global deny list
    (("administrator",), "users_set_roles", True),
    (("administrator",), "ledger_commit", True),
    (("administrator",), "documents_write", True),
    (("administrator",), "reports_approve_release", True),
    (("administrator",), "documents_purge", False),
    # editor: documents + reports + ledger, no user administration
    (("editor",), "documents_read", True),
    (("editor",), "documents_write", True),
    (("editor",), "reports_write", True),
    (("editor",), "ledger_propose", True),
    (("editor",), "ledger_commit", True),
    (("editor",), "create_upload_url", True),
    (("editor",), "get_download_link", True),
    (("editor",), "reports_approve_release", False),
    (("editor",), "users_list", False),
    (("editor",), "documents_purge", False),
    # reviewer: approvals and the commit half only
    (("reviewer",), "reports_approve_run", True),
    (("reviewer",), "reports_approve_release", True),
    (("reviewer",), "ledger_propose", True),
    (("reviewer",), "ledger_commit", True),
    (("reviewer",), "get_download_link", True),
    (("reviewer",), "ledger_read", False),
    (("reviewer",), "documents_write", False),
    (("reviewer",), "reports_read", False),
    (("reviewer",), "users_list", False),
    # viewer: reads plus the file entrypoints
    (("viewer",), "reports_read", True),
    (("viewer",), "reports_list", True),
    (("viewer",), "documents_read", True),
    (("viewer",), "ledger_read", True),
    (("viewer",), "create_upload_url", True),
    (("viewer",), "get_download_link", True),
    (("viewer",), "documents_write", False),
    (("viewer",), "reports_write", False),
    (("viewer",), "ledger_commit", False),
    (("viewer",), "users_list", False),
    # multi-role union
    (("editor", "reviewer"), "documents_write", True),
    (("editor", "reviewer"), "reports_approve_run", True),
    (("editor", "reviewer"), "users_set_roles", False),
    (("editor", "viewer"), "reports_read", True),
    (("editor", "viewer"), "documents_write", True),
    (("editor", "viewer"), "users_list", False),
)

_GOLDEN_IDS = [
    f"{role_set_label(rs)}__{tool}__{'allow' if allowed else 'deny'}"
    for rs, tool, allowed in GOLDEN_RUNTIME_CASES
]

_DOC_ORACLE_CASES = [
    (role, tool, _COMMITTED_DOC[tool][role])
    for role in doc_roles(_COMMITTED_DOC)
    for tool in sorted(_COMMITTED_DOC)
]

_DOC_ORACLE_IDS = [
    f"{role}__{tool}__{'allow' if allowed else 'deny'}" for role, tool, allowed in _DOC_ORACLE_CASES
]


def _coherence_id(case: tuple[tuple[str, ...], str, bool]) -> str:
    role_set, tool, expected = case
    verdict = "allow" if expected else "deny"
    return f"{role_set_label(role_set)}__{tool}__{verdict}"


@pytest.fixture
def fixture_policy():
    return conformance_policy()


@pytest.fixture
def patch_identity(monkeypatch):
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(
            email=CONFORMANCE_EMAIL,
            claims={"email": CONFORMANCE_EMAIL, "auth_method": "google", "interactive": True},
        ),
    )


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name


async def _async_noop(_context):
    return {"ok": True}


# --- Layer 1 --------------------------------------------------------------------


@pytest.mark.parametrize("role_set,tool,expected", GOLDEN_RUNTIME_CASES, ids=_GOLDEN_IDS)
@pytest.mark.asyncio
async def test_golden_runtime_on_call(
    patch_identity,
    role_set: tuple[str, ...],
    tool: str,
    expected: bool,
):
    harness = build_conformance_harness(roles=role_set)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": tool})())

    if expected:
        assert await harness.middleware.on_call_tool(ctx, _async_noop) == {"ok": True}
    else:
        recorder = DecisionRecorder()
        recorder.attach(harness.middleware)
        with pytest.raises(ToolError, match="access denied"):
            await harness.middleware.on_call_tool(ctx, _async_noop)
        assert recorder.last is not None
        assert recorder.last.reason == RbacDenialReason.NOT_PERMITTED


@pytest.mark.parametrize(
    "role_set",
    tuple(dict.fromkeys(case[0] for case in GOLDEN_RUNTIME_CASES)),
    ids=[role_set_label(rs) for rs in dict.fromkeys(case[0] for case in GOLDEN_RUNTIME_CASES)],
)
@pytest.mark.asyncio
async def test_golden_runtime_on_list_visibility(patch_identity, role_set: tuple[str, ...]):
    catalog = conformance_tool_names()
    harness = build_conformance_harness(roles=role_set)

    async def call_next(_context):
        return [_Tool(name) for name in sorted(catalog)]

    visible = await harness.middleware.on_list_tools(MiddlewareContext(message=object()), call_next)
    visible_names = {tool.name for tool in visible}
    for rs, tool, allowed in GOLDEN_RUNTIME_CASES:
        if rs != role_set:
            continue
        if allowed:
            assert tool in visible_names, f"golden allow: {tool}"
        else:
            assert tool not in visible_names, f"golden deny: {tool}"


# --- Layer 2: the committed matrix for the shipped default policy ----------------


def test_committed_doc_roles_match_the_default_policy():
    assert set(doc_roles(_COMMITTED_DOC)) == set(load_policy().role_names)


@pytest.mark.parametrize("role,tool,expected", _DOC_ORACLE_CASES, ids=_DOC_ORACLE_IDS)
def test_committed_doc_matches_default_policy(role: str, tool: str, expected: bool):
    assert doc_allows(_COMMITTED_DOC, role, tool) is expected
    assert load_policy().allows_role(role, tool) is expected


# --- Layer 3: policy coherence ---------------------------------------------------


@pytest.mark.parametrize(
    "role_set",
    CONFORMANCE_ROLE_SETS,
    ids=[role_set_label(rs) for rs in CONFORMANCE_ROLE_SETS],
)
@pytest.mark.asyncio
async def test_policy_coherence_on_list(
    fixture_policy,
    patch_identity,
    role_set: tuple[str, ...],
):
    catalog = conformance_tool_names()
    harness = build_conformance_harness(roles=role_set)
    expected = expected_visible_tools(fixture_policy, role_set, catalog)

    async def call_next(_context):
        return [_Tool(name) for name in sorted(catalog)]

    visible = await harness.middleware.on_list_tools(MiddlewareContext(message=object()), call_next)
    assert {tool.name for tool in visible} == expected


@pytest.mark.parametrize(
    "role_set,tool,expected",
    _POLICY_COHERENCE_CASES,
    ids=[_coherence_id(case) for case in _POLICY_COHERENCE_CASES],
)
@pytest.mark.asyncio
async def test_policy_coherence_on_call(
    patch_identity,
    role_set: tuple[str, ...],
    tool: str,
    expected: bool,
):
    harness = build_conformance_harness(roles=role_set)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": tool})())

    if expected:
        assert await harness.middleware.on_call_tool(ctx, _async_noop) == {"ok": True}
    else:
        with pytest.raises(ToolError, match="access denied"):
            await harness.middleware.on_call_tool(ctx, _async_noop)


# --- list != call boundary --------------------------------------------------------


@pytest.mark.asyncio
async def test_hidden_tool_rejected_on_direct_call_after_list_filter(patch_identity):
    """Tool registered in the host but absent from on_list must still fail on_call."""
    harness = build_conformance_harness(roles=("viewer",))
    hidden_tool = "documents_write"

    async def call_next(_context):
        return [_Tool(name) for name in sorted(conformance_tool_names())]

    visible = await harness.middleware.on_list_tools(MiddlewareContext(message=object()), call_next)
    assert hidden_tool not in {tool.name for tool in visible}

    ctx = MiddlewareContext(message=type("Msg", (), {"name": hidden_tool})())
    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)


@pytest.mark.asyncio
async def test_user_admin_tool_hidden_from_list_and_denied_on_call(patch_identity):
    harness = build_conformance_harness(roles=("editor",))
    hidden_tool = "users_set_roles"

    async def call_next(_context):
        return [_Tool(name) for name in sorted(conformance_tool_names())]

    visible = await harness.middleware.on_list_tools(MiddlewareContext(message=object()), call_next)
    assert hidden_tool not in {tool.name for tool in visible}

    ctx = MiddlewareContext(message=type("Msg", (), {"name": hidden_tool})())
    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)


# --- multi-role union / revocation ------------------------------------------------


@pytest.mark.asyncio
async def test_multi_role_union_expands_permissions(patch_identity):
    harness = build_conformance_harness(roles=("editor", "reviewer"))
    for tool in ("documents_write", "reports_approve_run"):
        ctx = MiddlewareContext(message=type("Msg", (), {"name": tool})())
        assert await harness.middleware.on_call_tool(ctx, _async_noop) == {"ok": True}


@pytest.mark.asyncio
async def test_role_revocation_narrows_union(patch_identity):
    harness = build_conformance_harness(roles=("editor", "reviewer"))
    reviewer_only = "reports_approve_run"
    ctx = MiddlewareContext(message=type("Msg", (), {"name": reviewer_only})())
    await harness.middleware.on_call_tool(ctx, _async_noop)

    harness.backend.set_roles(CONFORMANCE_EMAIL, ("editor",))
    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)


# --- subject negatives -------------------------------------------------------------


@pytest.mark.asyncio
async def test_blocked_user_denied_on_gated_tool(patch_identity):
    harness = build_conformance_harness(roles=("editor",), is_blocked=True)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "reports_read"})())
    recorder = DecisionRecorder()
    recorder.attach(harness.middleware)

    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)
    assert recorder.last is not None
    assert recorder.last.reason == RbacDenialReason.USER_BLOCKED


@pytest.mark.asyncio
async def test_user_without_roles_denied(patch_identity):
    harness = build_conformance_harness(roles=())
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "reports_read"})())
    recorder = DecisionRecorder()
    recorder.attach(harness.middleware)

    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)
    assert recorder.last is not None
    assert recorder.last.reason == RbacDenialReason.NO_ROLES


@pytest.mark.asyncio
async def test_unknown_user_denied(patch_identity):
    harness = build_conformance_harness(roles=("editor",))
    harness.backend._users.clear()
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "reports_read"})())
    recorder = DecisionRecorder()
    recorder.attach(harness.middleware)

    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)
    assert recorder.last is not None
    assert recorder.last.reason == RbacDenialReason.NO_ROLES


# --- fail-closed --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_directory_unavailable_fail_closed_on_call(patch_identity):
    harness = build_conformance_harness(roles=("editor",), directory_unavailable=True)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "reports_read"})())
    recorder = DecisionRecorder()
    recorder.attach(harness.middleware)

    with pytest.raises(ToolError, match="access denied"):
        await harness.middleware.on_call_tool(ctx, _async_noop)
    assert recorder.last is not None
    assert recorder.last.reason == RbacDenialReason.ROLES_UNAVAILABLE


@pytest.mark.asyncio
async def test_directory_unavailable_hides_catalog_on_list(patch_identity):
    harness = build_conformance_harness(roles=("editor",), directory_unavailable=True)

    async def call_next(_context):
        return [_Tool("reports_read")]

    visible = await harness.middleware.on_list_tools(MiddlewareContext(message=object()), call_next)
    assert visible == []


@pytest.mark.asyncio
async def test_policy_unavailable_fail_closed_on_call(patch_identity):
    harness = build_conformance_harness(roles=("editor",), load_policy_into_manager=False)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "reports_read"})())

    with pytest.raises(ToolError, match=CLIENT_DENIAL_MESSAGE):
        await harness.middleware.on_call_tool(ctx, _async_noop)


@pytest.mark.asyncio
async def test_policy_unavailable_hides_catalog_on_list(patch_identity):
    harness = build_conformance_harness(roles=("editor",), load_policy_into_manager=False)

    async def call_next(_context):
        return [_Tool("reports_read"), _Tool("create_upload_url")]

    visible = await harness.middleware.on_list_tools(MiddlewareContext(message=object()), call_next)
    assert visible == []


# --- catalog contract (loader validation, not runtime middleware) -------------------


def test_fixture_policy_validates_against_its_catalog(fixture_policy):
    result = assert_live_catalog_validation(
        fixture_policy,
        live_tool_names(),
        catalog_snapshot=conformance_snapshot(),
    )
    assert result.ok


def test_conformance_report_artifact(fixture_policy):
    """Optional acceptance artifact (set RBAC_CONFORMANCE_WRITE_REPORT to persist)."""
    report = render_conformance_report(fixture_policy, conformance_tool_names())
    assert "| Role set | Tool | Expected |" in report
    assert f"tools: {len(conformance_tool_names())}." in report

    output = os.environ.get("RBAC_CONFORMANCE_WRITE_REPORT")
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report, encoding="utf-8")
