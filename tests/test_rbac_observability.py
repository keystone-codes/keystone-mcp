"""Tests for RBAC audit events and Prometheus metrics."""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext
from prometheus_client import REGISTRY

from keystone_mcp.adapters.users_admin import UsersAdminAdapter
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.observability.audit import AuthzAuditRecorder
from keystone_mcp.observability.service import RbacObservability
from keystone_mcp.observability.subject import hash_subject
from keystone_mcp.rbac.loader import PolicyLoadError, RbacPolicyManager
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.rbac_middleware import RbacDenialReason, RbacMiddleware
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from support.test_env import UNUSED_REDIS_URL

AUDIT_TEST_POLICY = """\
version: "audit-v1"
default_deny: true
roles:
  administrator:
    description: admin
    allow: ["*"]
  editor:
    description: editor
    allow: ["create_upload_url", "ledger_commit"]
  viewer:
    description: viewer
    allow:
      - reports_read
      - create_upload_url
critical_tools: ["ledger_*"]
"""


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "rbac-policy.yaml"
    path.write_text(AUDIT_TEST_POLICY, encoding="utf-8")
    return path


@pytest.fixture
def settings(policy_path: Path) -> Settings:
    return Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        # The HTTP-proxy branch is what test_users_mutation_audited_on_service_timeout
        # exercises below (a mocked HTTP users directory client that times out); without this
        # the default built-in (local) backend would hit "service_unconfigured"
        # instead, since no UsersStore is wired up in this fixture.
        users_backend="http",
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url=UNUSED_REDIS_URL,
        rbac_audit_enabled=True,
        rbac_audit_list_tools_sample_rate=1.0,
        metrics_enabled=True,
    )


@pytest.fixture
def observability(settings: Settings) -> RbacObservability:
    from keystone_mcp.adapters.stub import StubAdapter

    manager = RbacPolicyManager(settings)
    registry = RouterRegistry(RouterEngine(settings), FastMCP("host"))
    registry.add_route("read", StubAdapter(), mode="live", namespace="reports")
    registry.add_route("purge_cache", StubAdapter(), mode="live", namespace="reports")
    registry.add_route("create_upload_url", StubAdapter(), mode="live")
    registry.add_route("ledger_commit", StubAdapter(), mode="live")
    manager.load_initial(registry)
    return RbacObservability(settings, policy_manager=manager)


def _middleware(
    settings: Settings,
    observability: RbacObservability,
    *,
    email: str = "viewer@example.com",
    roles: tuple[str, ...] = ("viewer",),
    is_blocked: bool = False,
    unavailable: bool = False,
) -> RbacMiddleware:
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.unavailable = unavailable
    backend.seed(email, roles=roles, is_blocked=is_blocked)
    manager = observability._policy_manager
    assert manager is not None
    return RbacMiddleware(
        manager,
        resolver,
        observability=observability,
    )


def _parse_audit_records(caplog: pytest.LogCaptureFixture) -> list[dict]:
    records: list[dict] = []
    for record in caplog.records:
        if not record.message.startswith("rbac audit "):
            continue
        payload = record.message.removeprefix("rbac audit ")
        records.append(json.loads(payload))
    return records


def test_hash_subject_never_contains_raw_email():
    email = "viewer@example.com"
    subject = hash_subject(email)
    assert subject is not None
    assert email not in subject
    assert subject.startswith("sub_")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "roles", "is_blocked", "unavailable", "expected_reason"),
    [
        ("reports_read", ("viewer",), False, False, None),
        ("reports_purge_cache", ("viewer",), False, False, RbacDenialReason.NOT_PERMITTED),
        ("create_upload_url", (), False, False, RbacDenialReason.NO_ROLES),
        ("create_upload_url", ("viewer",), True, False, RbacDenialReason.USER_BLOCKED),
        ("create_upload_url", ("viewer",), False, True, RbacDenialReason.ROLES_UNAVAILABLE),
    ],
)
async def test_authz_audit_event_fields(
    caplog: pytest.LogCaptureFixture,
    settings: Settings,
    observability: RbacObservability,
    monkeypatch,
    tool_name: str,
    roles: tuple[str, ...],
    is_blocked: bool,
    unavailable: bool,
    expected_reason: RbacDenialReason | None,
):
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email="viewer@example.com"),
    )
    middleware = _middleware(
        settings,
        observability,
        roles=roles,
        is_blocked=is_blocked,
        unavailable=unavailable,
    )
    ctx = MiddlewareContext(message=type("Msg", (), {"name": tool_name})())

    async def call_next(_context):
        return {"ok": True}

    if expected_reason is None:
        await middleware.on_call_tool(ctx, call_next)
    else:
        with pytest.raises(ToolError):
            await middleware.on_call_tool(ctx, call_next)

    events = [e for e in _parse_audit_records(caplog) if e["event"] == "rbac_authz_decision"]
    assert len(events) == 1
    event = events[0]
    assert event["tool"] == tool_name
    assert event["decision"] == ("allow" if expected_reason is None else "deny")
    assert event["reason"] == (expected_reason.value if expected_reason else None)
    assert event["policy_version"] == "audit-v1"
    assert event["policy_content_hash"]
    assert "viewer@example.com" not in json.dumps(event)
    assert event["operation"] == "call_tool"


HUMAN_GATE_POLICY = """\
version: "audit-human-gate"
default_deny: true
roles:
  administrator:
    allow: ["*"]
requires_human_identity: ["ledger_commit"]
"""


@pytest.mark.asyncio
async def test_human_identity_required_denial_records_login_provider(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    monkeypatch,
):
    """The audit event names the sign-in method behind a human_identity_required
    denial (X05), so an operator can read "signed in with api_key" straight
    off the log line instead of cross-referencing the token store.
    """
    from keystone_mcp.adapters.stub import StubAdapter

    policy_path = tmp_path / "human-gate-policy.yaml"
    policy_path.write_text(HUMAN_GATE_POLICY, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        redis_url=UNUSED_REDIS_URL,
        rbac_audit_enabled=True,
        rbac_audit_list_tools_sample_rate=1.0,
    )
    caplog.set_level(logging.INFO)
    manager = RbacPolicyManager(settings)
    registry = RouterRegistry(RouterEngine(settings), FastMCP("host"))
    registry.add_route("ledger_commit", StubAdapter(), mode="live")
    manager.load_initial(registry)
    observability = RbacObservability(settings, policy_manager=manager)

    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(
            email="admin@example.com",
            claims={
                "email": "admin@example.com",
                "auth_method": "api_key",
                "interactive": False,
            },
        ),
    )
    middleware = _middleware(
        settings, observability, email="admin@example.com", roles=("administrator",)
    )
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "ledger_commit"})())

    async def call_next(_context):
        return {"ok": True}

    with pytest.raises(ToolError):
        await middleware.on_call_tool(ctx, call_next)

    events = [e for e in _parse_audit_records(caplog) if e["event"] == "rbac_authz_decision"]
    assert len(events) == 1
    event = events[0]
    assert event["reason"] == "human_identity_required"
    assert event["login_provider"] == "api_key"


@pytest.mark.asyncio
async def test_list_tools_deny_always_audited(
    caplog: pytest.LogCaptureFixture,
    settings: Settings,
    observability: RbacObservability,
    monkeypatch,
):
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: None,
    )
    middleware = _middleware(settings, observability)

    async def call_next(_context):
        return [type("Tool", (), {"name": "create_upload_url"})()]

    visible = await middleware.on_list_tools(MiddlewareContext(message=object()), call_next)
    assert visible == []
    events = _parse_audit_records(caplog)
    assert len(events) == 1
    assert events[0]["decision"] == "deny"
    assert events[0]["reason"] == "no_identity"


@pytest.mark.asyncio
async def test_list_tools_allow_sampling(
    settings: Settings,
    observability: RbacObservability,
):
    quiet_settings = replace(settings, rbac_audit_list_tools_sample_rate=0.0)
    observability = RbacObservability(quiet_settings, policy_manager=observability._policy_manager)
    recorder = observability.authz_audit
    assert recorder.should_emit(allowed=True, tool_name="", operation="list_tools") is False
    assert recorder.should_emit(allowed=False, tool_name="", operation="list_tools") is True
    assert recorder.should_emit(allowed=True, tool_name="create_upload_url", operation="call_tool")


@pytest.mark.asyncio
async def test_audit_failure_does_not_change_verdict(
    settings: Settings,
    observability: RbacObservability,
    monkeypatch,
):
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email="viewer@example.com"),
    )
    middleware = _middleware(settings, observability)
    observability.authz_audit.record_decision = MagicMock(side_effect=RuntimeError("audit down"))
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "reports_read"})())

    async def call_next(_context):
        return {"ok": True}

    result = await middleware.on_call_tool(ctx, call_next)
    assert result == {"ok": True}


def test_users_mutation_audit(
    caplog: pytest.LogCaptureFixture, settings: Settings, observability: RbacObservability
):
    caplog.set_level(logging.INFO)
    adapter = UsersAdminAdapter(observability=observability)
    from keystone_mcp.adapters.base import Pattern
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route

    route = Route(
        name="users_grant_role",
        pattern=Pattern.SYNC,
        target=adapter,
        mode="live",
    )
    ctx = RouteContext(
        verified_identity=VerifiedIdentity(email="admin@example.com"),
        task_id="t_abc123",
        canonical_args="",
        tool_name="users_grant_role",
        pattern=Pattern.SYNC,
        settings=settings,
    )
    adapter._record_mutation_audit(
        route,
        ctx,
        {"email": "user@example.com", "role": "viewer"},
        {
            "state": "done",
            "user": {"email": "user@example.com", "roles": ["viewer"], "is_blocked": False},
        },
    )
    events = [e for e in _parse_audit_records(caplog) if e["event"] == "rbac_users_mutation"]
    assert len(events) == 1
    event = events[0]
    assert event["operation"] == "users_grant_role"
    assert event["outcome"] == "done"
    assert event["task_id"] == "t_abc123"
    assert event["policy_version"] == "audit-v1"
    assert "admin@example.com" not in json.dumps(event)
    assert "user@example.com" not in json.dumps(event)
    assert event["roles_after"] == "viewer"
    assert event["role"] == "viewer"


@pytest.mark.asyncio
async def test_users_mutation_audited_on_service_timeout(
    caplog: pytest.LogCaptureFixture,
    settings: Settings,
    observability: RbacObservability,
):
    import httpx

    from keystone_mcp.router.registry import Param

    caplog.set_level(logging.INFO)

    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    adapter = UsersAdminAdapter(
        directory=_http_directory(handler),
        observability=observability,
    )
    engine = RouterEngine(settings)
    registry = RouterRegistry(engine, FastMCP("host"))
    route = registry.add_route(
        "users_grant_role",
        adapter,
        mode="live",
        params=[Param("email", str), Param("role", str)],
    )

    out = await engine.execute(
        route,
        {"email": "user@example.com", "role": "viewer"},
        identity=VerifiedIdentity(email="admin@example.com"),
    )
    assert out["state"] == "error"
    assert out["code"] == "service_timeout"

    events = [e for e in _parse_audit_records(caplog) if e["event"] == "rbac_users_mutation"]
    assert len(events) == 1
    event = events[0]
    assert event["outcome"] == "error"
    assert event["code"] == "service_timeout"
    assert event["operation"] == "users_grant_role"
    assert event["role"] == "viewer"
    assert event["target"] is not None
    assert event["task_id"] == out["task_id"]
    assert "user@example.com" not in json.dumps(event)


def _http_directory(handler):
    from keystone_mcp.user_directory.http import HttpUserDirectory

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://users-directory.internal.example:8080",
        headers={"Authorization": "Bearer service-secret"},
    )
    return HttpUserDirectory(
        base_url="http://users-directory.internal.example:8080",
        service_token="service-secret",
        timeout_seconds=5.0,
        client=client,
    )


@pytest.mark.asyncio
async def test_policy_unavailable_audit_uses_list_tools_operation(
    caplog: pytest.LogCaptureFixture,
    settings: Settings,
    observability: RbacObservability,
    monkeypatch,
):
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email="viewer@example.com"),
    )
    middleware = _middleware(settings, observability)

    class _FailingManager:
        active_policy = None

        @property
        def policy(self):
            raise PolicyLoadError("not loaded")

    middleware._policy_manager = _FailingManager()  # type: ignore[assignment]

    class _Tool:
        name = "create_upload_url"

    async def call_next(_context):
        return [_Tool()]

    visible = await middleware.on_list_tools(MiddlewareContext(message=object()), call_next)
    assert visible == []

    events = [e for e in _parse_audit_records(caplog) if e["event"] == "rbac_authz_decision"]
    policy_events = [e for e in events if e.get("reason") == "policy_unavailable"]
    assert len(policy_events) == 1
    assert policy_events[0]["operation"] == "list_tools"


def test_metrics_increment_on_decision(settings: Settings, observability: RbacObservability):
    before = REGISTRY.get_sample_value(
        "keystone_mcp_rbac_decisions_total",
        {
            "decision": "allow",
            "reason": "none",
            "tool_family": "reports",
            "operation": "call_tool",
        },
    )
    observability.record_authz_decision(
        tool_name="reports_read",
        email="viewer@example.com",
        allowed=True,
        reason=None,
        roles=frozenset({"viewer"}),
        cache_hit=False,
        operation="call_tool",
        request_id=None,
    )
    after = REGISTRY.get_sample_value(
        "keystone_mcp_rbac_decisions_total",
        {
            "decision": "allow",
            "reason": "none",
            "tool_family": "reports",
            "operation": "call_tool",
        },
    )
    assert (after or 0) > (before or 0)


def test_policy_version_changes_after_hot_reload(
    settings: Settings,
    policy_path: Path,
    caplog: pytest.LogCaptureFixture,
):
    caplog.set_level(logging.INFO)
    manager = RbacPolicyManager(settings)
    from keystone_mcp.adapters.stub import StubAdapter

    registry = RouterRegistry(RouterEngine(settings), FastMCP("host"))
    registry.add_route("read", StubAdapter(), mode="live", namespace="reports")
    registry.add_route("purge_cache", StubAdapter(), mode="live", namespace="reports")
    registry.add_route("create_upload_url", StubAdapter(), mode="live")
    registry.add_route("ledger_commit", StubAdapter(), mode="live")
    manager.load_initial(registry)
    observability = RbacObservability(settings, policy_manager=manager)
    first_hash = observability.active_policy_fields().content_hash

    policy_path.write_text(
        AUDIT_TEST_POLICY.replace('version: "audit-v1"', 'version: "audit-v2"'),
        encoding="utf-8",
    )
    from keystone_mcp.adapters.stub import StubAdapter

    registry = RouterRegistry(RouterEngine(settings), FastMCP("host"))
    registry.add_route("read", StubAdapter(), mode="live", namespace="reports")
    registry.add_route("purge_cache", StubAdapter(), mode="live", namespace="reports")
    registry.add_route("create_upload_url", StubAdapter(), mode="live")
    registry.add_route("ledger_commit", StubAdapter(), mode="live")
    result = manager.reload(registry)
    assert result.success
    second_hash = observability.active_policy_fields().content_hash
    assert second_hash != first_hash
    assert observability.active_policy_fields().version == "audit-v2"


def test_audit_disabled(settings: Settings):
    quiet_settings = replace(settings, rbac_audit_enabled=False, metrics_enabled=False)
    recorder = AuthzAuditRecorder(
        enabled=quiet_settings.rbac_audit_enabled,
        list_tools_allow_sample_rate=1.0,
    )
    assert recorder.should_emit(allowed=True, tool_name="x", operation="call_tool") is False


@pytest.mark.asyncio
async def test_audit_marks_policy_declared_critical_tools(
    caplog: pytest.LogCaptureFixture,
    settings: Settings,
    observability: RbacObservability,
    monkeypatch,
):
    """The `critical` audit field follows critical_tools in the policy file."""
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email="viewer@example.com"),
    )
    middleware = _middleware(settings, observability, roles=("editor",))

    async def call_next(_context):
        return {"ok": True}

    for tool_name, expected in (("ledger_commit", True), ("create_upload_url", False)):
        caplog.clear()
        ctx = MiddlewareContext(message=type("Msg", (), {"name": tool_name})())
        await middleware.on_call_tool(ctx, call_next)
        events = [e for e in _parse_audit_records(caplog) if e["event"] == "rbac_authz_decision"]
        assert events, tool_name
        assert events[-1]["critical"] is expected, tool_name

    caplog.clear()
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "reports_read"})())
    with pytest.raises(ToolError):
        await middleware.on_call_tool(ctx, call_next)
    events = [e for e in _parse_audit_records(caplog) if e["event"] == "rbac_authz_decision"]
    assert events[-1]["critical"] is False


def test_critical_tool_patterns_are_empty_without_a_policy_manager(settings: Settings):
    assert RbacObservability(settings).critical_tool_patterns() == ()
