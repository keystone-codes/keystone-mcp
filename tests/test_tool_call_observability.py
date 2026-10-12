"""Prometheus metrics for MCP call_tool attempts vs invocations."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext
from fastmcp.tools.base import ToolResult
from mcp.types import TextContent
from prometheus_client import REGISTRY

from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.auth.throttle import PerIdentityThrottle
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.observability.metrics import RbacMetrics
from keystone_mcp.observability.service import RbacObservability
from keystone_mcp.observability.tool_call_labels import ClientIdLabelLimiter
from keystone_mcp.router.rbac_middleware import RbacMiddleware
from keystone_mcp.router.throttle_middleware import THROTTLE_MESSAGE, ThrottleMiddleware
from keystone_mcp.router.tool_call_observability_middleware import (
    ToolCallObservabilityMiddleware,
)
from keystone_mcp.server import build_server
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver

ALLOW_POLICY = """\
version: "tool-obs"
default_deny: true
roles:
  administrator:
    description: admin
    allow: ["*"]
  viewer:
    description: viewer
    allow: ["reports_read"]
"""


@pytest.fixture
def metrics_settings(tmp_path: Path) -> Settings:
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text(ALLOW_POLICY, encoding="utf-8")
    return Settings(
        base_url="http://localhost:8080",
        metrics_enabled=True,
        rbac_mode="enforce",
        rbac_policy_path=str(policy),
        throttle_max_requests=100,
        throttle_window_seconds=60,
    )


@pytest.fixture
def observability(metrics_settings: Settings) -> RbacObservability:
    return RbacObservability(metrics_settings)


def _tool_labels(
    tool: str,
    *,
    tool_name_mode: str = "full",
    auth_method: str = "none",
    oauth_client_id: str = "none",
) -> dict[str, str]:
    family = tool.split("_", 1)[0] if "_" in tool else tool
    if tool_name_mode == "coarse":
        tool_label = family
    else:
        tool_label = tool
    return {
        "tool_family": family,
        "namespace": family,
        "tool": tool_label,
        "auth_method": auth_method,
        "oauth_client_id": oauth_client_id,
    }


def _attempts(tool: str, **kwargs) -> float:
    return (
        REGISTRY.get_sample_value(
            "keystone_mcp_tool_call_attempts_total",
            _tool_labels(tool, **kwargs),
        )
        or 0.0
    )


def _invocations(tool: str, outcome: str, **kwargs) -> float:
    return (
        REGISTRY.get_sample_value(
            "keystone_mcp_tool_invocations_total",
            {**_tool_labels(tool, **kwargs), "outcome": outcome},
        )
        or 0.0
    )


async def _async_ok(_context):
    return {"ok": True}


async def _async_tool_error(_context):
    raise ToolError("boom")


async def _async_error(_context):
    raise RuntimeError("unexpected")


async def _async_cancelled(_context):
    raise asyncio.CancelledError


def _ctx(tool_name: str = "reports_read"):
    message = MagicMock()
    message.name = tool_name
    return MiddlewareContext(message=message)


@pytest.mark.asyncio
async def test_success_records_attempt_and_invocation(observability: RbacObservability):
    throttle = ThrottleMiddleware(PerIdentityThrottle(10, 60), observability=observability)
    inner = ToolCallObservabilityMiddleware(observability=observability)

    attempts_before = _attempts("reports_read")
    inv_before = _invocations("reports_read", "success")

    async def chain(context):
        return await inner.on_call_tool(context, _async_ok)

    result = await throttle.on_call_tool(_ctx(), chain)
    assert result == {"ok": True}
    assert _attempts("reports_read") == attempts_before + 1
    assert _invocations("reports_read", "success") == inv_before + 1


@pytest.mark.asyncio
async def test_throttle_denial_records_attempt_not_invocation(
    observability: RbacObservability,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        "keystone_mcp.router.throttle_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email="u@example.com"),
    )
    throttle = ThrottleMiddleware(
        PerIdentityThrottle(max_requests=1, window_seconds=60),
        observability=observability,
    )
    inner = ToolCallObservabilityMiddleware(observability=observability)

    async def chain(context):
        return await inner.on_call_tool(context, _async_ok)

    await throttle.on_call_tool(_ctx(), chain)

    attempts_before = _attempts("reports_read")
    inv_before = _invocations("reports_read", "success")

    with pytest.raises(ToolError, match=THROTTLE_MESSAGE):
        await throttle.on_call_tool(_ctx(), chain)

    assert _attempts("reports_read") == attempts_before + 1
    assert _invocations("reports_read", "success") == inv_before


@pytest.mark.asyncio
async def test_rbac_deny_records_attempt_not_invocation(
    metrics_settings: Settings,
    observability: RbacObservability,
    monkeypatch: pytest.MonkeyPatch,
):
    from fastmcp import FastMCP

    from keystone_mcp.adapters.stub import StubAdapter
    from keystone_mcp.rbac.loader import RbacPolicyManager
    from keystone_mcp.router.engine import RouterEngine
    from keystone_mcp.router.registry import RouterRegistry

    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email="viewer@example.com"),
    )
    monkeypatch.setattr(
        "keystone_mcp.router.throttle_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email="viewer@example.com"),
    )

    manager = RbacPolicyManager(metrics_settings)
    registry = RouterRegistry(RouterEngine(metrics_settings), FastMCP("host"))
    registry.add_route("read", StubAdapter(), mode="live", namespace="reports")
    registry.add_route("purge_cache", StubAdapter(), mode="live", namespace="reports")
    manager.load_initial(registry)

    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed("viewer@example.com", roles={"viewer"})

    throttle = ThrottleMiddleware(PerIdentityThrottle(10, 60), observability=observability)
    rbac = RbacMiddleware(
        manager,
        resolver,
        settings=metrics_settings,
        observability=observability,
        enforce=True,
    )
    inner = ToolCallObservabilityMiddleware(observability=observability)

    async def chain(context):
        return await rbac.on_call_tool(
            context,
            lambda ctx: inner.on_call_tool(ctx, _async_ok),
        )

    tool = "reports_purge_cache"
    attempts_before = _attempts(tool)
    inv_before = _invocations(tool, "success")

    with pytest.raises(ToolError, match="access denied"):
        await throttle.on_call_tool(_ctx(tool), chain)

    assert _attempts(tool) == attempts_before + 1
    assert _invocations(tool, "success") == inv_before


@pytest.mark.asyncio
async def test_tool_error_outcome(observability: RbacObservability):
    middleware = ToolCallObservabilityMiddleware(observability=observability)
    before = _invocations("reports_read", "tool_error")
    with pytest.raises(ToolError):
        await middleware.on_call_tool(_ctx(), _async_tool_error)
    assert _invocations("reports_read", "tool_error") == before + 1


@pytest.mark.asyncio
async def test_upstream_error_result_counts_as_tool_error(observability: RbacObservability):
    """A transparent-proxy ``ToolResult(is_error=True)`` is not an exception,
    so the middleware must inspect the returned result to record it as a
    ``tool_error`` outcome (see ``McpProxyAdapter`` with
    ``status_envelope=False``, the default)."""

    async def handler(_context):
        return ToolResult(content=[TextContent(type="text", text="quota exceeded")], is_error=True)

    middleware = ToolCallObservabilityMiddleware(observability=observability)
    before = _invocations("reports_read", "tool_error")
    result = await middleware.on_call_tool(_ctx(), handler)
    assert result.is_error is True
    assert _invocations("reports_read", "tool_error") == before + 1


@pytest.mark.asyncio
async def test_error_outcome(observability: RbacObservability):
    middleware = ToolCallObservabilityMiddleware(observability=observability)
    before = _invocations("reports_read", "error")
    with pytest.raises(RuntimeError):
        await middleware.on_call_tool(_ctx(), _async_error)
    assert _invocations("reports_read", "error") == before + 1


@pytest.mark.asyncio
async def test_cancelled_call_counts_as_cancelled(observability: RbacObservability):
    middleware = ToolCallObservabilityMiddleware(observability=observability)
    before = _invocations("reports_read", "cancelled")
    with pytest.raises(asyncio.CancelledError):
        await middleware.on_call_tool(_ctx(), _async_cancelled)
    assert _invocations("reports_read", "cancelled") == before + 1


@pytest.mark.asyncio
async def test_metrics_endpoint_lists_tool_call_metrics(metrics_settings: Settings):
    mcp, *_rest = build_server(
        identity_provider=StaticIdentityProvider({"token"}),
        settings=metrics_settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=metrics_settings.http_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/metrics")
    assert response.status_code == 200
    body = response.text
    assert "keystone_mcp_tool_call_attempts_total" in body
    assert "keystone_mcp_tool_invocations_total" in body
    assert "keystone_mcp_tool_invocation_seconds" in body
    assert "viewer@example.com" not in body
    assert "@example.com" not in body


@pytest.mark.asyncio
async def test_invocation_includes_auth_method_and_oauth_client_id(
    observability: RbacObservability,
    monkeypatch: pytest.MonkeyPatch,
):
    from types import SimpleNamespace

    monkeypatch.setattr(
        "keystone_mcp.observability.tool_call_labels.resolve_verified_identity",
        lambda: VerifiedIdentity(
            email="viewer@example.com",
            claims={"auth_method": "google"},
        ),
    )
    monkeypatch.setattr(
        "fastmcp.server.dependencies.get_access_token",
        lambda: SimpleNamespace(client_id="cursor-desktop", claims={}),
    )

    middleware = ToolCallObservabilityMiddleware(observability=observability)
    before = _invocations(
        "reports_read",
        "success",
        auth_method="google",
        oauth_client_id="cursor-desktop",
    )
    await middleware.on_call_tool(_ctx(), _async_ok)
    after = _invocations(
        "reports_read",
        "success",
        auth_method="google",
        oauth_client_id="cursor-desktop",
    )
    assert after == before + 1


def test_client_id_label_limiter():
    limiter = ClientIdLabelLimiter(2)
    # none/unknown pass through and never occupy a slot.
    assert limiter.label("none") == "none"
    assert limiter.label("unknown") == "unknown"

    assert limiter.label("a") == "a"
    assert limiter.label("b") == "b"
    assert limiter.label("c") == "other"
    assert limiter.label("a") == "a"

    assert limiter.label("none") == "none"
    assert limiter.label("unknown") == "unknown"


def test_client_id_label_limiter_zero_always_other():
    limiter = ClientIdLabelLimiter(0)
    assert limiter.label("x") == "other"
    assert limiter.label("y") == "other"
    assert limiter.label("none") == "none"
    assert limiter.label("unknown") == "unknown"


@pytest.mark.asyncio
async def test_client_id_limit_applies_to_metrics(monkeypatch: pytest.MonkeyPatch):
    from types import SimpleNamespace

    monkeypatch.setattr(
        "keystone_mcp.observability.tool_call_labels.resolve_verified_identity",
        lambda: VerifiedIdentity(
            email="viewer@example.com",
            claims={"auth_method": "google"},
        ),
    )

    metrics = RbacMetrics(enabled=True, oauth_client_id_limit=1)

    monkeypatch.setattr(
        "fastmcp.server.dependencies.get_access_token",
        lambda: SimpleNamespace(client_id="client-one", claims={}),
    )
    before_first = _invocations(
        "reports_read",
        "success",
        auth_method="google",
        oauth_client_id="client-one",
    )
    metrics.record_tool_invocation(
        tool_name="reports_read",
        outcome="success",
        duration_seconds=0.01,
    )
    after_first = _invocations(
        "reports_read",
        "success",
        auth_method="google",
        oauth_client_id="client-one",
    )
    assert after_first == before_first + 1

    monkeypatch.setattr(
        "fastmcp.server.dependencies.get_access_token",
        lambda: SimpleNamespace(client_id="client-two", claims={}),
    )
    before_other = _invocations(
        "reports_read",
        "success",
        auth_method="google",
        oauth_client_id="other",
    )
    metrics.record_tool_invocation(
        tool_name="reports_read",
        outcome="success",
        duration_seconds=0.01,
    )
    after_other = _invocations(
        "reports_read",
        "success",
        auth_method="google",
        oauth_client_id="other",
    )
    assert after_other == before_other + 1


def test_coarse_tool_label_uses_family_only(tmp_path: Path):
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text(ALLOW_POLICY, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        metrics_enabled=True,
        metrics_tool_name="coarse",
        rbac_mode="enforce",
        rbac_policy_path=str(policy),
    )
    metrics = RbacObservability(settings).metrics
    metrics.record_tool_call_attempt(tool_name="reports_read")
    value = REGISTRY.get_sample_value(
        "keystone_mcp_tool_call_attempts_total",
        {
            "tool_family": "reports",
            "namespace": "reports",
            "tool": "reports",
            "auth_method": "none",
            "oauth_client_id": "none",
        },
    )
    assert (value or 0) >= 1.0


def test_rbac_decision_metric_includes_operation(observability: RbacObservability):
    before = REGISTRY.get_sample_value(
        "keystone_mcp_rbac_decisions_total",
        {
            "decision": "allow",
            "reason": "none",
            "tool_family": "reports",
            "operation": "list_tools",
        },
    )
    observability.record_authz_decision(
        tool_name="reports_read",
        email="viewer@example.com",
        allowed=True,
        reason=None,
        roles=frozenset({"viewer"}),
        cache_hit=False,
        operation="list_tools",
        request_id=None,
    )
    after = REGISTRY.get_sample_value(
        "keystone_mcp_rbac_decisions_total",
        {
            "decision": "allow",
            "reason": "none",
            "tool_family": "reports",
            "operation": "list_tools",
        },
    )
    assert (after or 0) > (before or 0)
