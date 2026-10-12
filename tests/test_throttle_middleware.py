"""One tool call consumes exactly one throttle slot, in every RBAC mode.

The throttle used to be handed to both the router engine and the RBAC
middleware, and each recorded a hit, so a single tool call burned two slots of
an identity's budget and the effective limit was half the configured one. These
tests drive the assembled FastMCP app and pin the boundary: with a limit of N,
call N+1 is the first to be refused — not call N/2+1.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.auth.throttle import PerIdentityThrottle
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.throttle_middleware import (
    THROTTLE_MESSAGE,
    ThrottleMiddleware,
)
from keystone_mcp.server import build_server
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from support.login import dev_token_login

THROTTLE_LIMIT = 6
SUBJECT = "user@example.com"

ALLOW_ALL_POLICY = """\
version: "test-throttle"
default_deny: true
roles:
  administrator:
    description: admin
    allow: ["*"]
"""


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "rbac-policy.yaml"
    path.write_text(ALLOW_ALL_POLICY, encoding="utf-8")
    return path


@pytest.fixture
def patch_verified_identity(monkeypatch):
    """Every request carries the same verified identity, as OAuth would supply."""
    identity = VerifiedIdentity(email=SUBJECT)
    for module in (
        "keystone_mcp.identity",
        "keystone_mcp.router.rbac_middleware",
        "keystone_mcp.router.throttle_middleware",
    ):
        monkeypatch.setattr(f"{module}.resolve_verified_identity", lambda: identity)


def _settings(**overrides) -> Settings:
    return Settings(
        base_url="http://localhost:8080",
        throttle_max_requests=THROTTLE_LIMIT,
        throttle_window_seconds=60,
        **overrides,
    )


def _build_app(settings: Settings, **kwargs) -> FastMCP:
    """Assemble the real server, publish one stub tool, and load any RBAC policy."""
    from keystone_mcp.adapters.stub import StubAdapter

    mcp, registry, _oauth, _upstreams, policy_manager, _obs, _reconciler = build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
        **kwargs,
    )
    registry.add_route("ping", StubAdapter(), mode="live")
    if policy_manager is not None:
        policy_manager.load_initial(registry)
    return mcp


async def _count_calls_until_throttled(mcp: FastMCP, attempts: int) -> int:
    """Return how many calls succeeded before the first throttle refusal."""
    succeeded = 0
    async with Client(mcp) as client:
        for _ in range(attempts):
            try:
                await client.call_tool("ping", {})
            except ToolError as exc:
                assert THROTTLE_MESSAGE in str(exc), exc
                return succeeded
            succeeded += 1
    return succeeded


@pytest.mark.asyncio
async def test_rbac_off_throttles_on_the_configured_limit(patch_verified_identity):
    mcp = _build_app(_settings(rbac_mode="off"))
    assert await _count_calls_until_throttled(mcp, THROTTLE_LIMIT * 2) == THROTTLE_LIMIT


@pytest.mark.asyncio
async def test_rbac_enforce_throttles_on_the_configured_limit(
    patch_verified_identity,
    policy_path: Path,
):
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed(SUBJECT, roles=("administrator",))
    settings = _settings(
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url="redis://localhost:6379/0",
        rbac_audit_subject_salt="test-salt",
    )
    mcp = _build_app(settings, user_resolver=resolver)
    assert await _count_calls_until_throttled(mcp, THROTTLE_LIMIT * 2) == THROTTLE_LIMIT


@pytest.mark.asyncio
async def test_rbac_observe_throttles_on_the_configured_limit(
    patch_verified_identity,
    policy_path: Path,
):
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed(SUBJECT, roles=("administrator",))
    settings = _settings(
        rbac_mode="observe",
        rbac_policy_path=str(policy_path),
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url="redis://localhost:6379/0",
        rbac_audit_subject_salt="test-salt",
    )
    mcp = _build_app(settings, user_resolver=resolver)
    assert await _count_calls_until_throttled(mcp, THROTTLE_LIMIT * 2) == THROTTLE_LIMIT


# ── Middleware unit behaviour ───────────────────────────────────────────────
async def _async_noop(_ctx):
    return "ok"


def _ctx(tool_name: str = "ping") -> MiddlewareContext:
    return MiddlewareContext(message=type("Msg", (), {"name": tool_name})())


@pytest.mark.asyncio
async def test_throttle_runs_before_authorization(patch_verified_identity):
    """A refusal must not depend on anything downstream having run."""
    throttle = PerIdentityThrottle(max_requests=1, window_seconds=60)
    middleware = ThrottleMiddleware(throttle)
    downstream_calls = 0

    async def counting_next(_ctx):
        nonlocal downstream_calls
        downstream_calls += 1
        return "ok"

    assert await middleware.on_call_tool(_ctx(), counting_next) == "ok"
    assert downstream_calls == 1

    with pytest.raises(ToolError, match=THROTTLE_MESSAGE):
        await middleware.on_call_tool(_ctx(), counting_next)
    assert downstream_calls == 1


@pytest.mark.asyncio
async def test_unauthenticated_call_is_passed_through(monkeypatch):
    """With no verified identity there is nothing to aggregate on; authz decides."""
    monkeypatch.setattr(
        "keystone_mcp.router.throttle_middleware.resolve_verified_identity",
        lambda: None,
    )
    throttle = PerIdentityThrottle(max_requests=1, window_seconds=60)
    middleware = ThrottleMiddleware(throttle)
    for _ in range(5):
        assert await middleware.on_call_tool(_ctx(), _async_noop) == "ok"


@pytest.mark.asyncio
async def test_throttle_budget_is_per_identity(monkeypatch):
    subject = {"email": "a@example.com"}
    monkeypatch.setattr(
        "keystone_mcp.router.throttle_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email=subject["email"]),
    )
    middleware = ThrottleMiddleware(PerIdentityThrottle(max_requests=1, window_seconds=60))

    await middleware.on_call_tool(_ctx(), _async_noop)
    with pytest.raises(ToolError, match=THROTTLE_MESSAGE):
        await middleware.on_call_tool(_ctx(), _async_noop)

    # A different identity has its own budget.
    subject["email"] = "b@example.com"
    assert await middleware.on_call_tool(_ctx(), _async_noop) == "ok"


@pytest.mark.asyncio
async def test_throttled_denial_is_recorded_for_observability(patch_verified_identity):
    from keystone_mcp.router.rbac_middleware import RbacDenialReason

    recorded: list[dict] = []

    class _Recorder:
        def record_tool_call_attempt(self, *, tool_name: str) -> None:
            return None

        def record_authz_decision(self, **fields):
            recorded.append(fields)

    middleware = ThrottleMiddleware(
        PerIdentityThrottle(max_requests=1, window_seconds=60),
        observability=_Recorder(),  # type: ignore[arg-type]
    )
    await middleware.on_call_tool(_ctx("ping"), _async_noop)
    assert recorded == []

    with pytest.raises(ToolError, match=THROTTLE_MESSAGE):
        await middleware.on_call_tool(_ctx("ping"), _async_noop)

    assert len(recorded) == 1
    assert recorded[0]["allowed"] is False
    assert recorded[0]["reason"] is RbacDenialReason.THROTTLED
    assert recorded[0]["tool_name"] == "ping"
    assert recorded[0]["operation"] == "call_tool"
