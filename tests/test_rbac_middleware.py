"""Unit and integration tests for the production RBAC middleware."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity, resolve_verified_identity
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.rbac.policy import default_policy_path, parse_policy_yaml
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.rbac_middleware import (
    CLIENT_DENIAL_MESSAGE,
    RbacDenialReason,
    RbacMiddleware,
)
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.server import build_server
from keystone_mcp.user_directory import (
    CORE_CRITICAL_PATTERNS,
    CriticalToolMatcher,
    build_in_memory_user_directory_resolver,
    is_critical_tool,
)

MOUNTED_TEST_POLICY = """\
version: "test-mounted"
default_deny: true
roles:
  administrator:
    description: admin
    allow: ["*"]
  editor:
    description: editor
    allow:
      - reports_*
      - create_upload_url
  reviewer:
    description: reviewer
    allow: ["ledger_commit"]
  viewer:
    description: viewer
    allow:
      - reports_read
      - create_upload_url
critical_tools: ["ledger_*"]
"""


@pytest.fixture
def mounted_policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "rbac-policy.yaml"
    path.write_text(MOUNTED_TEST_POLICY, encoding="utf-8")
    return path


@pytest.fixture
def subject_state():
    return {"email": "viewer@example.com", "blocked": False}


@pytest.fixture
def patch_verified_identity(monkeypatch, subject_state):
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email=subject_state["email"]),
    )


def _make_middleware(
    policy_path: Path,
    *,
    email: str = "viewer@example.com",
    roles: tuple[str, ...] = ("viewer",),
    is_blocked: bool = False,
    unavailable: bool = False,
    load_policy: bool = True,
    enforce: bool = True,
) -> tuple[RbacMiddleware, object]:
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url="redis://localhost:6379/0",
    )
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.unavailable = unavailable
    backend.seed(email, roles=roles, is_blocked=is_blocked)
    registry = RouterRegistry(RouterEngine(settings), FastMCP("policy-host"))
    registry.add_route("read", StubAdapter(), mode="live", namespace="reports")
    registry.add_route("purge_cache", StubAdapter(), mode="live", namespace="reports")
    registry.add_route("create_upload_url", StubAdapter(), mode="live")
    registry.add_route("ledger_commit", StubAdapter(), mode="live")
    manager = RbacPolicyManager(settings)
    if load_policy:
        manager.load_initial(registry)
    middleware = RbacMiddleware(manager, resolver, enforce=enforce)
    # Kept for tests that hot-reload the policy behind a live middleware.
    middleware._test_registry = registry  # type: ignore[attr-defined]
    return middleware, backend


def test_resolve_verified_identity_reads_oauth_token(monkeypatch):
    class _Token:
        subject = "fallback@example.com"
        claims = {"email": "claims@example.com"}

    monkeypatch.setattr(
        "fastmcp.server.dependencies.get_access_token",
        lambda: _Token(),
    )
    identity = resolve_verified_identity()
    assert identity is not None
    assert identity.email == "claims@example.com"


@pytest.mark.asyncio
async def test_viewer_sees_only_union_allowed_tools(
    mounted_policy_path: Path,
    patch_verified_identity,
):
    middleware, _ = _make_middleware(mounted_policy_path)

    class _Tool:
        def __init__(self, name: str) -> None:
            self.name = name

    async def call_next(_context):
        return [
            _Tool("reports_read"),
            _Tool("reports_purge_cache"),
            _Tool("create_upload_url"),
        ]

    visible = await middleware.on_list_tools(MiddlewareContext(message=object()), call_next)
    assert {tool.name for tool in visible} == {
        "reports_read",
        "create_upload_url",
    }


@pytest.mark.asyncio
async def test_allowed_call_passes(mounted_policy_path: Path, patch_verified_identity):
    middleware, _ = _make_middleware(mounted_policy_path)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "reports_read"})())
    called = {"ok": False}

    async def call_next(_context):
        called["ok"] = True
        return {"status": "ok"}

    result = await middleware.on_call_tool(ctx, call_next)
    assert called["ok"] is True
    assert result == {"status": "ok"}


@pytest.mark.asyncio
async def test_direct_call_to_hidden_tool_is_denied(
    mounted_policy_path: Path,
    patch_verified_identity,
):
    middleware, _ = _make_middleware(mounted_policy_path)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "reports_purge_cache"})())

    async def call_next(_context):
        raise AssertionError("call_next should not run")

    with pytest.raises(ToolError, match="access denied"):
        await middleware.on_call_tool(ctx, call_next)


@pytest.mark.asyncio
async def test_blocked_user_denied_on_call(mounted_policy_path: Path, patch_verified_identity):
    middleware, _ = _make_middleware(
        mounted_policy_path,
        is_blocked=True,
        roles=("editor",),
    )
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "create_upload_url"})())

    with pytest.raises(ToolError, match="access denied"):
        await middleware.on_call_tool(ctx, _async_noop)


async def _async_noop(_context):
    return None


@pytest.mark.asyncio
async def test_user_without_roles_denied(mounted_policy_path: Path, patch_verified_identity):
    middleware, _ = _make_middleware(mounted_policy_path, roles=())
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "create_upload_url"})())

    with pytest.raises(ToolError, match="access denied"):
        await middleware.on_call_tool(ctx, _async_noop)


@pytest.mark.asyncio
async def test_no_identity_denied_on_call(monkeypatch, mounted_policy_path: Path):
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: None,
    )
    middleware, _ = _make_middleware(mounted_policy_path)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "create_upload_url"})())

    with pytest.raises(ToolError, match=CLIENT_DENIAL_MESSAGE):
        await middleware.on_call_tool(ctx, _async_noop)


@pytest.mark.asyncio
async def test_policy_unavailable_denied_on_call(
    mounted_policy_path: Path, patch_verified_identity
):
    middleware, _ = _make_middleware(mounted_policy_path, load_policy=False)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "create_upload_url"})())

    with pytest.raises(ToolError, match=CLIENT_DENIAL_MESSAGE):
        await middleware.on_call_tool(ctx, _async_noop)


@pytest.mark.asyncio
async def test_unexpected_resolver_error_fail_closed(
    mounted_policy_path: Path,
    patch_verified_identity,
    monkeypatch,
):
    middleware, _ = _make_middleware(mounted_policy_path)

    async def _boom(_email: str, *, critical: bool = False):
        raise RuntimeError("unexpected backend failure")

    monkeypatch.setattr(middleware._user_resolver, "resolve", _boom)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "create_upload_url"})())

    with pytest.raises(ToolError, match=CLIENT_DENIAL_MESSAGE):
        await middleware.on_call_tool(ctx, _async_noop)


@pytest.mark.asyncio
async def test_rbac_middleware_does_not_throttle(
    mounted_policy_path: Path,
    patch_verified_identity,
    monkeypatch,
):
    """Rate limiting belongs to ThrottleMiddleware; this one must not count calls."""
    middleware, _ = _make_middleware(mounted_policy_path)
    resolve_calls: list[str] = []

    async def counting_resolve(email: str, *, critical: bool = False):
        resolve_calls.append(email)
        return type(
            "R",
            (),
            {"exists": True, "roles": ("viewer",), "is_blocked": False},
        )()

    monkeypatch.setattr(middleware._user_resolver, "resolve", counting_resolve)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "create_upload_url"})())

    for _ in range(50):
        await middleware.on_call_tool(ctx, _async_noop)
    assert len(resolve_calls) == 50


@pytest.mark.asyncio
async def test_unknown_user_denied(mounted_policy_path: Path, patch_verified_identity):
    middleware, backend = _make_middleware(mounted_policy_path)
    backend._users.clear()
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "create_upload_url"})())

    with pytest.raises(ToolError, match="access denied"):
        await middleware.on_call_tool(ctx, _async_noop)


@pytest.mark.asyncio
async def test_directory_unavailable_fail_closed(
    mounted_policy_path: Path,
    patch_verified_identity,
):
    middleware, _ = _make_middleware(mounted_policy_path, unavailable=True)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "create_upload_url"})())

    with pytest.raises(ToolError, match="access denied"):
        await middleware.on_call_tool(ctx, _async_noop)


@pytest.mark.asyncio
async def test_directory_unavailable_hides_catalog(
    mounted_policy_path: Path,
    patch_verified_identity,
):
    middleware, _ = _make_middleware(mounted_policy_path, unavailable=True)

    class _Tool:
        name = "create_upload_url"

    async def call_next(_context):
        return [_Tool()]

    visible = await middleware.on_list_tools(
        MiddlewareContext(message=object()),
        call_next,
    )
    assert visible == []


@pytest.mark.asyncio
async def test_observe_mode_records_deny_but_does_not_block_call(
    mounted_policy_path: Path,
    patch_verified_identity,
):
    middleware, _ = _make_middleware(
        mounted_policy_path,
        roles=("reviewer",),
        enforce=False,
    )
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "create_upload_url"})())

    async def call_next(_context):
        return {"ok": True}

    result = await middleware.on_call_tool(ctx, call_next)
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_observe_mode_does_not_filter_catalog_on_deny(
    mounted_policy_path: Path,
    patch_verified_identity,
):
    middleware, _ = _make_middleware(
        mounted_policy_path,
        roles=("reviewer",),
        enforce=False,
    )

    class _Tool:
        name = "create_upload_url"

    async def call_next(_context):
        return [_Tool()]

    visible = await middleware.on_list_tools(
        MiddlewareContext(message=object()),
        call_next,
    )
    assert len(visible) == 1
    assert visible[0].name == "create_upload_url"


@pytest.mark.asyncio
async def test_observe_mode_directory_unavailable_still_allows_call(
    mounted_policy_path: Path,
    patch_verified_identity,
):
    middleware, _ = _make_middleware(
        mounted_policy_path,
        unavailable=True,
        enforce=False,
    )
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "create_upload_url"})())

    async def call_next(_context):
        return {"ok": True}

    result = await middleware.on_call_tool(ctx, call_next)
    assert result == {"ok": True}


def test_rbac_observe_registers_middleware(tmp_path: Path):
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text(default_policy_path().read_text(encoding="utf-8"), encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="observe",
        rbac_policy_path=str(policy),
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url="redis://localhost:6379/0",
    )
    resolver, _backend, _ = build_in_memory_user_directory_resolver()
    mcp, _registry, _oauth, _upstreams, policy_manager, _observability, _reconciler = build_server(
        identity_provider=StaticIdentityProvider({"token"}),
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
    )
    assert policy_manager is not None
    rbac_layers = [item for item in mcp.middleware if isinstance(item, RbacMiddleware)]
    assert len(rbac_layers) == 1
    assert rbac_layers[0]._enforce is False


def test_rbac_disabled_does_not_register_middleware(tmp_path: Path):
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text(default_policy_path().read_text(encoding="utf-8"), encoding="utf-8")
    settings = Settings(base_url="http://localhost:8080", rbac_mode="off")
    mcp, _registry, _oauth, _upstreams, policy_manager, _observability, _reconciler = build_server(
        identity_provider=StaticIdentityProvider({"token"}),
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
    )
    assert policy_manager is None
    assert not any(isinstance(item, RbacMiddleware) for item in mcp.middleware)


def test_rbac_enabled_registers_middleware(tmp_path: Path):
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text(default_policy_path().read_text(encoding="utf-8"), encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy),
        users_service_url="http://users:8000",
        users_service_token="token",
    )
    resolver, _backend, _ = build_in_memory_user_directory_resolver()
    mcp, _registry, _oauth, _upstreams, policy_manager, _observability, _reconciler = build_server(
        identity_provider=StaticIdentityProvider({"token"}),
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
    )
    assert policy_manager is not None
    rbac_layers = [item for item in mcp.middleware if isinstance(item, RbacMiddleware)]
    assert len(rbac_layers) == 1


@pytest.mark.asyncio
async def test_critical_tool_uses_synchronous_resolve(
    mounted_policy_path: Path,
    monkeypatch,
    subject_state,
):
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email=subject_state["email"]),
    )
    middleware, _ = _make_middleware(mounted_policy_path, roles=("editor",))
    seen: dict[str, bool] = {}

    async def fake_resolve(email: str, *, critical: bool = False):
        seen["critical"] = critical
        return type(
            "R",
            (),
            {
                "exists": True,
                "roles": ("editor",),
                "is_blocked": False,
            },
        )()

    monkeypatch.setattr(middleware._user_resolver, "resolve", fake_resolve)
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "create_upload_url"})())

    async def call_next(_context):
        return {"ok": True}

    result = await middleware.on_call_tool(ctx, call_next)
    assert seen["critical"] is True
    assert result == {"ok": True}


def test_denial_reason_values_are_stable():
    assert RbacDenialReason.NOT_PERMITTED.value == "not_permitted"
    assert RbacDenialReason.USER_BLOCKED.value == "user_blocked"
    assert RbacDenialReason.NO_ROLES.value == "no_roles"
    assert RbacDenialReason.ROLES_UNAVAILABLE.value == "roles_unavailable"
    assert RbacDenialReason.THROTTLED.value == "throttled"
    assert RbacDenialReason.POLICY_UNAVAILABLE.value == "policy_unavailable"


CORE_CRITICAL_TOOLS = (
    "users_list",
    "users_set_roles",
    "create_upload_url",
    "get_download_link",
)

POLICY_CRITICAL_TOOLS = ("ledger_commit", "ledger_read")

NON_CRITICAL_TOOLS = ("reports_read", "documents_write", "user_guide_read")


@pytest.mark.parametrize("tool_name", CORE_CRITICAL_TOOLS)
def test_core_built_ins_are_critical_without_any_policy(tool_name: str) -> None:
    assert is_critical_tool(tool_name) is True
    assert is_critical_tool(tool_name, ()) is True


@pytest.mark.parametrize("tool_name", POLICY_CRITICAL_TOOLS)
def test_policy_patterns_extend_the_critical_set(tool_name: str) -> None:
    assert is_critical_tool(tool_name) is False
    assert is_critical_tool(tool_name, ("ledger_*",)) is True


@pytest.mark.parametrize("tool_name", NON_CRITICAL_TOOLS)
def test_unlisted_tools_are_not_critical(tool_name: str) -> None:
    assert is_critical_tool(tool_name, ("ledger_*",)) is False


def test_critical_matcher_exposes_core_and_policy_patterns() -> None:
    matcher = CriticalToolMatcher(("ledger_*",))
    assert set(CORE_CRITICAL_PATTERNS) <= set(matcher.patterns)
    assert "ledger_*" in matcher.patterns
    assert matcher.matches("users_add") is True
    assert matcher.matches("ledger_commit") is True
    assert matcher.matches("reports_read") is False


@pytest.mark.asyncio
async def test_policy_declared_critical_tool_bypasses_the_cache(
    mounted_policy_path: Path,
    monkeypatch,
    subject_state,
):
    """critical_tools from YAML reaches the resolver as critical=True."""
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email=subject_state["email"]),
    )
    middleware, _ = _make_middleware(mounted_policy_path, roles=("administrator",))
    seen: list[tuple[str, bool]] = []

    async def fake_resolve(email: str, *, critical: bool = False):
        seen.append((email, critical))
        return type(
            "R",
            (),
            {"exists": True, "roles": ("administrator",), "is_blocked": False},
        )()

    monkeypatch.setattr(middleware._user_resolver, "resolve", fake_resolve)

    async def call_next(_context):
        return {"ok": True}

    for tool_name, expected_critical in (
        ("ledger_commit", True),
        ("reports_read", False),
    ):
        ctx = MiddlewareContext(message=type("Msg", (), {"name": tool_name})())
        await middleware.on_call_tool(ctx, call_next)
        assert seen[-1][1] is expected_critical, tool_name


@pytest.mark.asyncio
async def test_critical_set_follows_a_policy_hot_reload(
    mounted_policy_path: Path,
    monkeypatch,
    subject_state,
):
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email=subject_state["email"]),
    )
    middleware, _ = _make_middleware(mounted_policy_path, roles=("administrator",))
    seen: list[bool] = []

    async def fake_resolve(email: str, *, critical: bool = False):
        seen.append(critical)
        return type(
            "R",
            (),
            {"exists": True, "roles": ("administrator",), "is_blocked": False},
        )()

    monkeypatch.setattr(middleware._user_resolver, "resolve", fake_resolve)

    async def call_next(_context):
        return {"ok": True}

    ctx = MiddlewareContext(message=type("Msg", (), {"name": "reports_read"})())
    await middleware.on_call_tool(ctx, call_next)
    assert seen[-1] is False

    mounted_policy_path.write_text(
        MOUNTED_TEST_POLICY.replace(
            'critical_tools: ["ledger_*"]', 'critical_tools: ["reports_*"]'
        ),
        encoding="utf-8",
    )
    reload_result = middleware._policy_manager.reload(middleware._test_registry)
    assert reload_result.success is True

    await middleware.on_call_tool(ctx, call_next)
    assert seen[-1] is True


def test_policy_object_reports_only_its_own_critical_patterns():
    policy = parse_policy_yaml(MOUNTED_TEST_POLICY)
    assert policy.critical_tool_patterns == ("ledger_*",)
    assert policy.is_critical_tool("ledger_commit") is True
    # Core built-ins are not in the policy; the matcher adds them.
    assert policy.is_critical_tool("users_add") is False
    assert is_critical_tool("users_add", policy.critical_tool_patterns) is True
