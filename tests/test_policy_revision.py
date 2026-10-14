"""Cross-replica RBAC policy revision propagation."""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext
from prometheus_client import REGISTRY
from redis.exceptions import RedisError

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.observability.service import RbacObservability
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.rbac.policy_document import AllowRemove
from keystone_mcp.rbac.policy_revision import (
    InMemoryPolicyRevisionStore,
    PolicyRevisionWatcher,
)
from keystone_mcp.rbac.policy_store import PolicyStore
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.rbac_middleware import RbacMiddleware
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.surface.reconciler import SurfaceReconciler
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from support.test_env import UNUSED_REDIS_URL

TEST_POLICY = """\
version: "1.0.0"
default_deny: true
roles:
  administrator:
    description: admin
    allow: ["*"]
  editor:
    description: editor
    allow:
      - docs_search
      - docs_read
      - policy_read
"""

LIVE_ROUTE_NAMES = ("docs_search", "docs_read", "policy_read", "users_list")
ADMIN_ROLES = frozenset({"administrator"})


def _build_registry(settings: Settings) -> RouterRegistry:
    mcp = FastMCP("policy-revision-tests")
    registry = RouterRegistry(RouterEngine(settings), mcp)
    adapter = StubAdapter()
    for name in LIVE_ROUTE_NAMES:
        registry.add_route(name, adapter, mode="live")
    return registry


def _replica_stack(
    policy_path: Path,
    revision_store: InMemoryPolicyRevisionStore,
    *,
    min_interval_seconds: float = 0.0,
    clock=None,
) -> tuple[
    RbacPolicyManager,
    RbacMiddleware,
    PolicyRevisionWatcher,
    RouterRegistry,
    RbacObservability,
]:
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        rbac_audit_subject_salt="salt",
        policy_tools="full",
        redis_url=UNUSED_REDIS_URL,
        metrics_enabled=True,
    )
    registry = _build_registry(settings)
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed("admin@example.com", roles=("administrator",))
    backend.seed("editor@example.com", roles=("editor",))
    manager = RbacPolicyManager(settings)
    manager.load_initial(registry)
    observability = RbacObservability(settings, policy_manager=manager)
    manager._on_identity = observability.record_policy_identity
    identity = manager.identity
    if identity is not None:
        observability.record_policy_identity(identity)
    watcher = PolicyRevisionWatcher(
        store=revision_store,
        policy_manager=manager,
        registry=registry,
        observability=observability,
        min_interval_seconds=min_interval_seconds,
        clock=clock or (lambda: 0.0),
    )
    middleware = RbacMiddleware(
        manager,
        resolver,
        enforce=True,
        observability=observability,
        policy_revision_watcher=watcher,
    )
    return manager, middleware, watcher, registry, observability


@pytest.fixture
def shared_policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "rbac-policy.yaml"
    path.write_text(TEST_POLICY, encoding="utf-8")
    return path


@pytest.fixture
def revision_store() -> InMemoryPolicyRevisionStore:
    return InMemoryPolicyRevisionStore()


@pytest.mark.asyncio
async def test_change_reaches_other_replica_on_next_call(
    shared_policy_path: Path,
    revision_store: InMemoryPolicyRevisionStore,
) -> None:
    _mgr_a, _mw_a, watcher_a, registry_a, obs_a = _replica_stack(shared_policy_path, revision_store)
    _mgr_b, middleware_b, _watcher_b, _registry_b, _obs_b = _replica_stack(
        shared_policy_path, revision_store
    )
    store_a = PolicyStore(
        settings=_mgr_a._settings,
        policy_manager=_mgr_a,
        registry=registry_a,
        observability=obs_a,
        revision_watcher=watcher_a,
    )
    await store_a.change(
        changes=[AllowRemove("editor", ["docs_read"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_remove",
        task_id="t1",
    )

    async def call_next(_ctx):
        return {"ok": True}

    ctx = MiddlewareContext(message=type("Msg", (), {"name": "docs_read"})())
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
            lambda: VerifiedIdentity(email="editor@example.com"),
        )
        with pytest.raises(ToolError, match="access denied"):
            await middleware_b.on_call_tool(ctx, call_next)


@pytest.mark.asyncio
async def test_divergent_file_is_reported_once(
    tmp_path: Path,
    revision_store: InMemoryPolicyRevisionStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    path_a = tmp_path / "a.yaml"
    path_b = tmp_path / "b.yaml"
    path_a.write_text(TEST_POLICY, encoding="utf-8")
    path_b.write_text(TEST_POLICY, encoding="utf-8")

    settings_a = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(path_a),
        policy_tools="full",
        redis_url=UNUSED_REDIS_URL,
        metrics_enabled=True,
    )
    settings_b = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(path_b),
        policy_tools="full",
        redis_url=UNUSED_REDIS_URL,
        metrics_enabled=True,
    )
    registry_a = _build_registry(settings_a)
    registry_b = _build_registry(settings_b)
    mgr_a = RbacPolicyManager(settings_a)
    mgr_a.load_initial(registry_a)
    mgr_b = RbacPolicyManager(settings_b)
    mgr_b.load_initial(registry_b)
    obs_a = RbacObservability(settings_a, policy_manager=mgr_a)
    obs_b = RbacObservability(settings_b, policy_manager=mgr_b)
    watcher_a = PolicyRevisionWatcher(
        store=revision_store,
        policy_manager=mgr_a,
        registry=registry_a,
        observability=obs_a,
        min_interval_seconds=0.0,
        clock=lambda: 0.0,
    )
    watcher_b = PolicyRevisionWatcher(
        store=revision_store,
        policy_manager=mgr_b,
        registry=registry_b,
        observability=obs_b,
        min_interval_seconds=0.0,
        clock=lambda: 0.0,
    )
    store_a = PolicyStore(
        settings=settings_a,
        policy_manager=mgr_a,
        registry=registry_a,
        observability=obs_a,
        revision_watcher=watcher_a,
    )
    hash_before_b = mgr_b.identity.content_hash if mgr_b.identity else ""
    await store_a.change(
        changes=[AllowRemove("editor", ["docs_read"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_remove",
        task_id="t2",
    )

    resolver_b, backend_b, _ = build_in_memory_user_directory_resolver()
    backend_b.seed("editor@example.com", roles=("editor",))
    middleware_b = RbacMiddleware(
        mgr_b,
        resolver_b,
        enforce=True,
        observability=obs_b,
        policy_revision_watcher=watcher_b,
    )

    async def call_next(_ctx):
        return {"ok": True}

    ctx = MiddlewareContext(message=type("Msg", (), {"name": "docs_read"})())
    caplog.set_level(logging.ERROR)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
            lambda: VerifiedIdentity(email="editor@example.com"),
        )
        for _ in range(10):
            await middleware_b.on_call_tool(ctx, call_next)

    assert watcher_b.in_sync is False
    in_sync_samples = REGISTRY.get_sample_value("keystone_mcp_rbac_policy_in_sync")
    assert in_sync_samples == 0.0
    error_records = [
        r
        for r in caplog.records
        if r.levelno == logging.ERROR and "rbac policy revision" in r.message
    ]
    assert len(error_records) == 1
    assert mgr_b.identity is not None
    assert mgr_b.identity.content_hash == hash_before_b


@pytest.mark.asyncio
async def test_sighup_reload_republishes_and_clears_divergence(
    tmp_path: Path,
    revision_store: InMemoryPolicyRevisionStore,
) -> None:
    path_a = tmp_path / "a.yaml"
    path_b = tmp_path / "b.yaml"
    path_a.write_text(TEST_POLICY, encoding="utf-8")
    path_b.write_text(TEST_POLICY, encoding="utf-8")

    settings_a = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(path_a),
        policy_tools="full",
        redis_url=UNUSED_REDIS_URL,
        metrics_enabled=True,
    )
    settings_b = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(path_b),
        policy_tools="full",
        redis_url=UNUSED_REDIS_URL,
        metrics_enabled=True,
    )
    registry_a = _build_registry(settings_a)
    registry_b = _build_registry(settings_b)
    mgr_a = RbacPolicyManager(settings_a)
    mgr_a.load_initial(registry_a)
    mgr_b = RbacPolicyManager(settings_b)
    mgr_b.load_initial(registry_b)
    obs_a = RbacObservability(settings_a, policy_manager=mgr_a)
    obs_b = RbacObservability(settings_b, policy_manager=mgr_b)
    watcher_a = PolicyRevisionWatcher(
        store=revision_store,
        policy_manager=mgr_a,
        registry=registry_a,
        observability=obs_a,
        min_interval_seconds=0.0,
    )
    watcher_b = PolicyRevisionWatcher(
        store=revision_store,
        policy_manager=mgr_b,
        registry=registry_b,
        observability=obs_b,
        min_interval_seconds=0.0,
    )
    store_a = PolicyStore(
        settings=settings_a,
        policy_manager=mgr_a,
        registry=registry_a,
        observability=obs_a,
        revision_watcher=watcher_a,
    )
    await store_a.change(
        changes=[AllowRemove("editor", ["docs_read"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_remove",
        task_id="t3",
    )
    await watcher_b.ensure_current(force=True)
    assert watcher_b.in_sync is False

    path_b.write_text(path_a.read_text(encoding="utf-8"), encoding="utf-8")
    reconciler_b = SurfaceReconciler(
        settings=settings_b,
        registry=registry_b,
        upstreams=AsyncMock(),
        policy_manager=mgr_b,
        observability=obs_b,
        policy_revision_watcher=watcher_b,
    )
    reconciler_b._policy_reload_event.set()
    await reconciler_b._maybe_reload_policy(force=True)

    await watcher_a.ensure_current(force=True)
    assert watcher_a.in_sync is True
    assert watcher_b.in_sync is True


@pytest.mark.asyncio
async def test_revision_store_down_keeps_snapshot(
    shared_policy_path: Path,
    revision_store: InMemoryPolicyRevisionStore,
) -> None:
    times = iter([0.0, 0.0, 120.0])

    class _FailingStore(InMemoryPolicyRevisionStore):
        async def read(self):
            raise RedisError("down")

    failing = _FailingStore()
    _mgr, middleware, watcher, _registry, obs = _replica_stack(
        shared_policy_path,
        failing,
        clock=lambda: next(times),
    )
    before = _mgr.identity.content_hash if _mgr.identity else None

    async def call_next(_ctx):
        return {"ok": True}

    ctx = MiddlewareContext(message=type("Msg", (), {"name": "docs_read"})())
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
            lambda: VerifiedIdentity(email="editor@example.com"),
        )
        await middleware.on_call_tool(ctx, call_next)

    after = _mgr.identity.content_hash if _mgr.identity else None
    assert before == after
    unavailable = REGISTRY.get_sample_value(
        "keystone_mcp_rbac_policy_revision_checks_total", {"outcome": "unavailable"}
    )
    assert unavailable == 1.0


@pytest.mark.asyncio
async def test_checks_are_throttled(
    shared_policy_path: Path,
) -> None:
    store = InMemoryPolicyRevisionStore()
    times = iter([0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9])
    _mgr, middleware, _watcher, _registry, _obs = _replica_stack(
        shared_policy_path,
        store,
        min_interval_seconds=1.0,
        clock=lambda: next(times),
    )

    async def call_next(_ctx):
        return None

    ctx = MiddlewareContext(message=type("Msg", (), {"name": "docs_read"})())
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
            lambda: VerifiedIdentity(email="editor@example.com"),
        )
        for _ in range(10):
            await middleware.on_call_tool(ctx, call_next)

    assert store.read_count == 1


@pytest.mark.asyncio
async def test_publish_failure_is_a_warning(
    shared_policy_path: Path,
    revision_store: InMemoryPolicyRevisionStore,
) -> None:
    _mgr, _mw, watcher, registry, obs = _replica_stack(shared_policy_path, revision_store)

    async def fail_publish(_hash: str):
        raise RedisError("publish down")

    revision_store.publish = fail_publish  # type: ignore[method-assign]
    store = PolicyStore(
        settings=_mgr._settings,
        policy_manager=_mgr,
        registry=registry,
        observability=obs,
        revision_watcher=watcher,
    )
    result = await store.change(
        changes=[AllowRemove("editor", ["docs_read"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_remove",
        task_id="t4",
    )
    assert result.changed is True
    assert any("Redis unavailable" in w for w in result.warnings)


@pytest.mark.asyncio
async def test_policy_info_metric_keeps_one_series(
    shared_policy_path: Path,
    revision_store: InMemoryPolicyRevisionStore,
) -> None:
    _mgr, _mw, watcher, registry, obs = _replica_stack(shared_policy_path, revision_store)
    store = PolicyStore(
        settings=_mgr._settings,
        policy_manager=_mgr,
        registry=registry,
        observability=obs,
        revision_watcher=watcher,
    )
    await store.change(
        changes=[AllowRemove("editor", ["docs_read"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_remove",
        task_id="t5a",
    )
    first_hash = _mgr.identity.content_hash if _mgr.identity else ""
    await store.change(
        changes=[AllowRemove("editor", ["docs_search"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_remove",
        task_id="t5b",
    )
    second_hash = _mgr.identity.content_hash if _mgr.identity else ""
    assert first_hash != second_hash
    families = [m for m in REGISTRY.collect() if m.name == "keystone_mcp_rbac_policy_info"]
    assert len(families) == 1
    samples = list(families[0].samples)
    assert len(samples) == 1
    assert samples[0].labels["content_hash"] == second_hash
