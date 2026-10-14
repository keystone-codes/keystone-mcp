"""Surface reconciler: live catalog and policy file refresh."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastmcp import Client, FastMCP

from keystone_mcp.adapters.base import Pattern
from keystone_mcp.config import Settings
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import (
    UpstreamCatalogRead,
    UpstreamListToolsError,
    UpstreamRegistry,
    fetch_upstream_tools,
)
from keystone_mcp.surface import reconciler as reconciler_module
from keystone_mcp.surface.reconciler import SurfaceReconciler

LIVE_TOOLS = frozenset({"reports_read", "reports_write"})

TEST_POLICY = """\
version: "3.0.0"
default_deny: true
roles:
  administrator:
    allow: ["*"]
"""


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(TEST_POLICY, encoding="utf-8")
    return path


@pytest.fixture
def reconciler_stack(policy_path: Path):
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_service_url="http://users:8000",
        users_service_token="token",
        refresh_interval_seconds=300,
        upstream_discovery_timeout_seconds=5.0,
    )
    main = FastMCP("main")
    engine = RouterEngine(settings)
    registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(
        main_mcp=main,
        registry=registry,
        discovery_timeout_seconds=5.0,
    )
    upstreams.add_upstream("reports", "http://reports:8081/mcp", namespace="reports")
    policy_manager = RbacPolicyManager(settings)
    from keystone_mcp.adapters.stub import StubAdapter

    adapter = StubAdapter()
    for tool in sorted(LIVE_TOOLS):
        registry.add_route(
            tool,
            adapter,
            pattern=Pattern.SYNC,
            mode="live",
            namespace="reports",
            config_mode="PROXY",
            upstream_tool=tool,
            mcp=upstreams._sub_servers["reports"],
        )
    policy_manager.load_initial(registry)
    reconciler = SurfaceReconciler(
        settings=settings,
        registry=registry,
        upstreams=upstreams,
        policy_manager=policy_manager,
        observability=None,
    )
    reconciler.seed_snapshots()
    return reconciler, registry, policy_path, policy_manager, upstreams


async def test_policy_file_change_applies_without_sighup(reconciler_stack):
    reconciler, _registry, policy_path, policy_manager, _upstreams = reconciler_stack
    policy_path.write_text(
        TEST_POLICY.replace('version: "3.0.0"', 'version: "3.0.1"'),
        encoding="utf-8",
    )
    with patch.object(reconciler, "_refresh_catalogs", new_callable=AsyncMock):
        await reconciler.tick()
    assert policy_manager.identity is not None
    assert policy_manager.identity.version == "3.0.1"


async def test_invalid_policy_file_keeps_previous(reconciler_stack):
    reconciler, _registry, policy_path, policy_manager, _upstreams = reconciler_stack
    policy_path.write_text("version: 2\nroles: {}\n", encoding="utf-8")
    with patch.object(reconciler, "_refresh_catalogs", new_callable=AsyncMock):
        await reconciler.tick()
    assert policy_manager.identity is not None
    assert policy_manager.identity.version == "3.0.0"


def test_repr_does_not_leak_bearer_token_via_upstreams_field(monkeypatch, policy_path: Path):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_REPORTS_TOKEN", "super-secret-token-value")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_service_url="http://users:8000",
        users_service_token="token",
        refresh_interval_seconds=300,
        upstream_discovery_timeout_seconds=5.0,
    )
    main = FastMCP("main")
    engine = RouterEngine(settings)
    registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(
        main_mcp=main,
        registry=registry,
        discovery_timeout_seconds=5.0,
    )
    upstreams.add_upstream(
        "reports",
        "http://reports:8081/mcp",
        namespace="reports",
        bearer_env="KEYSTONE_MCP_UPSTREAM_REPORTS_TOKEN",
    )
    policy_manager = RbacPolicyManager(settings)
    reconciler = SurfaceReconciler(
        settings=settings,
        registry=registry,
        upstreams=upstreams,
        policy_manager=policy_manager,
        observability=None,
    )

    rendered = repr(reconciler)

    assert "super-secret-token-value" not in rendered
    assert "Bearer" not in rendered


async def test_upstream_timeout_keeps_previous_catalog(reconciler_stack):
    reconciler, registry, _policy_path, _policy_manager, _upstreams = reconciler_stack
    before = set(registry.routes.keys())

    with patch(
        "keystone_mcp.router.upstream.fetch_upstream_tools",
        new_callable=AsyncMock,
        side_effect=UpstreamListToolsError("timeout"),
    ):
        await reconciler.tick()

    assert set(registry.routes.keys()) == before


async def test_single_empty_upstream_list_holds_catalog(reconciler_stack):
    reconciler, registry, _policy_path, _policy_manager, _upstreams = reconciler_stack
    before = set(registry.routes.keys())

    with patch(
        "keystone_mcp.router.upstream.fetch_upstream_tools",
        new_callable=AsyncMock,
        return_value=[],
    ):
        await reconciler.tick()

    assert set(registry.routes.keys()) == before
    assert reconciler._empty_list_streak.get("reports") == 1


async def test_unreachable_upstream_does_not_crash_tick(reconciler_stack, caplog):
    """A connection-level RuntimeError (not UpstreamListToolsError) must not
    propagate out of tick(): the namespace keeps its previous catalog and the
    failure is logged, instead of killing the reconciler task."""
    reconciler, registry, _policy_path, _policy_manager, _upstreams = reconciler_stack
    before = set(registry.routes.keys())

    with (
        caplog.at_level(logging.WARNING, logger=reconciler_module.__name__),
        patch(
            "keystone_mcp.router.upstream.fetch_upstream_tools",
            new_callable=AsyncMock,
            side_effect=RuntimeError("Client failed to connect"),
        ),
    ):
        await reconciler.tick()

    assert set(registry.routes.keys()) == before
    assert any(
        record.levelno >= logging.WARNING and "namespace=reports" in record.getMessage()
        for record in caplog.records
    )


async def test_fetch_upstream_tools_wraps_connect_errors():
    with pytest.raises(UpstreamListToolsError):
        await fetch_upstream_tools("http://127.0.0.1:9/mcp", timeout_seconds=2)


async def test_one_failing_namespace_does_not_block_others(reconciler_stack):
    reconciler, registry, _policy_path, _policy_manager, upstreams = reconciler_stack

    class _FakeTool:
        def __init__(self, name: str) -> None:
            self.name = name
            self.description = "ledger tool"
            self.input_schema = None

    upstreams.add_upstream("ledger", "http://ledger:8082/mcp", namespace="ledger")

    async def _fake_fetch(url: str, *, timeout_seconds: float, **_kwargs):
        if "reports" in url:
            raise UpstreamListToolsError("reports upstream unreachable")
        return [_FakeTool("do_thing")]

    with patch(
        "keystone_mcp.router.upstream.fetch_upstream_tools",
        new_callable=AsyncMock,
        side_effect=_fake_fetch,
    ):
        await reconciler.tick()

    assert "ledger:do_thing" in registry.routes


# --- parallel catalog refresh (C06 step 6) -------------------------------------------


async def test_hanging_namespace_does_not_delay_others(reconciler_stack):
    """A namespace that hangs on listing must not block others past its own budget."""
    reconciler, registry, _policy_path, _policy_manager, upstreams = reconciler_stack
    discovery_timeout = 1.0
    upstreams.discovery_timeout_seconds = discovery_timeout
    budget = reconciler_module._REFRESH_BUDGET_MULTIPLIER * discovery_timeout

    upstreams.add_upstream("ledger", "http://ledger:8082/mcp", namespace="ledger")
    reports_before = set(registry.routes.keys())

    async def _read_catalog(cfg):
        if cfg.namespace == "reports":
            await asyncio.sleep(budget + 5.0)
            return UpstreamCatalogRead(
                tools=[_FakeTool("reports_read"), _FakeTool("reports_write")],
                prompts=[],
                resources=[],
                templates=[],
            )
        return UpstreamCatalogRead(
            tools=[_FakeTool("new_tool")],
            prompts=[],
            resources=[],
            templates=[],
        )

    with patch.object(upstreams, "read_catalog", side_effect=_read_catalog):
        started = time.monotonic()
        await reconciler.tick()
        elapsed = time.monotonic() - started

    assert elapsed <= budget + 1.0
    assert "ledger:new_tool" in registry.routes
    assert set(registry.routes.keys()) & reports_before == reports_before
    unavailable = upstreams.unavailable_namespaces()
    assert "reports" in unavailable
    assert unavailable["reports"] == f"refresh timed out after {budget:g}s"


async def test_parallel_refresh_announces_changes_once(reconciler_stack):
    """Two namespaces changing in one tick must produce a single tools list_changed."""
    reconciler, registry, _policy_path, _policy_manager, upstreams = reconciler_stack
    upstreams.add_upstream("ledger", "http://ledger:8082/mcp", namespace="ledger")

    sessions = MagicMock()
    sessions.broadcast_list_changed = AsyncMock(return_value=0)
    reconciler.client_sessions = sessions

    async def _read_catalog(cfg):
        if cfg.namespace == "reports":
            return UpstreamCatalogRead(
                tools=[
                    _FakeTool("reports_read"),
                    _FakeTool("reports_write"),
                    _FakeTool("reports_extra"),
                ],
                prompts=[],
                resources=[],
                templates=[],
            )
        return UpstreamCatalogRead(
            tools=[_FakeTool("ledger_tool")],
            prompts=[],
            resources=[],
            templates=[],
        )

    with patch.object(upstreams, "read_catalog", side_effect=_read_catalog):
        await reconciler.tick()

    assert "ledger:ledger_tool" in registry.routes
    assert "reports:reports_extra" in registry.routes
    sessions.broadcast_list_changed.assert_awaited_once_with({"tools"})


# --- atomic add_route: no "ghost tool" after a skipped/rejected route (FX-proxy #1) --


class _FakeSchemaTool:
    def __init__(self, name: str, schema: dict, *, description: str = "fake tool") -> None:
        self.name = name
        self.description = description
        self.input_schema = schema


_GOOD_SCHEMA = {
    "type": "object",
    "properties": {"query": {"type": "string"}},
    "required": ["query"],
}

#: Before P07, ``from`` (a Python keyword) made a tool unpublishable:
#: ``inspect.Parameter`` refused it outright when the proxy built a handler's
#: Python function signature from the schema. Since P07 publishes the
#: upstream's own raw schema instead (no signature to build), this schema
#: publishes just fine -- see
#: ``test_proxy_foreign_upstream.test_tool_with_reserved_and_non_identifier_param_names_is_published``.
#: The two tests below instead inject a registration failure directly (as
#: ``test_upstream_discovery.test_one_unpublishable_tool_does_not_drop_the_namespace``
#: already does), to keep covering the atomicity guarantee for whatever other
#: reason ``add_route`` may still fail (see ``RouterRegistry.add_route``'s and
#: ``UpstreamRegistry.mark_unpublishable``'s docstrings).


async def test_unpublishable_tool_is_retried_every_tick_not_cached_as_done(
    reconciler_stack, caplog, monkeypatch
):
    """A tool that fails to publish must not get a fingerprint recorded for
    it: if it did, the next tick would see the (unregistered) fingerprint
    already matches "previous" and skip retrying it forever."""
    reconciler, registry, _policy_path, _policy_manager, upstreams = reconciler_stack
    upstreams.add_upstream("ledger", "http://ledger:8082/mcp", namespace="ledger")

    async def _fake_fetch(url: str, *, timeout_seconds: float, **_kwargs):
        if "reports" in url:
            raise UpstreamListToolsError("reports upstream unreachable")
        return [_FakeSchemaTool("bad_tool", _GOOD_SCHEMA)]

    original_register_tool = RouterRegistry._register_tool

    def flaky_register_tool(self, route, mcp):
        if route.name == "bad_tool":
            raise RuntimeError("boom")
        return original_register_tool(self, route, mcp)

    monkeypatch.setattr(RouterRegistry, "_register_tool", flaky_register_tool)

    with (
        caplog.at_level(logging.ERROR),
        patch(
            "keystone_mcp.router.upstream.fetch_upstream_tools",
            new_callable=AsyncMock,
            side_effect=_fake_fetch,
        ),
    ):
        await reconciler.tick()
        first_tick_errors = sum("upstream tool skipped" in r.message for r in caplog.records)
        caplog.clear()
        await reconciler.tick()
        second_tick_errors = sum("upstream tool skipped" in r.message for r in caplog.records)

    assert "ledger:bad_tool" not in registry.routes
    assert first_tick_errors == 1
    assert second_tick_errors == 1, "a skipped tool must be retried, not cached as handled"


async def test_failed_update_keeps_old_tool_and_removal_still_works(
    reconciler_stack, caplog, monkeypatch
):
    """The "ghost tool" scenario end to end, through the reconciler.

    Tick 1: ``good_tool`` publishes normally. Tick 2: the upstream changes the
    tool (forcing an update attempt) but republishing it fails; the update
    must be refused but the *old* version must stay fully published --
    registry and FastMCP agreeing -- and retried (ERROR) rather than silently
    cached as up to date. Tick 3: the upstream drops the tool entirely; it
    must actually disappear from both the registry and FastMCP's own catalog
    -- proving the old route was never orphaned from the fingerprint
    bookkeeping that drives removal.
    """
    reconciler, registry, _policy_path, _policy_manager, upstreams = reconciler_stack
    upstreams.add_upstream("ledger", "http://ledger:8082/mcp", namespace="ledger")
    sub = upstreams._sub_servers["ledger"]

    def _fetch_returning(namespace_tools: list):
        async def _fake_fetch(url: str, *, timeout_seconds: float, **_kwargs):
            if "reports" in url:
                raise UpstreamListToolsError("reports upstream unreachable")
            return namespace_tools

        return _fake_fetch

    # Tick 1: publish good_tool normally.
    with patch(
        "keystone_mcp.router.upstream.fetch_upstream_tools",
        new_callable=AsyncMock,
        side_effect=_fetch_returning([_FakeSchemaTool("good_tool", _GOOD_SCHEMA)]),
    ):
        await reconciler.tick()

    assert "ledger:good_tool" in registry.routes
    async with Client(sub) as client:
        tools = await client.list_tools()
    assert next(t for t in tools if t.name == "good_tool").input_schema["required"] == ["query"]

    # Tick 2: the upstream changes the tool's description (forcing an update
    # attempt -- the fingerprint changes), but republishing it fails this one
    # time. The update must be refused, logged, and the old (working) version
    # must remain exactly as it was.
    original_register_tool = RouterRegistry._register_tool

    def flaky_register_tool(self, route, mcp):
        if route.name == "good_tool":
            raise RuntimeError("boom")
        return original_register_tool(self, route, mcp)

    monkeypatch.setattr(RouterRegistry, "_register_tool", flaky_register_tool)

    with (
        caplog.at_level(logging.ERROR),
        patch(
            "keystone_mcp.router.upstream.fetch_upstream_tools",
            new_callable=AsyncMock,
            side_effect=_fetch_returning(
                [_FakeSchemaTool("good_tool", _GOOD_SCHEMA, description="good tool, v2")]
            ),
        ),
    ):
        await reconciler.tick()

    assert any("upstream tool skipped" in r.message for r in caplog.records)
    assert "ledger:good_tool" in registry.routes
    assert registry.routes["ledger:good_tool"].description == "fake tool"
    async with Client(sub) as client:
        tools = await client.list_tools()
    still_good = next(t for t in tools if t.name == "good_tool")
    assert list(still_good.input_schema["properties"]) == ["query"]

    monkeypatch.setattr(RouterRegistry, "_register_tool", original_register_tool)

    # Tick 3: the upstream drops the tool entirely. It must actually be
    # removed now -- the failed update in tick 2 must not have orphaned it
    # from the fingerprint bookkeeping that drives removal.
    with patch(
        "keystone_mcp.router.upstream.fetch_upstream_tools",
        new_callable=AsyncMock,
        side_effect=_fetch_returning([_FakeSchemaTool("other_tool", _GOOD_SCHEMA)]),
    ):
        await reconciler.tick()

    assert "ledger:good_tool" not in registry.routes
    assert "ledger:other_tool" in registry.routes
    async with Client(sub) as client:
        tools = await client.list_tools()
    assert not any(t.name == "good_tool" for t in tools)


_ENUM_SCHEMA_V1 = {
    "type": "object",
    "properties": {"mode": {"type": "string", "enum": ["a", "b"]}},
    "required": ["mode"],
}
_ENUM_SCHEMA_V2 = {
    "type": "object",
    "properties": {"mode": {"type": "string", "enum": ["a", "b", "c"]}},
    "required": ["mode"],
}


async def test_enum_change_triggers_update(reconciler_stack, caplog):
    """P07: the fingerprint now covers the published schema itself, not just
    ``Param`` fields, so an upstream that only changes an ``enum`` (same
    param name, type and required-ness) is still seen as "updated" -- and the
    pre-update tool is removed first, so no "Component already exists"
    WARNING is logged on the (now routine) schema-only update."""
    reconciler, registry, _policy_path, _policy_manager, upstreams = reconciler_stack
    upstreams.add_upstream("ledger", "http://ledger:8082/mcp", namespace="ledger")
    sub = upstreams._sub_servers["ledger"]

    def _fetch_returning(tools: list):
        async def _fake_fetch(url: str, *, timeout_seconds: float, **_kwargs):
            if "reports" in url:
                raise UpstreamListToolsError("reports upstream unreachable")
            return tools

        return _fake_fetch

    with patch(
        "keystone_mcp.router.upstream.fetch_upstream_tools",
        new_callable=AsyncMock,
        side_effect=_fetch_returning([_FakeSchemaTool("set_mode", _ENUM_SCHEMA_V1)]),
    ):
        await reconciler.tick()

    assert "ledger:set_mode" in registry.routes
    async with Client(sub) as client:
        tools = await client.list_tools()
    first = next(t for t in tools if t.name == "set_mode")
    assert first.input_schema["properties"]["mode"]["enum"] == ["a", "b"]

    with (
        caplog.at_level(logging.INFO),
        patch(
            "keystone_mcp.router.upstream.fetch_upstream_tools",
            new_callable=AsyncMock,
            side_effect=_fetch_returning([_FakeSchemaTool("set_mode", _ENUM_SCHEMA_V2)]),
        ),
    ):
        await reconciler.tick()

    assert not any("Component already exists" in r.message for r in caplog.records)
    assert any("added=0 removed=0 updated=1" in r.getMessage() for r in caplog.records), [
        r.getMessage() for r in caplog.records
    ]

    async with Client(sub) as client:
        tools = await client.list_tools()
    second = next(t for t in tools if t.name == "set_mode")
    assert second.input_schema["properties"]["mode"]["enum"] == ["a", "b", "c"]


async def test_policy_reload_runs_even_if_catalog_refresh_crashes(reconciler_stack):
    reconciler, _registry, policy_path, policy_manager, _upstreams = reconciler_stack
    policy_path.write_text(
        TEST_POLICY.replace('version: "3.0.0"', 'version: "3.0.3"'),
        encoding="utf-8",
    )

    with patch.object(reconciler, "_refresh_catalogs", side_effect=RuntimeError("boom")):
        await reconciler.tick()

    assert policy_manager.identity is not None
    assert policy_manager.identity.version == "3.0.3"


async def test_supervisor_restarts_crashed_loop(reconciler_stack, monkeypatch):
    reconciler, *_rest = reconciler_stack
    monkeypatch.setattr(reconciler_module, "_RESTART_DELAY_MIN_SECONDS", 0.01)

    calls = {"count": 0}
    recovered = asyncio.Event()

    async def _fake_run_loop(interval: int) -> None:
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("loop exploded")
        recovered.set()
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            raise

    with patch.object(reconciler, "_run_loop", side_effect=_fake_run_loop):
        reconciler._loop = asyncio.get_running_loop()
        reconciler._task = asyncio.create_task(
            reconciler._supervise(300), name="surface-reconciler"
        )
        await asyncio.wait_for(recovered.wait(), timeout=2)
        assert calls["count"] == 2

        await reconciler.stop()


async def test_sighup_with_dead_task_reloads_inline(reconciler_stack):
    reconciler, *_rest = reconciler_stack
    reconciler._loop = asyncio.get_running_loop()

    async def _already_done() -> None:
        return None

    reconciler._task = asyncio.create_task(_already_done())
    await reconciler._task  # ensure done() is True

    assert reconciler.request_policy_reload() is False


async def test_sighup_forces_reload_through_the_running_loop_even_if_file_unchanged(
    reconciler_stack,
):
    """``_run_loop`` must not clear the policy-reload event before ``tick()``.

    It used to call ``self._policy_reload_event.clear()`` right after
    ``wait_for`` returned, *before* calling ``tick()``. By the time
    ``_tick_locked`` checked ``is_set()`` the event was already false, so
    ``force_policy`` was always False and a SIGHUP (or
    ``request_policy_reload()``) with an unchanged policy file never actually
    forced a reload — only a real file change ever reloaded the policy.
    """
    reconciler, _registry, _policy_path, policy_manager, _upstreams = reconciler_stack

    with patch.object(reconciler, "_refresh_catalogs", new_callable=AsyncMock):
        with patch.object(policy_manager, "reload", wraps=policy_manager.reload) as reload_spy:
            reconciler._loop = asyncio.get_running_loop()
            loop_task = asyncio.create_task(reconciler._run_loop(300))
            reconciler._task = loop_task
            # Give _run_loop a tick to reach the wait_for() call.
            await asyncio.sleep(0)

            assert reconciler.request_policy_reload() is True

            for _ in range(200):
                if reload_spy.called:
                    break
                await asyncio.sleep(0.01)

            loop_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await loop_task

    assert reload_spy.called, "SIGHUP did not force a policy reload on an unchanged file"


async def test_refresh_interval_zero_skips_reconciler_creation():
    settings = Settings(base_url="http://localhost:8080", refresh_interval_seconds=0)
    from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
    from keystone_mcp.server import build_server

    _mcp, _registry, _oauth, _upstreams, _pm, _obs, reconciler = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
    )
    assert reconciler is None


# --- per-upstream availability status (P05) ----------------------------------------


class _FakeTool:
    def __init__(self, name: str, *, description: str = "") -> None:
        self.name = name
        self.description = description
        self.input_schema = None


async def test_upstream_down_at_start_is_added_when_it_comes_up():
    """A namespace with no routes yet, marked unavailable at add_upstream time,
    gets its tools and its 'available' status back on the first successful tick."""
    settings = Settings(base_url="http://localhost:8080", refresh_interval_seconds=300)
    main = FastMCP("main")
    engine = RouterEngine(settings)
    registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(main_mcp=main, registry=registry, discovery_timeout_seconds=5.0)
    upstreams.add_upstream("ledger", "http://ledger:8083/mcp", namespace="ledger")

    assert upstreams.unavailable_namespaces() == {"ledger": "not discovered yet"}

    reconciler = SurfaceReconciler(
        settings=settings,
        registry=registry,
        upstreams=upstreams,
        policy_manager=None,
        observability=None,
    )
    reconciler.seed_snapshots()

    with patch(
        "keystone_mcp.router.upstream.fetch_upstream_tools",
        new_callable=AsyncMock,
        return_value=[_FakeTool("read"), _FakeTool("write")],
    ):
        await reconciler.tick()

    assert "ledger:read" in registry.routes
    assert "ledger:write" in registry.routes
    assert upstreams.unavailable_namespaces() == {}


async def test_upstream_lost_after_start_keeps_tools_and_is_reported(
    reconciler_stack, caplog: pytest.LogCaptureFixture
):
    reconciler, registry, _policy_path, _policy_manager, upstreams = reconciler_stack
    before = set(registry.routes.keys())
    # Simulate "reports" having been reachable at startup.
    upstreams.mark_available("reports")

    with (
        caplog.at_level(logging.WARNING, logger=reconciler_module.__name__),
        patch(
            "keystone_mcp.router.upstream.fetch_upstream_tools",
            new_callable=AsyncMock,
            side_effect=UpstreamListToolsError("reports down"),
        ),
    ):
        await reconciler.tick()
        became_unavailable_after_first = sum(
            1 for r in caplog.records if "became unavailable" in r.getMessage()
        )
        await reconciler.tick()

    assert set(registry.routes.keys()) == before
    assert upstreams.unavailable_namespaces() == {"reports": "reports down"}
    assert became_unavailable_after_first == 1
    became_unavailable_total = sum(
        1 for r in caplog.records if "became unavailable" in r.getMessage()
    )
    assert became_unavailable_total == 1
    refresh_failed_count = sum(
        1 for r in caplog.records if "upstream refresh failed" in r.getMessage()
    )
    assert refresh_failed_count == 2


async def test_upstream_recovery_is_logged(reconciler_stack, caplog: pytest.LogCaptureFixture):
    reconciler, _registry, _policy_path, _policy_manager, upstreams = reconciler_stack
    upstreams.mark_available("reports")
    upstreams.mark_unavailable("reports", "temporary outage")

    with (
        # "available again" is logged by keystone_mcp.router.upstream, not the
        # reconciler itself, so capture at the root logger instead of scoping
        # to one module.
        caplog.at_level(logging.INFO),
        patch(
            "keystone_mcp.router.upstream.fetch_upstream_tools",
            new_callable=AsyncMock,
            return_value=[_FakeTool("reports_read"), _FakeTool("reports_write")],
        ),
    ):
        await reconciler.tick()

    assert upstreams.unavailable_namespaces() == {}
    assert any("available again" in r.getMessage() for r in caplog.records)


# --- RBAC drift re-check when an unavailable namespace comes up (P06) --------------

DOCS_TYPO_POLICY = """\
version: "3.0.0"
default_deny: true
roles:
  administrator:
    allow: ["reports_read", "docs_serch"]
"""

DOCS_GLOB_POLICY = """\
version: "3.0.0"
default_deny: true
roles:
  administrator:
    allow: ["reports_read", "docs_*"]
"""


def _build_docs_reconciler(tmp_path: Path, policy_text: str):
    """A standalone reconciler with one namespace ("docs"), unavailable from
    the start, and a policy manager wired to its catalog state -- unlike
    ``reconciler_stack``, which builds ``RbacPolicyManager(settings)`` with no
    upstream state at all."""
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy_text, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_service_url="http://users:8000",
        users_service_token="token",
        refresh_interval_seconds=300,
        upstream_discovery_timeout_seconds=5.0,
    )
    main = FastMCP("main")
    engine = RouterEngine(settings)
    registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(main_mcp=main, registry=registry, discovery_timeout_seconds=5.0)
    upstreams.add_upstream("docs", "http://docs:8081/mcp", namespace="docs")
    from keystone_mcp.adapters.stub import StubAdapter

    registry.add_route("reports_read", StubAdapter(), pattern=Pattern.SYNC, mode="live")
    policy_manager = RbacPolicyManager(settings, upstream_catalog_state=upstreams.catalog_state)
    policy_manager.load_initial(registry)  # docs is down: docs_* / docs_serch are "not verified"
    reconciler = SurfaceReconciler(
        settings=settings,
        registry=registry,
        upstreams=upstreams,
        policy_manager=policy_manager,
        observability=None,
    )
    reconciler.seed_snapshots()
    return reconciler, registry, upstreams, policy_manager


async def test_drift_check_runs_when_unavailable_upstream_comes_up(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
):
    """``docs`` was down at load time so its typo'd allow pattern was merely
    "not verified"; once it comes up with a real catalog that does not
    contain the typo'd name, the drift check must report it as an ERROR
    (the policy stays active either way -- drift never refuses)."""
    reconciler, registry, upstreams, policy_manager = _build_docs_reconciler(
        tmp_path, DOCS_TYPO_POLICY
    )
    assert upstreams.unavailable_namespaces() == {"docs": "not discovered yet"}

    with (
        caplog.at_level(logging.ERROR),
        patch(
            "keystone_mcp.router.upstream.fetch_upstream_tools",
            new_callable=AsyncMock,
            return_value=[_FakeTool("search")],
        ),
    ):
        await reconciler.tick()

    assert upstreams.unavailable_namespaces() == {}
    assert "docs:search" in registry.routes
    assert any(
        "unmatched allow patterns after catalog change" in r.getMessage()
        and "docs_serch" in r.getMessage()
        for r in caplog.records
    )
    assert policy_manager.active_policy is not None


async def test_drift_check_runs_when_upstream_comes_up_with_empty_list(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
):
    """Same namespace, but it answers with zero tools on its first tick: the
    catalog does not change (still empty), yet the transition to available
    must still trigger the drift check, or ``docs_*`` would stay "not
    verified" forever."""
    reconciler, _registry, upstreams, policy_manager = _build_docs_reconciler(
        tmp_path, DOCS_GLOB_POLICY
    )
    assert upstreams.unavailable_namespaces() == {"docs": "not discovered yet"}

    with (
        caplog.at_level(logging.ERROR),
        patch(
            "keystone_mcp.router.upstream.fetch_upstream_tools",
            new_callable=AsyncMock,
            return_value=[],
        ),
    ):
        await reconciler.tick()

    assert upstreams.unavailable_namespaces() == {}
    assert any(
        "unmatched allow patterns after catalog change" in r.getMessage()
        and "docs_*" in r.getMessage()
        for r in caplog.records
    )
    assert policy_manager.active_policy is not None
