"""Operational RBAC policy loader: live catalog gate, snapshot merge, hot-reload."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastmcp import FastMCP

from keystone_mcp.adapters.base import Pattern
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.rbac.catalog import collect_live_tool_names
from keystone_mcp.rbac.catalog_snapshot import CatalogSnapshot
from keystone_mcp.rbac.loader import (
    PolicyLoadError,
    RbacPolicyManager,
    assert_live_catalog_validation,
    split_unverified_allow_patterns,
)
from keystone_mcp.rbac.policy import (
    PolicyContractError,
    default_policy_path,
    hash_policy_bytes,
    load_policy_file,
    load_policy_file_with_hash,
    parse_policy_yaml,
    policy_content_hash,
)
from keystone_mcp.rbac.upstream_state import UpstreamCatalogState, pattern_owner
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import (
    UpstreamListToolsError,
    UpstreamRegistry,
    UpstreamUnavailableError,
)
from keystone_mcp.server import (
    bootstrap_platform,
    bootstrap_rbac_policy,
    build_server,
    install_policy_reload_signal,
)
from keystone_mcp.surface.reconciler import SurfaceReconciler

LIVE_TOOLS = frozenset(
    {
        "create_upload_url",
        "get_download_link",
        "documents_read",
        "documents_write",
        "reports_read",
        "reports_write",
        "ledger_read",
        "ledger_commit",
    }
)

TEST_POLICY = """\
version: "3.0.0"
default_deny: true
roles:
  administrator:
    description: admin
    allow: ["*"]
  editor:
    description: editor
    allow:
      - documents_*
      - reports_*
      - ledger_read
      - ledger_commit
      - create_upload_url
      - get_download_link
  viewer:
    description: viewer
    allow:
      - documents_read
      - reports_read
      - get_download_link
requires_human_identity: ["ledger_commit"]
critical_tools: ["ledger_*"]
"""

SNAPSHOT_YAML = """\
active: ["documents_read", "documents_write", "reports_read", "reports_write"]
reserved: ["documents_purge"]
wip: ["reports_approve_run"]
"""


class _StubAdapter:
    async def invoke(self, **_kwargs):
        return {"state": "ok"}


def _make_registry_with_tools(
    tool_names: frozenset[str],
    *,
    stub_names: frozenset[str] = frozenset(),
) -> RouterRegistry:
    mcp = FastMCP("test-main")
    engine = RouterEngine(Settings(base_url="http://localhost:8080"))
    registry = RouterRegistry(engine, mcp)
    adapter = _StubAdapter()
    for name in sorted(tool_names):
        registry.add_route(name, adapter, pattern=Pattern.M_B, mode="live")
    for name in sorted(stub_names):
        registry.add_route(name, adapter, pattern=Pattern.M_B, mode="stub")
    return registry


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    target = tmp_path / "rbac-policy.yaml"
    target.write_text(TEST_POLICY, encoding="utf-8")
    return target


@pytest.fixture
def rbac_settings(policy_path: Path) -> Settings:
    return Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_service_url="http://users:8000",
        users_service_token="token",
        refresh_interval_seconds=0,
    )


# --- live catalog collection ----------------------------------------------------


def test_collect_live_tool_names_uses_published_names():
    registry = _make_registry_with_tools(frozenset({"create_upload_url", "get_download_link"}))
    names = collect_live_tool_names(registry)
    assert names == ("create_upload_url", "get_download_link")
    assert isinstance(names, tuple)


def test_collect_live_tool_names_excludes_stub_routes():
    registry = _make_registry_with_tools(
        frozenset({"create_upload_url"}),
        stub_names=frozenset({"get_download_link", "documents_read"}),
    )
    assert collect_live_tool_names(registry) == ("create_upload_url",)


# --- startup gate ---------------------------------------------------------------


def test_policy_validates_against_full_live_catalog():
    policy = parse_policy_yaml(TEST_POLICY)
    assert_live_catalog_validation(policy, LIVE_TOOLS)


def test_policy_validates_against_a_live_subset():
    """A deployment may mount fewer tools than the policy globs could match."""
    policy = parse_policy_yaml(TEST_POLICY)
    result = assert_live_catalog_validation(
        policy,
        LIVE_TOOLS - {"documents_write", "reports_write"},
    )
    assert result.ok
    assert "documents_write" not in result.tool_names


def test_unmatched_allow_pattern_fails_live_validation():
    policy = parse_policy_yaml(TEST_POLICY.replace("documents_*", "docments_*", 1))
    with pytest.raises(PolicyContractError, match="unmatched allow patterns"):
        assert_live_catalog_validation(policy, LIVE_TOOLS)


def test_snapshot_active_names_satisfy_patterns_absent_from_live():
    """Patterns matching only snapshot names load; the names stay unroutable."""
    policy = parse_policy_yaml(TEST_POLICY)
    snapshot = CatalogSnapshot(active=frozenset({"documents_read", "reports_read"}))
    live = frozenset({"create_upload_url", "get_download_link", "ledger_read", "ledger_commit"})
    with pytest.raises(PolicyContractError, match="unmatched allow patterns"):
        assert_live_catalog_validation(policy, live)
    result = assert_live_catalog_validation(policy, live, catalog_snapshot=snapshot)
    assert "documents_read" in result.tool_names


def test_snapshot_reserved_and_wip_feed_reserved_allow_patterns():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
reserved_allow_patterns: ["reports_approve_*"]
roles:
  administrator:
    allow: ["*"]
  reviewer:
    allow: ["reports_approve_*", "reports_read"]
"""
    )
    live = frozenset({"reports_read"})
    with pytest.raises(PolicyContractError, match="unmatched allow patterns"):
        assert_live_catalog_validation(policy, live)
    result = assert_live_catalog_validation(
        policy,
        live,
        catalog_snapshot=CatalogSnapshot(wip=frozenset({"reports_approve_run"})),
    )
    assert result.ok


def test_live_tool_reachable_by_no_role_is_a_warning_not_a_refusal(caplog):
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  viewer:
    allow: ["reports_read"]
"""
    )
    with caplog.at_level("WARNING"):
        result = assert_live_catalog_validation(
            policy,
            frozenset({"reports_read", "ledger_commit"}),
        )
    assert result.unreachable_tools == frozenset({"ledger_commit"})
    assert "unreachable by any role" in caplog.text


# --- unavailable upstream namespace gate (P06) -----------------------------------


def test_pattern_owner_takes_the_literal_head_and_longest_namespace():
    namespaces = {"docs", "billing", "billing_admin"}
    assert pattern_owner("docs_*", namespaces) == "docs"
    assert pattern_owner("docs_search", namespaces) == "docs"
    assert pattern_owner("docs_[ab]*", namespaces) == "docs"
    assert pattern_owner("*_search", namespaces) is None
    assert pattern_owner("doc*", namespaces) is None
    assert pattern_owner("billing_admin_x", namespaces) == "billing_admin"


def test_allow_pattern_of_unpublishable_tool_is_a_warning_not_an_error(caplog):
    """A tool the upstream offers but that could not be published (bad
    schema, FX-proxy #1) must not fail startup just because the policy
    explicitly names it -- the namespace itself is reachable, only this one
    tool is missing, and it is checked again once it publishes."""
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  viewer:
    allow: ["reports_read", "docs_search"]
"""
    )
    state = UpstreamCatalogState(
        namespaces=frozenset({"reports", "docs"}),
        unavailable=frozenset(),
        unpublishable=frozenset({"docs_search"}),
    )
    with caplog.at_level("WARNING"):
        result = assert_live_catalog_validation(
            policy,
            frozenset({"reports_read"}),
            upstream_state=state,
        )
    assert result is not None
    assert "docs_search" in caplog.text
    assert "viewer:docs_search" in caplog.text


def test_typo_in_tool_name_still_fails_while_a_different_tool_is_unpublishable():
    """``unpublishable`` only excuses patterns that actually match one of its
    names -- a plain typo elsewhere stays a hard error."""
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  viewer:
    allow: ["reports_read", "docs_serch"]
"""
    )
    state = UpstreamCatalogState(
        namespaces=frozenset({"reports", "docs"}),
        unavailable=frozenset(),
        unpublishable=frozenset({"docs_search"}),
    )
    with pytest.raises(PolicyContractError, match="viewer:docs_serch"):
        assert_live_catalog_validation(
            policy,
            frozenset({"reports_read"}),
            upstream_state=state,
        )


def test_reserved_allow_pattern_is_not_excused_by_unpublishable():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
reserved_allow_patterns: ["docs_future"]
roles:
  viewer:
    allow: ["reports_read", "docs_future"]
"""
    )
    state = UpstreamCatalogState(
        namespaces=frozenset({"reports", "docs"}),
        unavailable=frozenset(),
        unpublishable=frozenset({"docs_future"}),
    )
    with pytest.raises(PolicyContractError, match="viewer:docs_future"):
        assert_live_catalog_validation(
            policy,
            frozenset({"reports_read"}),
            catalog_snapshot=CatalogSnapshot(),
            upstream_state=state,
        )


async def test_bootstrap_platform_starts_under_rbac_with_policy_for_unpublishable_tool(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
):
    """End-to-end (startup): a tool that fails to publish must not take the
    whole server down, even when the RBAC policy explicitly allows it by name
    (FX-proxy #1).

    Since P07, a parameter named ``from`` no longer makes a tool
    unpublishable (the upstream's raw schema is published verbatim, with no
    Python function signature built from it -- see
    ``test_proxy_foreign_upstream.
    test_tool_with_reserved_and_non_identifier_param_names_is_published``).
    This test instead injects a registration failure directly, to keep
    covering the ``mark_unpublishable``/"not verified" path for whatever
    other reason publication may still fail.
    """
    policy_file = tmp_path / "rbac-policy.yaml"
    policy_file.write_text(
        """\
version: "0.1"
default_deny: true
roles:
  administrator:
    allow: ["ns_bad_tool"]
""",
        encoding="utf-8",
    )
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_file),
        users_service_url="http://users:8000",
        users_service_token="token",
        refresh_interval_seconds=0,
        upstream_discovery_retries=0,
    )
    _mcp, registry, _oauth, upstreams, policy_manager, _observability, _reconciler = build_server(
        settings=settings,
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    upstreams.add_upstream("bad-mcp", "http://unused", namespace="ns")

    harmless_schema = {"type": "object", "properties": {}}
    tools = [SimpleNamespace(name="bad_tool", description="", inputSchema=harmless_schema)]

    original_register_tool = RouterRegistry._register_tool

    def flaky_register_tool(self, route, mcp):
        if route.name == "bad_tool":
            raise RuntimeError("boom")
        return original_register_tool(self, route, mcp)

    monkeypatch.setattr(RouterRegistry, "_register_tool", flaky_register_tool)

    with (
        caplog.at_level(logging.WARNING),
        patch(
            "keystone_mcp.router.upstream.fetch_upstream_tools",
            new_callable=AsyncMock,
            return_value=tools,
        ),
    ):
        discovery = await bootstrap_platform(upstreams, registry, settings, policy_manager)

    assert discovery.failed is False
    assert "ns:bad_tool" not in registry.routes
    assert policy_manager is not None
    assert policy_manager.identity is not None
    assert any(
        "not verified" in record.getMessage() and "ns_bad_tool" in record.getMessage()
        for record in caplog.records
    )


def test_allow_pattern_of_unavailable_namespace_is_a_warning(caplog):
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  viewer:
    allow: ["reports_read", "docs_*"]
"""
    )
    state = UpstreamCatalogState(
        namespaces=frozenset({"reports", "docs"}),
        unavailable=frozenset({"docs"}),
    )
    with caplog.at_level("WARNING"):
        result = assert_live_catalog_validation(
            policy,
            frozenset({"reports_read"}),
            upstream_state=state,
        )
    assert result is not None
    assert "docs" in caplog.text
    assert "viewer:docs_*" in caplog.text


def test_typo_in_namespace_part_still_fails_while_upstream_is_down():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  viewer:
    allow: ["reports_read", "dosc_*"]
"""
    )
    state = UpstreamCatalogState(
        namespaces=frozenset({"reports", "docs"}),
        unavailable=frozenset({"docs"}),
    )
    with pytest.raises(PolicyContractError, match="viewer:dosc_\\*"):
        assert_live_catalog_validation(
            policy,
            frozenset({"reports_read"}),
            upstream_state=state,
        )


def test_reserved_allow_pattern_is_not_excused_by_unavailability():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
reserved_allow_patterns: ["docs_future"]
roles:
  viewer:
    allow: ["reports_read", "docs_future"]
"""
    )
    state = UpstreamCatalogState(
        namespaces=frozenset({"reports", "docs"}),
        unavailable=frozenset({"docs"}),
    )
    with pytest.raises(PolicyContractError, match="viewer:docs_future"):
        assert_live_catalog_validation(
            policy,
            frozenset({"reports_read"}),
            catalog_snapshot=CatalogSnapshot(),
            upstream_state=state,
        )


def test_star_pattern_is_not_reclassified():
    """Every upstream down and an empty catalog never reaches this gate under
    RBAC: P05's "all unavailable" refusal fires first, inside
    ``bootstrap_platform`` -- see
    ``test_bootstrap_platform_refuses_when_every_upstream_is_down_under_rbac``.
    This gate itself, called directly with an empty catalog and no live
    upstream, downgrades ``*`` to a WARNING regardless (S4): see
    ``test_star_pattern_on_empty_catalog_is_a_warning``.
    """
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  admin:
    allow: ["*"]
"""
    )
    state = UpstreamCatalogState(namespaces=frozenset({"docs"}), unavailable=frozenset({"docs"}))
    # Does not raise: the empty catalog makes "*" unmatched, and that is
    # always a warning, never an error (S4), independent of upstream state.
    assert_live_catalog_validation(policy, frozenset(), upstream_state=state)


def test_star_pattern_on_empty_catalog_is_a_warning(caplog):
    """S4: an empty live catalog (e.g. ``observe`` mode, no upstream mounted,
    file tools off) must not refuse a policy whose only pattern is ``*``."""
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  admin:
    allow: ["*"]
"""
    )
    state = UpstreamCatalogState(namespaces=frozenset(), unavailable=frozenset())
    with caplog.at_level("WARNING"):
        result = assert_live_catalog_validation(policy, frozenset(), upstream_state=state)
    assert result is not None
    assert "catalog is empty" in caplog.text


def test_snapshot_active_name_satisfies_pattern_of_unavailable_namespace(caplog):
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  viewer:
    allow: ["docs_search"]
"""
    )
    state = UpstreamCatalogState(namespaces=frozenset({"docs"}), unavailable=frozenset({"docs"}))
    with caplog.at_level("WARNING"):
        result = assert_live_catalog_validation(
            policy,
            frozenset(),
            catalog_snapshot=CatalogSnapshot(active=frozenset({"docs_search"})),
            upstream_state=state,
        )
    assert result.ok
    assert "not verified" not in caplog.text


def test_without_upstream_state_behaviour_is_unchanged():
    """``upstream_state=None`` (the default) keeps the 0.3.1 behaviour: every
    unmatched allow pattern is a hard error, even one that would be owned by
    an "unavailable" namespace if state were tracked."""
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  viewer:
    allow: ["docs_*"]
"""
    )
    with pytest.raises(PolicyContractError, match="viewer:docs_\\*"):
        assert_live_catalog_validation(policy, frozenset())


def test_split_unverified_allow_patterns_with_no_state_is_all_errors():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  viewer:
    allow: ["docs_*", "reports_*"]
"""
    )
    errors, unverified = split_unverified_allow_patterns(
        policy, ("viewer:docs_*", "viewer:reports_*"), None
    )
    assert set(errors) == {"viewer:docs_*", "viewer:reports_*"}
    assert unverified == {}


# --- manager ---------------------------------------------------------------------


def test_manager_loads_policy_from_config_path(rbac_settings: Settings, policy_path: Path):
    registry = _make_registry_with_tools(LIVE_TOOLS)
    manager = RbacPolicyManager(rbac_settings)
    snapshot = manager.load_initial(registry)

    assert snapshot.policy.version == "3.0.0"
    assert snapshot.identity.source_path == policy_path
    assert snapshot.identity.content_hash == policy_content_hash(policy_path)
    assert manager.policy is snapshot.policy
    assert manager.identity == snapshot.identity


def test_active_policy_is_none_before_load(rbac_settings: Settings):
    manager = RbacPolicyManager(rbac_settings)
    assert manager.active_policy is None
    with pytest.raises(PolicyLoadError, match="has not been loaded"):
        _ = manager.policy


def test_load_policy_file_with_hash_matches_parsed_bytes(policy_path: Path):
    raw_bytes = policy_path.read_bytes()
    policy, content_hash = load_policy_file_with_hash(policy_path)
    assert policy.version == "3.0.0"
    assert content_hash == hash_policy_bytes(raw_bytes)
    assert content_hash == policy_content_hash(policy_path)


def test_manager_without_snapshot_setting_works(rbac_settings: Settings):
    manager = RbacPolicyManager(rbac_settings)
    assert manager.catalog_snapshot().is_empty is True
    manager.load_initial(_make_registry_with_tools(LIVE_TOOLS))


def test_manager_merges_configured_snapshot(tmp_path: Path, policy_path: Path):
    snapshot_path = tmp_path / "snapshot.yaml"
    snapshot_path.write_text(SNAPSHOT_YAML, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        rbac_catalog_snapshot_path=str(snapshot_path),
        users_service_url="http://users:8000",
        users_service_token="token",
    )
    manager = RbacPolicyManager(settings)
    assert manager.catalog_snapshot().active == frozenset(
        {"documents_read", "documents_write", "reports_read", "reports_write"}
    )
    # documents_* / reports_* are satisfied by the snapshot, not the live routes.
    manager.load_initial(
        _make_registry_with_tools(
            frozenset({"create_upload_url", "get_download_link", "ledger_read", "ledger_commit"})
        )
    )
    assert manager.policy.version == "3.0.0"


def test_manager_rejects_unreadable_snapshot(tmp_path: Path, policy_path: Path):
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        rbac_catalog_snapshot_path=str(tmp_path / "missing.yaml"),
        users_service_url="http://users:8000",
        users_service_token="token",
    )
    manager = RbacPolicyManager(settings)
    with pytest.raises(PolicyLoadError, match="CATALOG_SNAPSHOT"):
        manager.load_initial(_make_registry_with_tools(LIVE_TOOLS))


def test_manager_refuses_missing_policy_file(tmp_path: Path):
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(tmp_path / "absent.yaml"),
        users_service_url="http://users:8000",
        users_service_token="token",
    )
    manager = RbacPolicyManager(settings)
    with pytest.raises(PolicyLoadError, match="does not exist"):
        manager.load_initial(_make_registry_with_tools(LIVE_TOOLS))


# --- hot reload -------------------------------------------------------------------


def test_hot_reload_applies_valid_policy(rbac_settings: Settings, policy_path: Path):
    registry = _make_registry_with_tools(LIVE_TOOLS)
    manager = RbacPolicyManager(rbac_settings)
    first = manager.load_initial(registry)
    policy_path.write_text(
        TEST_POLICY.replace('version: "3.0.0"', 'version: "3.0.1"'),
        encoding="utf-8",
    )

    result = manager.reload(registry)

    assert result.success is True
    assert result.error is None
    assert manager.identity is not None
    assert manager.identity.version == "3.0.1"
    assert manager.identity.content_hash != first.identity.content_hash


def test_hot_reload_refreshes_human_identity_and_critical_sets(
    rbac_settings: Settings,
    policy_path: Path,
):
    registry = _make_registry_with_tools(LIVE_TOOLS)
    manager = RbacPolicyManager(rbac_settings)
    manager.load_initial(registry)
    assert manager.policy.requires_human_identity("ledger_commit") is True
    assert manager.policy.is_critical_tool("ledger_read") is True

    policy_path.write_text(
        TEST_POLICY.replace('requires_human_identity: ["ledger_commit"]', "")
        .replace('critical_tools: ["ledger_*"]', 'critical_tools: ["documents_*"]')
        .replace('version: "3.0.0"', 'version: "3.1.0"'),
        encoding="utf-8",
    )
    assert manager.reload(registry).success is True

    assert manager.policy.version == "3.1.0"
    assert manager.policy.requires_human_identity("ledger_commit") is False
    assert manager.policy.is_critical_tool("ledger_read") is False
    assert manager.policy.is_critical_tool("documents_write") is True


def test_hot_reload_rolls_back_on_invalid_policy(rbac_settings: Settings, policy_path: Path):
    registry = _make_registry_with_tools(LIVE_TOOLS)
    manager = RbacPolicyManager(rbac_settings)
    first = manager.load_initial(registry)
    policy_path.write_text(TEST_POLICY.replace("documents_*", "docments_*", 1), encoding="utf-8")

    result = manager.reload(registry)

    assert result.success is False
    assert result.error is not None
    assert manager.identity == first.identity
    assert manager.policy.version == "3.0.0"


def test_hot_reload_rolls_back_on_unknown_top_level_key(
    rbac_settings: Settings,
    policy_path: Path,
):
    registry = _make_registry_with_tools(LIVE_TOOLS)
    manager = RbacPolicyManager(rbac_settings)
    manager.load_initial(registry)
    policy_path.write_text(TEST_POLICY + 'canonical_roles: ["administrator"]\n', encoding="utf-8")

    result = manager.reload(registry)

    assert result.success is False
    assert "unknown top-level keys" in (result.error or "")
    assert manager.policy.version == "3.0.0"


def test_hot_reload_rolls_back_when_policy_file_missing(
    rbac_settings: Settings,
    policy_path: Path,
):
    registry = _make_registry_with_tools(LIVE_TOOLS)
    manager = RbacPolicyManager(rbac_settings)
    first = manager.load_initial(registry)
    policy_path.unlink()

    result = manager.reload(registry)

    assert result.success is False
    assert "does not exist" in (result.error or "")
    assert manager.identity == first.identity
    assert manager.policy.version == "3.0.0"


def test_install_policy_reload_signal_invokes_reload(
    rbac_settings: Settings,
    policy_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    import signal as signal_mod

    if not hasattr(signal_mod, "SIGHUP"):
        pytest.skip("SIGHUP not available on this platform")

    registry = _make_registry_with_tools(LIVE_TOOLS)
    manager = RbacPolicyManager(rbac_settings)
    manager.load_initial(registry)
    policy_path.write_text(
        TEST_POLICY.replace('version: "3.0.0"', 'version: "3.0.2"'),
        encoding="utf-8",
    )

    captured: list[object] = []

    def fake_signal(signum, handler):
        captured.append((signum, handler))

    monkeypatch.setattr(signal_mod, "signal", fake_signal)
    install_policy_reload_signal(registry, manager)

    assert captured
    _signum, handler = captured[0]
    handler(_signum, None)
    assert manager.identity is not None
    assert manager.identity.version == "3.0.2"


async def test_install_policy_reload_signal_falls_back_when_reconciler_dead(
    rbac_settings: Settings,
    policy_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """SIGHUP must still reload the policy inline when the reconciler's
    background task is not running (dead or never started), instead of
    silently doing nothing."""
    import signal as signal_mod

    if not hasattr(signal_mod, "SIGHUP"):
        pytest.skip("SIGHUP not available on this platform")

    registry = _make_registry_with_tools(LIVE_TOOLS)
    manager = RbacPolicyManager(rbac_settings)
    manager.load_initial(registry)
    policy_path.write_text(
        TEST_POLICY.replace('version: "3.0.0"', 'version: "3.0.4"'),
        encoding="utf-8",
    )

    main = FastMCP("main")
    engine = RouterEngine(rbac_settings)
    reconciler_registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(main_mcp=main, registry=reconciler_registry)
    reconciler = SurfaceReconciler(
        settings=rbac_settings,
        registry=reconciler_registry,
        upstreams=upstreams,
        policy_manager=manager,
        observability=None,
    )
    reconciler._loop = asyncio.get_running_loop()

    async def _already_done() -> None:
        return None

    reconciler._task = asyncio.create_task(_already_done())
    await reconciler._task

    captured: list[object] = []

    def fake_signal(signum, handler):
        captured.append((signum, handler))

    monkeypatch.setattr(signal_mod, "signal", fake_signal)
    install_policy_reload_signal(registry, manager, reconciler=reconciler)

    assert captured
    _signum, handler = captured[0]
    handler(_signum, None)
    assert manager.identity is not None
    assert manager.identity.version == "3.0.4"


def test_hot_reload_accepts_policy_for_unavailable_namespace(
    rbac_settings: Settings, policy_path: Path
):
    """A reload that only adds an allow pattern for a currently-down upstream
    namespace must succeed (P06), not roll back as it would pre-P06."""
    registry = _make_registry_with_tools(LIVE_TOOLS)
    state = UpstreamCatalogState(namespaces=frozenset({"docs"}), unavailable=frozenset({"docs"}))
    manager = RbacPolicyManager(rbac_settings, upstream_catalog_state=lambda: state)
    manager.load_initial(registry)

    policy_path.write_text(
        TEST_POLICY.replace(
            "      - documents_*",
            "      - documents_*\n      - docs_*",
        ),
        encoding="utf-8",
    )

    result = manager.reload(registry)

    assert result.success is True
    assert result.error is None


# --- bootstrap ---------------------------------------------------------------------


def test_bootstrap_rbac_policy_fails_startup_on_invalid_policy(
    rbac_settings: Settings,
    policy_path: Path,
):
    policy_path.write_text(TEST_POLICY.replace("documents_*", "docments_*", 1), encoding="utf-8")
    registry = _make_registry_with_tools(LIVE_TOOLS)
    manager = RbacPolicyManager(rbac_settings)
    with pytest.raises(PolicyLoadError):
        bootstrap_rbac_policy(manager, registry)


async def test_bootstrap_platform_fails_when_discovery_failed_with_rbac(
    rbac_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
):
    _mcp, registry, _oauth, upstreams, policy_manager, _observability, _reconciler = build_server(
        settings=rbac_settings,
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    upstreams.add_upstream("fixture", "http://unused", namespace="fixture")

    async def failing_discover_all() -> dict[str, int]:
        raise RuntimeError("upstream unavailable")

    monkeypatch.setattr(upstreams, "discover_all", failing_discover_all)
    settings = replace(rbac_settings, upstream_discovery_retries=0)

    with pytest.raises(PolicyLoadError, match="upstream discovery failed"):
        await bootstrap_platform(upstreams, registry, settings, policy_manager)


async def test_bootstrap_platform_loads_policy_after_upstream_discovery(
    rbac_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
):
    _mcp, registry, _oauth, upstreams, policy_manager, _observability, _reconciler = build_server(
        settings=rbac_settings,
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    assert policy_manager is not None
    upstreams.add_upstream("fixture", "http://unused", namespace="fixture")

    async def fake_discover_all() -> dict[str, int]:
        adapter = _StubAdapter()
        for tool in sorted(LIVE_TOOLS):
            registry.add_route(tool, adapter, pattern=Pattern.M_B, mode="live")
        return {"fixture": len(LIVE_TOOLS)}

    monkeypatch.setattr(upstreams, "discover_all", fake_discover_all)
    await bootstrap_platform(upstreams, registry, rbac_settings, policy_manager)

    assert policy_manager.identity is not None
    assert policy_manager.identity.version == "3.0.0"


def test_build_server_skips_policy_manager_when_rbac_disabled():
    settings = Settings(base_url="http://localhost:8080", rbac_mode="off")
    _mcp, _registry, _oauth, _upstreams, policy_manager, _observability, _reconciler = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
    )
    assert policy_manager is None


def test_shipped_default_policy_loads_against_the_core_catalog(tmp_path: Path):
    """The default policy validates against the tools the core catalog registers."""
    policy = load_policy_file(default_policy_path())
    assert_live_catalog_validation(
        policy,
        frozenset({"create_upload_url", "get_download_link", "users_list"}),
    )


# --- startup with an unreachable upstream (P05) ------------------------------------

SINGLE_NAMESPACE_POLICY = """\
version: "3.0.0"
default_deny: true
roles:
  administrator:
    allow: ["reports_*"]
"""


async def _register_fixed_tools(upstreams, registry, cfg, names: tuple[str, ...]) -> int:
    """Stand-in for a real ``_discover_one``: register fixed tools under cfg.namespace."""
    adapter = upstreams._adapters[cfg.namespace]
    sub = upstreams._sub_servers[cfg.namespace]
    for name in names:
        registry.add_route(
            name,
            adapter,
            pattern=Pattern.M_B,
            mode="live",
            namespace=cfg.namespace,
            config_mode="PROXY",
            upstream_tool=name,
            mcp=sub,
        )
    return len(names)


async def test_bootstrap_platform_starts_with_one_upstream_down_under_rbac(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
):
    policy_file = tmp_path / "rbac-policy.yaml"
    policy_file.write_text(SINGLE_NAMESPACE_POLICY, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_file),
        users_service_url="http://users:8000",
        users_service_token="token",
        refresh_interval_seconds=0,
        upstream_discovery_retries=0,
    )
    _mcp, registry, _oauth, upstreams, policy_manager, _observability, _reconciler = build_server(
        settings=settings,
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    upstreams.add_upstream("reports-mcp", "http://reports:8081/mcp", namespace="reports")
    upstreams.add_upstream("ops-mcp", "http://ops:8082/mcp", namespace="ops")

    async def _discover_one(cfg):
        if cfg.namespace == "ops":
            raise UpstreamListToolsError("connection refused")
        return await _register_fixed_tools(upstreams, registry, cfg, ("read",))

    upstreams._discover_one = _discover_one  # type: ignore[method-assign]

    with caplog.at_level(logging.WARNING):
        discovery = await bootstrap_platform(upstreams, registry, settings, policy_manager)

    assert discovery.failed is False
    assert set(discovery.unavailable) == {"ops"}
    assert any(
        "ops" in record.getMessage() and record.levelno >= logging.WARNING
        for record in caplog.records
    )
    assert policy_manager is not None
    assert policy_manager.identity is not None


TWO_NAMESPACE_POLICY = """\
version: "3.0.0"
default_deny: true
roles:
  administrator:
    allow: ["reports_*", "docs_*"]
"""


async def test_bootstrap_platform_starts_under_rbac_with_policy_for_unavailable_upstream(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
):
    """A policy referencing a namespace whose upstream fails discovery loads
    with a WARNING (P06), instead of refusing to start (pre-P06 behaviour)."""
    policy_file = tmp_path / "rbac-policy.yaml"
    policy_file.write_text(TWO_NAMESPACE_POLICY, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_file),
        users_service_url="http://users:8000",
        users_service_token="token",
        refresh_interval_seconds=0,
        upstream_discovery_retries=0,
    )
    _mcp, registry, _oauth, upstreams, policy_manager, _observability, _reconciler = build_server(
        settings=settings,
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    upstreams.add_upstream("reports-mcp", "http://reports:8081/mcp", namespace="reports")
    upstreams.add_upstream("docs-mcp", "http://docs:8082/mcp", namespace="docs")

    async def _discover_one(cfg):
        if cfg.namespace == "docs":
            raise UpstreamListToolsError("connection refused")
        return await _register_fixed_tools(upstreams, registry, cfg, ("read",))

    upstreams._discover_one = _discover_one  # type: ignore[method-assign]

    with caplog.at_level(logging.WARNING):
        discovery = await bootstrap_platform(upstreams, registry, settings, policy_manager)

    assert discovery.failed is False
    assert set(discovery.unavailable) == {"docs"}
    assert policy_manager is not None
    assert policy_manager.identity is not None
    assert any(
        "not verified" in record.getMessage() and "docs" in record.getMessage()
        for record in caplog.records
    )


async def test_bootstrap_platform_refuses_when_every_upstream_is_down_under_rbac(
    rbac_settings: Settings,
):
    settings = replace(rbac_settings, upstream_discovery_retries=0)
    _mcp, registry, _oauth, upstreams, policy_manager, _observability, _reconciler = build_server(
        settings=settings,
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    upstreams.add_upstream("reports-mcp", "http://reports:8081/mcp", namespace="reports")
    upstreams.add_upstream("ops-mcp", "http://ops:8082/mcp", namespace="ops")

    async def _discover_one(cfg):
        raise UpstreamListToolsError(f"{cfg.namespace} unreachable")

    upstreams._discover_one = _discover_one  # type: ignore[method-assign]

    with pytest.raises(PolicyLoadError) as excinfo:
        await bootstrap_platform(upstreams, registry, settings, policy_manager)

    assert "reports" in str(excinfo.value)
    assert "ops" in str(excinfo.value)


async def test_bootstrap_platform_starts_with_every_upstream_down_without_rbac():
    settings = Settings(base_url="http://localhost:8080", upstream_discovery_retries=0)
    _mcp, registry, _oauth, upstreams, policy_manager, _observability, _reconciler = build_server(
        settings=settings,
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    assert policy_manager is None
    upstreams.add_upstream("reports-mcp", "http://reports:8081/mcp", namespace="reports")
    upstreams.add_upstream("ops-mcp", "http://ops:8082/mcp", namespace="ops")

    async def _discover_one(cfg):
        raise UpstreamListToolsError(f"{cfg.namespace} unreachable")

    upstreams._discover_one = _discover_one  # type: ignore[method-assign]

    discovery = await bootstrap_platform(upstreams, registry, settings, policy_manager)

    assert discovery.failed is True
    assert set(discovery.unavailable) == {"reports", "ops"}


async def test_require_all_refuses_when_one_upstream_is_down():
    settings = Settings(
        base_url="http://localhost:8080",
        upstream_require_all=True,
        upstream_discovery_retries=0,
    )
    _mcp, registry, _oauth, upstreams, policy_manager, _observability, _reconciler = build_server(
        settings=settings,
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    upstreams.add_upstream("reports-mcp", "http://reports:8081/mcp", namespace="reports")
    upstreams.add_upstream("ops-mcp", "http://ops:8082/mcp", namespace="ops")

    async def _discover_one(cfg):
        if cfg.namespace == "ops":
            raise UpstreamListToolsError("connection refused")
        return await _register_fixed_tools(upstreams, registry, cfg, ("read",))

    upstreams._discover_one = _discover_one  # type: ignore[method-assign]

    with pytest.raises(UpstreamUnavailableError) as excinfo:
        await bootstrap_platform(upstreams, registry, settings, policy_manager)

    assert "ops" in str(excinfo.value)


def test_default_policy_loads_against_builtin_catalog_in_enforce(tmp_path: Path):
    """A fresh enforce deployment, no file API and no upstream, still starts.

    ``register_catalog`` then publishes only the users_* admin tools (the file
    tools are skipped without ``KEYSTONE_MCP_FILE_API_URL``), and the shipped
    default policy (administrator: allow "*") must validate against that
    catalog without any "unmatched allow patterns" refusal.
    """
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(default_policy_path()),
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url="redis://localhost:6379/0",
        rbac_audit_subject_salt="test-salt",
    )
    mcp = FastMCP("test-builtin-only")
    engine = RouterEngine(settings)
    registry = RouterRegistry(engine, mcp)
    register_catalog(registry, settings)

    manager = RbacPolicyManager(settings)
    bootstrap_rbac_policy(manager, registry)

    assert manager.identity is not None
