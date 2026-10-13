"""Upstream prefix filter parsing and multi-mount discovery."""

from __future__ import annotations

import json
from types import SimpleNamespace

from fastmcp import Client, FastMCP

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings, load_settings
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import (
    UpstreamRegistry,
    build_prefix_tool_filter,
    resolve_mounted_tool_name,
)
from keystone_mcp.server import build_server

FACADE_TOOLS = [
    "submit_batch",
    "list_projects",
    "ledger_read",
    "ledger_put_rates",
    "reports_apply",
    "reports_read",
]


def test_build_prefix_tool_filter_include_only() -> None:
    predicate = build_prefix_tool_filter(include_prefixes=("ledger_",))
    assert predicate is not None
    assert predicate("ledger_read") is True
    assert predicate("reports_read") is False


def test_build_prefix_tool_filter_exclude_only() -> None:
    predicate = build_prefix_tool_filter(
        exclude_prefixes=("ledger_", "reports_"),
    )
    assert predicate is not None
    assert predicate("submit_batch") is True
    assert predicate("ledger_read") is False
    assert predicate("reports_apply") is False


def test_resolve_mounted_tool_name_strips_prefix() -> None:
    assert resolve_mounted_tool_name("ledger_read", "ledger_") == "read"
    assert resolve_mounted_tool_name("submit_batch", None) == "submit_batch"


def test_settings_upstreams_parse_prefix_filters(monkeypatch) -> None:
    payload = [
        {
            "name": "facade",
            "url": "http://facade-mcp-http:8098/mcp",
            "namespace": "facade",
            "enabled": True,
            "exclude_prefixes": ["ledger_", "reports_"],
        },
        {
            "name": "facade-ledger",
            "url": "http://facade-mcp-http:8098/mcp",
            "namespace": "ledger",
            "enabled": True,
            "tool_prefix": "ledger_",
        },
        {
            "name": "facade-reports",
            "url": "http://facade-mcp-http:8098/mcp",
            "namespace": "reports",
            "enabled": True,
            "include_prefixes": ["reports_"],
            "strip_prefix": "reports_",
        },
    ]
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS", json.dumps(payload))
    settings = load_settings()
    assert len(settings.upstreams) == 3

    doc_cfg, ledger_cfg, folder_cfg = settings.upstreams
    assert doc_cfg.exclude_prefixes == ("ledger_", "reports_")
    assert ledger_cfg.include_prefixes == ("ledger_",)
    assert ledger_cfg.strip_prefix == "ledger_"
    assert folder_cfg.include_prefixes == ("reports_",)
    assert folder_cfg.strip_prefix == "reports_"


async def test_discover_splits_one_facade_by_prefix() -> None:
    main = FastMCP("keystone-main")
    engine = RouterEngine(Settings(base_url="http://localhost:8080"))
    registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(main_mcp=main, registry=registry)
    facade_url = "http://unused"

    upstreams.add_upstream(
        "facade",
        facade_url,
        namespace="facade",
        tool_filter=build_prefix_tool_filter(
            exclude_prefixes=("ledger_", "reports_"),
        ),
    )
    upstreams.add_upstream(
        "facade-ledger",
        facade_url,
        namespace="ledger",
        tool_filter=build_prefix_tool_filter(include_prefixes=("ledger_",)),
        strip_prefix="ledger_",
    )
    upstreams.add_upstream(
        "facade-reports",
        facade_url,
        namespace="reports",
        tool_filter=build_prefix_tool_filter(include_prefixes=("reports_",)),
        strip_prefix="reports_",
    )

    async def patched_discover(cfg):
        sub = upstreams._sub_servers[cfg.namespace]
        adapter = upstreams._adapters[cfg.namespace]
        tools = [
            SimpleNamespace(name=name, description="", input_schema={}) for name in FACADE_TOOLS
        ]
        registered = 0
        for tool in tools:
            tool_name = tool.name
            if cfg.tool_filter is not None and not cfg.tool_filter(tool_name):
                continue
            route_name = resolve_mounted_tool_name(tool_name, cfg.strip_prefix)
            registry.add_route(
                route_name,
                adapter,
                description="",
                mode="live",
                upstream_tool=tool_name,
                namespace=cfg.namespace,
                config_mode="PROXY",
                tags={cfg.namespace},
                meta={"upstream": cfg.name},
                mcp=sub,
            )
            registered += 1
        return registered

    upstreams._discover_one = patched_discover  # type: ignore[method-assign]
    counts = await upstreams.discover_all()
    assert counts == {
        "facade": 2,
        "ledger": 2,
        "reports": 2,
    }

    async with Client(main) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert names == {
        "facade_submit_batch",
        "facade_list_projects",
        "ledger_read",
        "ledger_put_rates",
        "reports_apply",
        "reports_read",
    }

    ledger_route = registry.routes["ledger:read"]
    assert ledger_route.upstream_tool == "ledger_read"
    assert ledger_route.published_name == "ledger_read"


def test_build_server_registers_prefix_filtered_upstreams(monkeypatch) -> None:
    payload = [
        {
            "name": "facade-ledger",
            "url": "http://facade-mcp-http:8098/mcp",
            "namespace": "ledger",
            "enabled": True,
            "tool_prefix": "ledger_",
        }
    ]
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS", json.dumps(payload))
    _mcp, _registry, _oauth, upstreams, _policy_manager, _observability, _reconciler = build_server(
        settings=Settings(),
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    cfg = upstreams._upstreams[0]
    assert cfg.namespace == "ledger"
    assert cfg.strip_prefix == "ledger_"
    assert cfg.tool_filter is not None
    assert cfg.tool_filter("ledger_read") is True
    assert cfg.tool_filter("reports_read") is False


RULEBOOK_FACADE_TOOLS = [
    "submit_batch",
    "rulebook_read",
    "rulebook_document_read",
    "rulebook_run_report_read",
    "present_rulebook_release",
    "confirm_rulebook_release",
]

ORCHESTRATOR_RULEBOOK_UPSTREAMS = [
    {
        "name": "facade",
        "url": "http://facade-mcp:8098/mcp",
        "namespace": "facade",
        "enabled": True,
        "exclude_prefixes": [
            "ledger_",
            "reports_",
            "rulebook_",
            "present_rulebook_release",
            "confirm_rulebook_release",
        ],
    },
    {
        "name": "facade-ruling-set",
        "url": "http://facade-mcp:8098/mcp",
        "namespace": "rulebook",
        "enabled": True,
        "include_prefixes": [
            "rulebook_",
            "present_rulebook_release",
            "confirm_rulebook_release",
        ],
        "strip_prefix": "rulebook_",
    },
]


def test_settings_upstreams_parse_rulebook_present_confirm_mount(monkeypatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS", json.dumps(ORCHESTRATOR_RULEBOOK_UPSTREAMS))
    settings = load_settings()
    assert len(settings.upstreams) == 2

    doc_cfg, ruling_cfg = settings.upstreams
    assert "present_rulebook_release" in doc_cfg.exclude_prefixes
    assert "confirm_rulebook_release" in doc_cfg.exclude_prefixes
    assert ruling_cfg.include_prefixes == (
        "rulebook_",
        "present_rulebook_release",
        "confirm_rulebook_release",
    )
    assert ruling_cfg.strip_prefix == "rulebook_"


async def test_discover_routes_present_confirm_to_rulebook_namespace() -> None:
    main = FastMCP("keystone-main")
    engine = RouterEngine(Settings(base_url="http://localhost:8080"))
    registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(main_mcp=main, registry=registry)
    facade_url = "http://unused"

    upstreams.add_upstream(
        "facade",
        facade_url,
        namespace="facade",
        tool_filter=build_prefix_tool_filter(
            exclude_prefixes=(
                "rulebook_",
                "present_rulebook_release",
                "confirm_rulebook_release",
            ),
        ),
    )
    upstreams.add_upstream(
        "facade-rulebook",
        facade_url,
        namespace="rulebook",
        tool_filter=build_prefix_tool_filter(
            include_prefixes=(
                "rulebook_",
                "present_rulebook_release",
                "confirm_rulebook_release",
            ),
        ),
        strip_prefix="rulebook_",
    )

    async def patched_discover(cfg):
        sub = upstreams._sub_servers[cfg.namespace]
        adapter = upstreams._adapters[cfg.namespace]
        tools = [
            SimpleNamespace(name=name, description="", input_schema={})
            for name in RULEBOOK_FACADE_TOOLS
        ]
        registered = 0
        for tool in tools:
            tool_name = tool.name
            if cfg.tool_filter is not None and not cfg.tool_filter(tool_name):
                continue
            route_name = resolve_mounted_tool_name(tool_name, cfg.strip_prefix)
            registry.add_route(
                route_name,
                adapter,
                description="",
                mode="live",
                upstream_tool=tool_name,
                namespace=cfg.namespace,
                config_mode="PROXY",
                tags={cfg.namespace},
                meta={"upstream": cfg.name},
                mcp=sub,
            )
            registered += 1
        return registered

    upstreams._discover_one = patched_discover  # type: ignore[method-assign]
    counts = await upstreams.discover_all()
    assert counts == {"facade": 1, "rulebook": 5}

    async with Client(main) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert names == {
        "facade_submit_batch",
        "rulebook_read",
        "rulebook_document_read",
        "rulebook_run_report_read",
        "rulebook_present_rulebook_release",
        "rulebook_confirm_rulebook_release",
    }

    present_route = registry.routes["rulebook:present_rulebook_release"]
    assert present_route.upstream_tool == "present_rulebook_release"
    assert present_route.published_name == "rulebook_present_rulebook_release"

    confirm_route = registry.routes["rulebook:confirm_rulebook_release"]
    assert confirm_route.upstream_tool == "confirm_rulebook_release"
    assert confirm_route.published_name == "rulebook_confirm_rulebook_release"

    assert "facade:present_rulebook_release" not in registry.routes
    assert "facade:confirm_rulebook_release" not in registry.routes
