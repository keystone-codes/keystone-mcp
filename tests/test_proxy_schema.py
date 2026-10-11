"""Tests for deployment-supplied upstream inputSchema patches."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastmcp import Client, FastMCP

from keystone_mcp.config import ConfigError, Settings, validate_settings
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.proxy_schema import (
    PROXY_SCHEMA_PROPERTY_PATCHES,
    PatchTable,
    ProxySchemaPatchError,
    apply_proxy_schema_patches,
    load_proxy_schema_patches,
)
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.schema import schema_to_params
from keystone_mcp.router.upstream import UpstreamRegistry

NULLABLE_BOOL = {"anyOf": [{"type": "boolean"}, {"type": "null"}], "default": None}
NULLABLE_INT = {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": None}

PATCH_DOCUMENT = {
    "widgets": {
        "start_batch": {
            "run_checks": NULLABLE_BOOL,
            "max_items": NULLABLE_INT,
        }
    }
}


@pytest.fixture
def patch_file(tmp_path: Path) -> Path:
    path = tmp_path / "proxy-schema-patches.json"
    path.write_text(json.dumps(PATCH_DOCUMENT), encoding="utf-8")
    return path


def test_core_ships_no_patches() -> None:
    assert PROXY_SCHEMA_PROPERTY_PATCHES == {}


def test_no_patch_file_means_no_patches() -> None:
    assert load_proxy_schema_patches("") == {}
    assert load_proxy_schema_patches("   ") == {}


def test_patch_file_loads_into_namespace_tool_table(patch_file: Path) -> None:
    table = load_proxy_schema_patches(patch_file)
    assert set(table) == {("widgets", "start_batch")}
    assert table[("widgets", "start_batch")]["run_checks"] == NULLABLE_BOOL
    assert table[("widgets", "start_batch")]["max_items"] == NULLABLE_INT


def test_patched_properties_are_merged_into_the_upstream_schema(patch_file: Path) -> None:
    table = load_proxy_schema_patches(patch_file)
    patched = apply_proxy_schema_patches(
        "widgets",
        "start_batch",
        {
            "type": "object",
            "properties": {
                "widget_path": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None},
                "dry_run": {"anyOf": [{"type": "boolean"}, {"type": "null"}], "default": None},
            },
        },
        patches=table,
    )
    assert patched is not None
    props = patched["properties"]
    # Upstream properties survive, patched ones are added.
    assert set(props) == {"widget_path", "dry_run", "run_checks", "max_items"}

    by_name = {param.name: param for param in schema_to_params(patched)}
    assert by_name["run_checks"].type == bool | None
    assert by_name["max_items"].type == int | None


def test_patch_replaces_a_property_of_the_same_name(patch_file: Path) -> None:
    table = load_proxy_schema_patches(patch_file)
    patched = apply_proxy_schema_patches(
        "widgets",
        "start_batch",
        {"type": "object", "properties": {"max_items": {"type": "string"}}},
        patches=table,
    )
    assert patched is not None
    assert patched["properties"]["max_items"] == NULLABLE_INT


def test_patch_builds_a_schema_when_upstream_advertises_none(patch_file: Path) -> None:
    patched = apply_proxy_schema_patches(
        "widgets", "start_batch", None, patches=load_proxy_schema_patches(patch_file)
    )
    assert patched is not None
    assert patched["type"] == "object"
    assert set(patched["properties"]) == {"run_checks", "max_items"}


def test_unpatched_tool_and_namespace_are_untouched(patch_file: Path) -> None:
    table = load_proxy_schema_patches(patch_file)
    schema = {"type": "object", "properties": {"x": {"type": "string"}}}
    assert apply_proxy_schema_patches("widgets", "batch_status", schema, patches=table) is schema
    assert apply_proxy_schema_patches("gadgets", "start_batch", schema, patches=table) is schema


def test_apply_without_patches_is_a_noop() -> None:
    schema = {"type": "object", "properties": {"x": {"type": "string"}}}
    assert apply_proxy_schema_patches("widgets", "start_batch", schema) is schema


def test_patched_fragment_is_copied_per_call(patch_file: Path) -> None:
    """A caller mutating the merged schema must not corrupt the loaded table."""
    table = load_proxy_schema_patches(patch_file)
    patched = apply_proxy_schema_patches("widgets", "start_batch", None, patches=table)
    assert patched is not None
    patched["properties"]["run_checks"]["default"] = "mutated"
    assert table[("widgets", "start_batch")]["run_checks"]["default"] is None


# ── Malformed patch files are refused at startup ────────────────────────────
def test_missing_patch_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ProxySchemaPatchError, match="cannot be read"):
        load_proxy_schema_patches(tmp_path / "absent.json")


def test_invalid_json_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ProxySchemaPatchError, match="not valid JSON"):
        load_proxy_schema_patches(path)


@pytest.mark.parametrize(
    ("document", "match"),
    [
        ('["widgets"]', "keyed by namespace"),
        ('{"widgets": 3}', "object of tool names"),
        ('{"widgets": {"start_batch": 3}}', "object of property names"),
        ('{"widgets": {"start_batch": {"run_checks": true}}}', "JSON Schema fragment"),
    ],
)
def test_malformed_patch_structure_is_refused(tmp_path: Path, document: str, match: str) -> None:
    path = tmp_path / "bad-shape.json"
    path.write_text(document, encoding="utf-8")
    with pytest.raises(ProxySchemaPatchError, match=match):
        load_proxy_schema_patches(path)


def test_settings_refuse_a_patch_path_that_is_not_a_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_PROXY_SCHEMA_PATCHES", str(tmp_path / "absent.json"))
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_PROXY_SCHEMA_PATCHES"):
        validate_settings(Settings())


def test_settings_accept_an_existing_patch_file(monkeypatch, patch_file: Path) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_PROXY_SCHEMA_PATCHES", str(patch_file))
    settings = Settings()
    validate_settings(settings)
    assert settings.proxy_schema_patches_path == str(patch_file)


# ── Discovery applies the loaded table ──────────────────────────────────────
@pytest.fixture
def widgets_downstream():
    mcp = FastMCP("widgets-downstream")

    @mcp.tool(name="start_batch")
    def start_batch(
        widget_path: str | None = None,
        dry_run: bool | None = None,
    ) -> dict:
        return {"status": "ok", "widget_path": widget_path, "dry_run": dry_run}

    return mcp


async def test_discovery_registers_patched_params(widgets_downstream, patch_file: Path) -> None:
    main = FastMCP("keystone-main")
    engine = RouterEngine(Settings(base_url="http://localhost:8080"))
    registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(
        main_mcp=main,
        registry=registry,
        schema_patches=load_proxy_schema_patches(patch_file),
    )
    upstreams.add_upstream("widgets-mcp", "http://unused", namespace="widgets")

    async def in_process_discover(cfg):
        """Same body as _discover_one, but listing tools over an in-process client."""
        sub = upstreams._sub_servers[cfg.namespace]
        adapter = upstreams._adapters[cfg.namespace]
        async with Client(widgets_downstream) as client:
            tools = await client.list_tools()
        for tool in tools:
            input_schema = apply_proxy_schema_patches(
                cfg.namespace,
                tool.name,
                tool.inputSchema if isinstance(tool.inputSchema, dict) else None,
                patches=upstreams.schema_patches,
            )
            registry.add_route(
                tool.name,
                adapter,
                params=schema_to_params(input_schema),
                description=tool.description or "",
                mode="live",
                upstream_tool=tool.name,
                namespace=cfg.namespace,
                config_mode="PROXY",
                tags={cfg.namespace},
                mcp=sub,
            )
        return len(tools)

    upstreams._discover_one = in_process_discover  # type: ignore[method-assign]
    await upstreams.discover_all()

    route = registry.routes["widgets:start_batch"]
    assert {param.name for param in route.params} == {
        "widget_path",
        "dry_run",
        "run_checks",
        "max_items",
    }


async def test_patched_property_is_published_verbatim() -> None:
    """P07: a schema patch is not only used to build ``Param``s (``route.params``,
    asserted above) -- it must also show up in the client-visible ``inputSchema``,
    with every JSON Schema key the patch declares (not just a type)."""
    patch_table: PatchTable = {
        ("widgets", "start_batch"): {
            "priority": {
                "type": "string",
                "enum": ["low", "high"],
                "description": "priority level",
            }
        }
    }
    base_schema = {"type": "object", "properties": {"widget_path": {"type": "string"}}}
    patched = apply_proxy_schema_patches("widgets", "start_batch", base_schema, patches=patch_table)

    from keystone_mcp.adapters.stub import StubAdapter

    mcp = FastMCP("t")
    registry = RouterRegistry(RouterEngine(Settings(base_url="http://localhost:8080")), mcp)
    registry.add_route(
        "start_batch",
        StubAdapter(),
        mode="live",
        namespace="widgets",
        config_mode="PROXY",
        upstream_tool="start_batch",
        input_schema=patched,
        mcp=mcp,
    )

    async with Client(mcp) as client:
        tools = await client.list_tools()
    tool = next(t for t in tools if t.name == "start_batch")

    assert tool.inputSchema["properties"]["priority"] == {
        "type": "string",
        "enum": ["low", "high"],
        "description": "priority level",
    }
