"""RBAC middleware coverage over mounted sub-servers.

Proves root ``add_middleware(RbacMiddleware)`` intercepts ``on_list_tools`` and
``on_call_tool`` for namespace-mounted sub-server tools (FastMCP 3.4.4+).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.rbac_middleware import RbacMiddleware
from keystone_mcp.router.registry import Param, RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver

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
    allow: ["reports_purge_cache"]
  viewer:
    description: viewer
    allow:
      - reports_read
      - create_upload_url
"""


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "rbac-policy.yaml"
    path.write_text(MOUNTED_TEST_POLICY, encoding="utf-8")
    return path


@pytest.fixture
def downstream_server():
    mcp = FastMCP("reports-downstream")

    @mcp.tool()
    def read(item_id: str) -> dict:
        return {"status": "ok", "item_id": item_id}

    @mcp.tool()
    def purge_cache() -> dict:
        return {"status": "reset"}

    return mcp


@pytest.fixture
def subject_state():
    return {"email": "viewer@example.com"}


@pytest.fixture
def patch_verified_identity(monkeypatch, subject_state):
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: VerifiedIdentity(email=subject_state["email"]),
    )
    monkeypatch.setattr(
        "keystone_mcp.identity.resolve_verified_identity",
        lambda: VerifiedIdentity(email=subject_state["email"]),
    )


def _rbac_stack(
    policy_path: Path,
    subject_state: dict,
    *,
    roles: tuple[str, ...] = ("viewer",),
):
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url="redis://localhost:6379/0",
    )
    resolver, backend, revision = build_in_memory_user_directory_resolver()
    backend.seed(subject_state["email"], roles=roles)
    return settings, resolver, backend, revision


def _attach_rbac_middleware(
    main: FastMCP,
    *,
    settings: Settings,
    resolver,
) -> RbacPolicyManager:
    manager = RbacPolicyManager(settings)
    main.add_middleware(RbacMiddleware(manager, resolver))
    return manager


def build_decorator_mount_server(
    policy_path: Path,
    subject_state: dict,
    *,
    roles: tuple[str, ...] = ("viewer",),
):
    settings, resolver, backend, revision = _rbac_stack(policy_path, subject_state, roles=roles)
    main = FastMCP("keystone-rbac")
    engine = RouterEngine(settings)
    registry = RouterRegistry(engine, main)

    sub = FastMCP("reports")
    main.mount(sub, namespace="reports")

    registry.add_route("create_upload_url", StubAdapter(), mode="live")
    registry.add_route(
        "read",
        StubAdapter(),
        params=[Param("item_id", str)],
        mode="live",
        namespace="reports",
        mcp=sub,
    )
    registry.add_route(
        "purge_cache",
        StubAdapter(),
        mode="live",
        namespace="reports",
        mcp=sub,
    )
    manager = _attach_rbac_middleware(main, settings=settings, resolver=resolver)
    manager.load_initial(registry)
    return main, backend, revision


def build_production_path_server(policy_path: Path, subject_state: dict):
    settings, resolver, backend, revision = _rbac_stack(policy_path, subject_state)
    main = FastMCP("keystone-rbac")
    engine = RouterEngine(settings)
    registry = RouterRegistry(engine, main)
    upstreams = UpstreamRegistry(main_mcp=main, registry=registry)

    registry.add_route("create_upload_url", StubAdapter(), mode="live")
    manager = _attach_rbac_middleware(main, settings=settings, resolver=resolver)
    return main, registry, upstreams, backend, manager


async def _register_production_path_tools(upstreams, downstream_server):
    async def patched_discover(cfg):
        sub = upstreams._sub_servers[cfg.namespace]
        async with Client(downstream_server) as client:
            tools = await client.list_tools()
        for tool in tools:
            from keystone_mcp.router.schema import schema_to_params

            upstreams.registry.add_route(
                tool.name,
                StubAdapter(),
                params=schema_to_params(tool.inputSchema),
                description=tool.description or "",
                mode="live",
                upstream_tool=tool.name,
                namespace=cfg.namespace,
                config_mode="PROXY",
                tags={cfg.namespace},
                meta={"upstream": cfg.name, "namespace": cfg.namespace},
                mcp=sub,
            )
        return len(tools)

    upstreams._discover_one = patched_discover  # type: ignore[method-assign]
    upstreams.add_upstream("reports-mcp", "http://unused", namespace="reports")
    return await upstreams.discover_all()


async def test_production_path_add_route_middleware_enforces_allow_deny(
    downstream_server,
    subject_state,
    patch_verified_identity,
    policy_path,
):
    main, registry, upstreams, _backend, manager = build_production_path_server(
        policy_path, subject_state
    )
    counts = await _register_production_path_tools(upstreams, downstream_server)
    manager.load_initial(registry)
    assert counts["reports"] == 2
    assert "reports:read" in registry.routes

    allowed = {"create_upload_url", "reports_read"}
    async with Client(main) as client:
        tools = await client.list_tools()
        names = {t.name for t in tools}
        assert names == allowed

        result = await client.call_tool(
            "reports_read",
            {"item_id": "402"},
        )
        assert result.data["state"] == "done"
        assert result.data["stub"] is True

        with pytest.raises(ToolError, match="access denied"):
            await client.call_tool("reports_purge_cache", {})


async def test_mounted_forbidden_tool_call_rejected(
    subject_state,
    patch_verified_identity,
    policy_path,
):
    main, _backend, _revision = build_decorator_mount_server(policy_path, subject_state)
    allowed = {"create_upload_url", "reports_read"}

    async with Client(main) as client:
        tools = await client.list_tools()
        names = {t.name for t in tools}
        assert names == allowed

        result = await client.call_tool(
            "reports_read",
            {"item_id": "402"},
        )
        assert result.data["state"] == "done"

        with pytest.raises(ToolError, match="access denied"):
            await client.call_tool("reports_purge_cache", {})


async def test_root_and_mounted_tools_share_middleware(
    subject_state,
    patch_verified_identity,
    policy_path,
):
    main, _backend, _revision = build_decorator_mount_server(
        policy_path,
        subject_state,
        roles=("reviewer",),
    )

    async with Client(main) as client:
        with pytest.raises(ToolError, match="access denied"):
            await client.call_tool("create_upload_url", {"purpose": "x"})
        with pytest.raises(ToolError, match="access denied"):
            await client.call_tool(
                "reports_read",
                {"item_id": "402"},
            )


async def test_block_after_discovery_denies_mounted_call(
    subject_state,
    patch_verified_identity,
    policy_path,
):
    main, backend, revision = build_decorator_mount_server(policy_path, subject_state)

    async with Client(main) as client:
        tools = await client.list_tools()
        assert "reports_read" in {t.name for t in tools}

        backend.block(subject_state["email"])
        revision.bump()

        with pytest.raises(ToolError, match="access denied"):
            await client.call_tool(
                "reports_read",
                {"item_id": "402"},
            )


async def test_reconnect_and_relist_do_not_bypass_call_gate(
    subject_state,
    patch_verified_identity,
    policy_path,
):
    main, backend, revision = build_decorator_mount_server(policy_path, subject_state)

    async with Client(main) as client:
        await client.list_tools()

    backend.block(subject_state["email"])
    revision.bump()

    async with Client(main) as reconnect_client:
        tools = await reconnect_client.list_tools()
        assert tools == []

        with pytest.raises(ToolError, match="access denied"):
            await reconnect_client.call_tool(
                "reports_read",
                {"item_id": "402"},
            )

        with pytest.raises(ToolError, match="access denied"):
            await reconnect_client.call_tool("reports_purge_cache", {})

        await reconnect_client.list_tools()
        with pytest.raises(ToolError, match="access denied"):
            await reconnect_client.call_tool(
                "reports_read",
                {"item_id": "402"},
            )


async def test_list_filter_and_call_gate_stay_consistent(
    subject_state,
    patch_verified_identity,
    policy_path,
):
    main, _backend, _revision = build_decorator_mount_server(policy_path, subject_state)

    async with Client(main) as client:
        visible = {t.name for t in await client.list_tools()}
        assert "reports_purge_cache" not in visible

        with pytest.raises(ToolError, match="access denied"):
            await client.call_tool("reports_purge_cache", {})


async def test_negative_control_without_middleware_call_succeeds():
    main = FastMCP("keystone-no-mw")
    sub = FastMCP("reports")

    @sub.tool()
    def purge_cache() -> dict:
        return {"status": "reset"}

    main.mount(sub, namespace="reports")

    async with Client(main) as client:
        tools = await client.list_tools()
        assert "reports_purge_cache" in {t.name for t in tools}
        result = await client.call_tool("reports_purge_cache", {})
        assert result.data["status"] == "reset"
