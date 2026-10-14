"""RBAC list endpoints for prompts and resources (C03 / A6-10)."""

from __future__ import annotations

from pathlib import Path

import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.resources import TextResource
from fastmcp.utilities.tests import asgi_server

from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import PolicyLoadError, RbacPolicyManager
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.rbac_middleware import RbacMiddleware
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from keystone_mcp.router.upstream_uri_middleware import UpstreamResourceUriMiddleware
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)
from support.test_env import require_redis_url

ANN = VerifiedIdentity(email="ann@example.com")
BLOCKED = VerifiedIdentity(email="blocked@example.com")


def _orphan_resource() -> TextResource:
    return TextResource(
        name="orphan_local",
        uri="file:///orphan-local.md",
        description="Not tracked in upstream content catalog.",
        text="orphan",
    )


@pytest.fixture(autouse=True)
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity", lambda: ANN
    )


async def _enforce_stack(
    app,
    *,
    policy_path: Path,
    policy_yaml: str,
    rbac_mode: str = "enforce",
):
    policy_path.write_text(policy_yaml, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode=rbac_mode,
        rbac_policy_path=str(policy_path),
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url=require_redis_url(),
    )
    main = FastMCP("keystone-rbac-lists")
    registry = RouterRegistry(RouterEngine(settings), main)
    upstreams = UpstreamRegistry(
        main_mcp=main,
        registry=registry,
        http_client_factory=asgi_http_client_factory(app),
        identity_issuer=settings.base_url.rstrip("/"),
        rbac_mode=rbac_mode,
    )
    upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
    await upstreams.discover_all()
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed(ANN.email, roles=("member",))
    backend.seed(BLOCKED.email, roles=())
    manager = RbacPolicyManager(
        settings,
        extra_catalog_names=lambda: upstreams.content.rbac_names(),
    )
    middleware = RbacMiddleware(
        manager,
        resolver,
        settings=settings,
        content_catalog=upstreams.content,
    )
    main.add_middleware(middleware)
    main.add_middleware(UpstreamResourceUriMiddleware(upstreams.content))
    manager.load_initial(registry)
    return main, settings, upstreams, middleware


@pytest.mark.parametrize("client_mode", ["legacy", "modern"])
@pytest.mark.parametrize("list_method", ["prompts", "resources", "templates"])
async def test_enforce_list_denied_returns_empty(
    tmp_path: Path, client_mode: str, list_method: str, monkeypatch
):
    app = build_lowlevel_upstream_app(tools=["greet"], prompts=True, resources=True)
    policy = """\
version: "1.0.0"
default_deny: true
roles:
  member:
    allow: ["hello_*"]
"""
    async with LifespanManager(app):
        main, settings, _upstreams, _middleware = await _enforce_stack(
            app, policy_path=tmp_path / "policy.yaml", policy_yaml=policy
        )

        def _blocked() -> VerifiedIdentity:
            return BLOCKED

        monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", _blocked)
        monkeypatch.setattr(
            "keystone_mcp.router.rbac_middleware.resolve_verified_identity", _blocked
        )

        async def _assert_empty(client: Client) -> None:
            if list_method == "prompts":
                assert await client.list_prompts() == []
            elif list_method == "resources":
                assert await client.list_resources() == []
            else:
                assert await client.list_resource_templates() == []

        if client_mode == "legacy":
            async with Client(main) as client:
                await _assert_empty(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _assert_empty(client)


@pytest.mark.parametrize("client_mode", ["legacy", "modern"])
@pytest.mark.parametrize("list_method", ["prompts", "resources", "templates"])
async def test_enforce_list_without_policy_returns_empty(
    tmp_path: Path, client_mode: str, list_method: str
):
    app = build_lowlevel_upstream_app(tools=["greet"], prompts=True, resources=True)
    async with LifespanManager(app):
        main, settings, _upstreams, middleware = await _enforce_stack(
            app,
            policy_path=tmp_path / "policy.yaml",
            policy_yaml='version: "1.0.0"\ndefault_deny: true\nroles:\n  member:\n    allow: ["*"]\n',
        )

        class _FailingManager:
            active_policy = None

            @property
            def policy(self):
                raise PolicyLoadError("not loaded")

        middleware._policy_manager = _FailingManager()  # type: ignore[assignment]

        async def _assert_empty(client: Client) -> None:
            if list_method == "prompts":
                assert await client.list_prompts() == []
            elif list_method == "resources":
                assert await client.list_resources() == []
            else:
                assert await client.list_resource_templates() == []

        if client_mode == "legacy":
            async with Client(main) as client:
                await _assert_empty(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _assert_empty(client)


@pytest.mark.parametrize("client_mode", ["legacy", "modern"])
async def test_enforce_hides_resource_without_rbac_name(tmp_path: Path, client_mode: str):
    app = build_lowlevel_upstream_app(tools=["greet"], resources=True)
    policy = """\
version: "1.0.0"
default_deny: true
roles:
  member:
    allow: ["*"]
"""
    async with LifespanManager(app):
        main, settings, upstreams, _middleware = await _enforce_stack(
            app, policy_path=tmp_path / "policy.yaml", policy_yaml=policy
        )
        upstreams._sub_servers["hello"].add_resource(_orphan_resource())

        async def _assert_enforce(client: Client) -> None:
            uris = {str(r.uri) for r in await client.list_resources()}
            assert "file:///orphan-local.md" not in uris
            assert all("orphan-local" not in u for u in uris)

        if client_mode == "legacy":
            async with Client(main) as client:
                await _assert_enforce(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _assert_enforce(client)

        settings_observe = Settings(
            base_url="http://localhost:8080",
            rbac_mode="observe",
            rbac_policy_path=str(tmp_path / "policy.yaml"),
            users_service_url="http://users:8000",
            users_service_token="token",
            redis_url=require_redis_url(),
        )
        main2 = FastMCP("observe")
        registry2 = RouterRegistry(RouterEngine(settings_observe), main2)
        upstreams2 = UpstreamRegistry(
            main_mcp=main2,
            registry=registry2,
            http_client_factory=asgi_http_client_factory(app),
            rbac_mode="observe",
        )
        upstreams2.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams2.discover_all()
        resolver, backend, _ = build_in_memory_user_directory_resolver()
        backend.seed(ANN.email, roles=("member",))
        manager2 = RbacPolicyManager(
            settings_observe,
            extra_catalog_names=lambda: upstreams2.content.rbac_names(),
        )
        main2.add_middleware(
            RbacMiddleware(
                manager2,
                resolver,
                settings=settings_observe,
                content_catalog=upstreams2.content,
            )
        )
        main2.add_middleware(UpstreamResourceUriMiddleware(upstreams2.content))
        manager2.load_initial(registry2)
        upstreams2._sub_servers["hello"].add_resource(_orphan_resource())

        if client_mode == "legacy":
            async with Client(main2) as client:
                listed = await client.list_resources()
                assert any("orphan" in str(r.uri) or r.name == "orphan_local" for r in listed)
        else:
            async with asgi_server(main2, path=settings_observe.http_path) as running:
                async with running.client() as client:
                    listed = await client.list_resources()
                    assert any("orphan" in str(r.uri) or r.name == "orphan_local" for r in listed)
