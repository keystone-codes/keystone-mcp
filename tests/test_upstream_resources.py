"""Upstream resource discovery, proxying and RBAC (Y12)."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from unittest.mock import AsyncMock

import jwt
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.utilities.tests import asgi_server
from mcp.client.subscriptions import listen as listen_subscriptions
from mcp.shared.exceptions import MCPError

import keystone_mcp.surface.reconciler as reconciler_module
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.rbac_middleware import RbacMiddleware
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamListToolsError, UpstreamRegistry
from keystone_mcp.router.upstream_content import published_uri_for_namespace
from keystone_mcp.surface.client_sessions import ClientSessionRegistry, SessionTrackingMiddleware
from keystone_mcp.surface.reconciler import SurfaceReconciler
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)
from support.test_env import require_redis_url

ANN = VerifiedIdentity(email="ann@example.com")
_IDENTITY_SECRET = "s3cr3t-identity-" + "v" * 20
_HANDBOOK_PUBLISHED = published_uri_for_namespace("hello", "file:///handbook.md")
_NOTE_TEMPLATE_PUBLISHED = published_uri_for_namespace("hello", "notes://items/{id}")


@pytest.fixture(autouse=True)
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity", lambda: ANN
    )


def _build_upstreams(app, *, observed: dict | None = None, monkeypatch=None, identity: bool = True):
    if monkeypatch is not None and identity:
        monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_HELLO_IDENTITY_SECRET", _IDENTITY_SECRET)
    settings = Settings(base_url="http://localhost:8080")
    main = FastMCP("keystone-test")
    registry = RouterRegistry(RouterEngine(settings), main)
    upstreams = UpstreamRegistry(
        main_mcp=main,
        registry=registry,
        http_client_factory=asgi_http_client_factory(app),
        identity_issuer=settings.base_url.rstrip("/"),
        rbac_mode=settings.rbac_mode,
    )
    upstream_kw: dict = {}
    if identity:
        upstream_kw["identity_secret_env"] = "KEYSTONE_MCP_UPSTREAM_HELLO_IDENTITY_SECRET"
    upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello", **upstream_kw)
    return main, registry, upstreams


def _outermost_uri_middleware(main: FastMCP, upstreams: UpstreamRegistry) -> None:
    from keystone_mcp.router.upstream_uri_middleware import UpstreamResourceUriMiddleware

    main.add_middleware(UpstreamResourceUriMiddleware(upstreams.content))


@pytest.mark.parametrize("client_mode", ["legacy", "modern"])
async def test_resource_published_with_namespaced_uri(monkeypatch, client_mode: str):
    app = build_lowlevel_upstream_app(tools=["greet"], resources=True)
    async with LifespanManager(app):
        main, _registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        await upstreams.discover_all()
        _outermost_uri_middleware(main, upstreams)

        settings = Settings(base_url="http://localhost:8080")
        if client_mode == "legacy":
            async with Client(main) as client:
                resources = await client.list_resources()
                uris = {str(r.uri) for r in resources}
                assert _HANDBOOK_PUBLISHED in uris
                blocks = await client.read_resource(_HANDBOOK_PUBLISHED)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    resources = await client.list_resources()
                    uris = {str(r.uri) for r in resources}
                    assert _HANDBOOK_PUBLISHED in uris
                    blocks = await client.read_resource(_HANDBOOK_PUBLISHED)
        assert blocks[0].text == "Handbook"


@pytest.mark.parametrize("client_mode", ["legacy", "modern"])
async def test_template_published_and_read(monkeypatch, client_mode: str):
    app = build_lowlevel_upstream_app(tools=["greet"], resources=True)
    async with LifespanManager(app):
        main, _registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        await upstreams.discover_all()
        _outermost_uri_middleware(main, upstreams)

        settings = Settings(base_url="http://localhost:8080")
        note_uri = _NOTE_TEMPLATE_PUBLISHED.replace("{id}", "7")
        if client_mode == "legacy":
            async with Client(main) as client:
                templates = await client.list_resource_templates()
                assert _NOTE_TEMPLATE_PUBLISHED in {t.uri_template for t in templates}
                blocks = await client.read_resource(note_uri)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    templates = await client.list_resource_templates()
                    assert _NOTE_TEMPLATE_PUBLISHED in {t.uri_template for t in templates}
                    blocks = await client.read_resource(note_uri)
        assert blocks[0].text == "Note 7"


@pytest.mark.parametrize("client_mode", ["legacy", "modern"])
async def test_rbac_by_resource_name(tmp_path: Path, monkeypatch, client_mode: str):
    policy_handbook = """\
version: "1.0.0"
default_deny: true
roles:
  member:
    allow: ["hello_handbook"]
"""
    policy_wildcard = policy_handbook.replace('["hello_handbook"]', '["hello_*"]')
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy_handbook, encoding="utf-8")

    app = build_lowlevel_upstream_app(tools=["greet"], resources=True)
    async with LifespanManager(app):
        main, registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        settings = Settings(
            base_url="http://localhost:8080",
            rbac_mode="enforce",
            rbac_policy_path=str(policy_path),
            users_service_url="http://users:8000",
            users_service_token="token",
            redis_url=require_redis_url(),
        )
        resolver, backend, _revision = build_in_memory_user_directory_resolver()
        backend.seed(ANN.email, roles=("member",))
        manager = RbacPolicyManager(
            settings,
            extra_catalog_names=lambda: upstreams.content.rbac_names(),
        )
        main.add_middleware(
            RbacMiddleware(
                manager,
                resolver,
                settings=settings,
                content_catalog=upstreams.content,
            )
        )
        _outermost_uri_middleware(main, upstreams)
        await upstreams.discover_all()
        manager.load_initial(registry)

        if client_mode == "legacy":
            async with Client(main) as client:
                await _assert_rbac_resource_visibility(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _assert_rbac_resource_visibility(client)

        policy_path.write_text(policy_wildcard, encoding="utf-8")
        manager.reload(registry)

        if client_mode == "legacy":
            async with Client(main) as client:
                templates = await client.list_resource_templates()
                assert len(templates) >= 1
                note_uri = _NOTE_TEMPLATE_PUBLISHED.replace("{id}", "7")
                blocks = await client.read_resource(note_uri)
                assert blocks[0].text == "Note 7"
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    templates = await client.list_resource_templates()
                    assert len(templates) >= 1
                    note_uri = _NOTE_TEMPLATE_PUBLISHED.replace("{id}", "7")
                    blocks = await client.read_resource(note_uri)
                    assert blocks[0].text == "Note 7"


async def _assert_rbac_resource_visibility(client: Client) -> None:
    resources = await client.list_resources()
    assert _HANDBOOK_PUBLISHED in {str(r.uri) for r in resources}
    templates = await client.list_resource_templates()
    assert _NOTE_TEMPLATE_PUBLISHED not in {t.uri_template for t in templates}
    note_uri = _NOTE_TEMPLATE_PUBLISHED.replace("{id}", "7")
    with pytest.raises(MCPError, match="access denied"):
        await client.read_resource(note_uri)


async def test_unknown_uri_is_denied(tmp_path: Path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """\
version: "1.0.0"
default_deny: true
roles:
  member:
    allow: ["hello_*"]
""",
        encoding="utf-8",
    )
    app = build_lowlevel_upstream_app(tools=["greet"], resources=True)
    async with LifespanManager(app):
        main, registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        settings = Settings(
            base_url="http://localhost:8080",
            rbac_mode="enforce",
            rbac_policy_path=str(policy_path),
            users_service_url="http://users:8000",
            users_service_token="token",
            redis_url=require_redis_url(),
        )
        resolver, backend, _revision = build_in_memory_user_directory_resolver()
        backend.seed(ANN.email, roles=("member",))
        manager = RbacPolicyManager(
            settings,
            extra_catalog_names=lambda: upstreams.content.rbac_names(),
        )
        main.add_middleware(
            RbacMiddleware(
                manager,
                resolver,
                settings=settings,
                content_catalog=upstreams.content,
            )
        )
        _outermost_uri_middleware(main, upstreams)
        await upstreams.discover_all()
        manager.load_initial(registry)

        async with Client(main) as client:
            with pytest.raises(MCPError, match="access denied"):
                await client.read_resource("notes://hello/other/7")


async def test_identity_on_resource_read(monkeypatch):
    observed: dict = {}
    app = build_lowlevel_upstream_app(tools=["greet"], resources=True, observed=observed)
    async with LifespanManager(app):
        main, _registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        await upstreams.discover_all()
        _outermost_uri_middleware(main, upstreams)

        async with Client(main) as client:
            await client.read_resource(_HANDBOOK_PUBLISHED)

        token = observed["resource_headers"].get("x-keystone-identity")
        assert token is not None
        decoded = jwt.decode(
            token,
            _IDENTITY_SECRET,
            algorithms=["HS256"],
            audience="hello-upstream",
            issuer="http://localhost:8080",
        )
        assert decoded["mcp_method"] == "resources/read"
        assert decoded["mcp_target"] == "file:///handbook.md"


async def test_resource_list_change_notifies_legacy(monkeypatch):
    app = build_lowlevel_upstream_app(tools=["greet"], resources=False)
    async with LifespanManager(app):
        main, registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        settings = Settings(base_url="http://localhost:8080", refresh_interval_seconds=3600)
        client_sessions = ClientSessionRegistry()
        main.add_middleware(SessionTrackingMiddleware(client_sessions))
        reconciler = SurfaceReconciler(
            settings=settings,
            registry=registry,
            upstreams=upstreams,
            policy_manager=None,
            observability=None,
            client_sessions=client_sessions,
        )
        await upstreams.discover_all()
        reconciler.seed_snapshots()

        received: list = []

        async def handler(message):
            received.append(message)

        async with Client(main, mode="legacy", message_handler=handler) as client:
            await client.list_tools()
            assert await client.list_resources() == []

            app2 = build_lowlevel_upstream_app(tools=["greet"], resources=True)
            async with LifespanManager(app2):
                real_resources = reconciler_module.fetch_upstream_resources
                real_templates = reconciler_module.fetch_upstream_resource_templates
                factory = asgi_http_client_factory(app2)

                async def fake_resources(url, **kwargs):
                    kwargs["httpx_client_factory"] = factory(kwargs.get("timeout_seconds", 5.0))
                    return await real_resources(url, **kwargs)

                async def fake_templates(url, **kwargs):
                    kwargs["httpx_client_factory"] = factory(kwargs.get("timeout_seconds", 5.0))
                    return await real_templates(url, **kwargs)

                reconciler_module.fetch_upstream_resources = fake_resources
                reconciler_module.fetch_upstream_resource_templates = fake_templates
                try:
                    await reconciler.tick()
                finally:
                    reconciler_module.fetch_upstream_resources = real_resources
                    reconciler_module.fetch_upstream_resource_templates = real_templates

            await asyncio.sleep(0)
            assert any(m.method == "notifications/resources/list_changed" for m in received)


async def test_resource_list_change_notifies_modern(monkeypatch):
    from conftest import BASE_URL, VALID_TOKEN
    from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
    from keystone_mcp.server import build_server
    from support.login import dev_token_login
    from test_list_changed import _modern_client

    app = build_lowlevel_upstream_app(tools=["greet"], resources=False)
    async with LifespanManager(app):
        settings = Settings(base_url=BASE_URL, refresh_interval_seconds=3600)
        mcp, registry, _oauth, upstreams, _pm, _obs, reconciler = build_server(
            login_providers=[dev_token_login({VALID_TOKEN})],
            settings=settings,
            oauth_store=InMemoryOAuthStore(),
            register_builtin_catalog=False,
        )
        upstreams.http_client_factory = asgi_http_client_factory(app)
        upstreams.add_upstream("hello", UPSTREAM_MCP_URL, namespace="hello")
        await upstreams.discover_all()
        assert reconciler is not None
        reconciler.seed_snapshots()

        async with _modern_client(mcp, settings) as client:
            await client.list_tools()
            async with listen_subscriptions(client.session, resources_list_changed=True) as sub:
                app2 = build_lowlevel_upstream_app(tools=["greet"], resources=True)
                async with LifespanManager(app2):
                    real_resources = reconciler_module.fetch_upstream_resources
                    real_templates = reconciler_module.fetch_upstream_resource_templates
                    factory = asgi_http_client_factory(app2)

                    async def fake_resources(url, **kwargs):
                        kwargs["httpx_client_factory"] = factory(kwargs.get("timeout_seconds", 5.0))
                        return await real_resources(url, **kwargs)

                    async def fake_templates(url, **kwargs):
                        kwargs["httpx_client_factory"] = factory(kwargs.get("timeout_seconds", 5.0))
                        return await real_templates(url, **kwargs)

                    reconciler_module.fetch_upstream_resources = fake_resources
                    reconciler_module.fetch_upstream_resource_templates = fake_templates
                    try:
                        await reconciler.tick()
                    finally:
                        reconciler_module.fetch_upstream_resources = real_resources
                        reconciler_module.fetch_upstream_resource_templates = real_templates

                event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)
                assert type(event).__name__ == "ResourcesListChanged"


async def test_namespace_uri_transform_matches_fastmcp(monkeypatch):
    app = build_lowlevel_upstream_app(tools=["greet"], resources=True)
    async with LifespanManager(app):
        main, _registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        await upstreams.discover_all()
        spec = upstreams.content.resources("hello")["file:///handbook.md"]
        async with Client(main) as client:
            listed = await client.list_resources()
        listed_uri = next(str(r.uri) for r in listed if r.name == "handbook")
        assert spec.published_uri == listed_uri


async def test_client_meta_identity_key_is_not_forwarded(monkeypatch):
    observed: dict = {}
    app = build_lowlevel_upstream_app(tools=["greet"], resources=True, observed=observed)
    async with LifespanManager(app):
        main, _registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        await upstreams.discover_all()
        _outermost_uri_middleware(main, upstreams)

        meta = {"keystone-mcp/identity": "forged"}
        async with Client(main) as client:
            await client.read_resource(_HANDBOOK_PUBLISHED, meta=meta)

        assert "keystone-mcp/identity" not in observed.get("resource_meta", {})


async def test_resources_failure_keeps_tools(monkeypatch, caplog: pytest.LogCaptureFixture):
    app = build_lowlevel_upstream_app(tools=["greet"], resources=True)
    async with LifespanManager(app):
        main, registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        await upstreams.discover_all()
        assert upstreams.unavailable_namespaces() == {}

        monkeypatch.setattr(
            "keystone_mcp.surface.reconciler.fetch_upstream_resources",
            AsyncMock(side_effect=UpstreamListToolsError("list_resources exploded")),
        )

        settings = Settings(base_url="http://localhost:8080", refresh_interval_seconds=60)
        reconciler = SurfaceReconciler(
            settings=settings,
            registry=registry,
            upstreams=upstreams,
            policy_manager=None,
            observability=None,
        )
        reconciler.seed_snapshots()

        with caplog.at_level(logging.WARNING, logger=reconciler_module.__name__):
            await reconciler.tick()

        assert upstreams.unavailable_namespaces() == {}
        assert any("upstream resources refresh failed" in r.message for r in caplog.records)
        async with Client(main) as client:
            tools = await client.list_tools()
            assert "hello_greet" in {t.name for t in tools}
