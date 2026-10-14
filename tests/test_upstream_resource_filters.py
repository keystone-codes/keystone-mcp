"""Upstream resource publish filters and RBAC name collision."""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.utilities.tests import asgi_server
from mcp import types
from prometheus_client import REGISTRY

from keystone_mcp.config import Settings, load_settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import (
    UpstreamCatalogRead,
    UpstreamRegistry,
    build_prefix_tool_filter,
)
from keystone_mcp.router.upstream_content import published_uri_for_namespace
from keystone_mcp.router.upstream_uri_middleware import UpstreamResourceUriMiddleware
from keystone_mcp.surface.reconciler import SurfaceReconciler
from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy
from keystone_mcp.upstream_registry.validate import validate_upstream_registry
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)
from support.resource_upstreams import build_resource_upstream_app

ANN = VerifiedIdentity(email="ann@example.com")


@pytest.fixture(autouse=True)
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity", lambda: ANN
    )


def _metric_collision(namespace: str, kind: str) -> float:
    return (
        REGISTRY.get_sample_value(
            "keystone_mcp_upstream_items_rejected_total",
            labels={"namespace": namespace, "kind": kind, "reason": "rbac_name_collision"},
        )
        or 0.0
    )


async def _build_stack(router_app, url: str = UPSTREAM_MCP_URL, **upstream_kw):
    main = FastMCP("keystone-resource-filter-test")
    registry = RouterRegistry(RouterEngine(Settings(base_url="http://localhost:8080")), main)
    factory = asgi_http_client_factory(router_app)
    upstreams = UpstreamRegistry(
        main_mcp=main,
        registry=registry,
        http_client_factory=factory,
        identity_issuer="http://localhost:8080",
    )
    upstreams.add_upstream("hello-upstream", url, namespace="hello", **upstream_kw)
    await upstreams.discover_all()
    main.add_middleware(UpstreamResourceUriMiddleware(upstreams.content))
    settings = Settings(base_url="http://localhost:8080")
    return main, settings, upstreams, registry


@pytest.mark.parametrize("client_mode", ["legacy", "modern"])
async def test_resources_published_by_default_as_before(client_mode: str):
    app = build_lowlevel_upstream_app(tools=["greet"], resources=True)
    async with LifespanManager(app):
        main, settings, _upstreams, _registry = await _build_stack(app, url=UPSTREAM_MCP_URL)
        handbook = published_uri_for_namespace("hello", "file:///handbook.md")
        note_tpl = published_uri_for_namespace("hello", "notes://items/{id}")

        async def _assert(client: Client) -> None:
            uris = {str(r.uri) for r in await client.list_resources()}
            templates = {t.uri_template for t in await client.list_resource_templates()}
            assert handbook in uris
            assert note_tpl in templates

        if client_mode == "legacy":
            async with Client(main) as client:
                await _assert(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _assert(client)


@pytest.mark.parametrize("client_mode", ["legacy", "modern"])
async def test_publish_resources_false_hides_all(client_mode: str):
    app = build_resource_upstream_app(
        resources=[
            types.Resource(
                uri="file:///handbook.md",
                name="handbook",
                description="h",
                mime_type="text/plain",
            )
        ],
        templates=[
            types.ResourceTemplate(
                uri_template="notes://items/{id}",
                name="note",
                description="n",
                mime_type="text/plain",
            )
        ],
    )
    async with LifespanManager(app):
        main, settings, _upstreams, _registry = await _build_stack(app, publish_resources=False)

        async def _assert(client: Client) -> None:
            assert await client.list_resources() == []
            assert await client.list_resource_templates() == []
            tools = {t.name for t in await client.list_tools()}
            assert "hello_greet" in tools

        if client_mode == "legacy":
            async with Client(main) as client:
                await _assert(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _assert(client)


@pytest.mark.parametrize("client_mode", ["legacy", "modern"])
async def test_resource_include_and_exclude_prefixes(client_mode: str):
    app = build_resource_upstream_app(
        resources=[
            types.Resource(
                uri="file:///handbook.md",
                name="handbook",
                description="h",
                mime_type="text/plain",
            ),
            types.Resource(
                uri="file:///secret.md",
                name="hand_private_x",
                description="x",
                mime_type="text/plain",
            ),
            types.Resource(
                uri="notes://1",
                name="notes",
                description="n",
                mime_type="text/plain",
            ),
        ],
        templates=[],
    )
    resource_filter = build_prefix_tool_filter(
        include_prefixes=("hand",),
        exclude_prefixes=("hand_private",),
    )
    async with LifespanManager(app):
        main, settings, _upstreams, _registry = await _build_stack(
            app, resource_filter=resource_filter
        )
        published_handbook = published_uri_for_namespace("hello", "file:///handbook.md")

        async def _assert(client: Client) -> None:
            uris = {str(r.uri) for r in await client.list_resources()}
            assert published_handbook in uris
            assert published_uri_for_namespace("hello", "file:///secret.md") not in uris
            assert published_uri_for_namespace("hello", "notes://1") not in uris

        if client_mode == "legacy":
            async with Client(main) as client:
                await _assert(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _assert(client)


async def test_tool_filter_without_resource_filter_warns_once(
    caplog: pytest.LogCaptureFixture,
):
    app = build_resource_upstream_app(
        resources=[
            types.Resource(
                uri="file:///handbook.md",
                name="handbook",
                description="h",
                mime_type="text/plain",
            )
        ],
    )
    tool_filter = build_prefix_tool_filter(include_prefixes=("greet",))
    async with LifespanManager(app):
        main, _settings, upstreams, registry = await _build_stack(app, tool_filter=tool_filter)
        settings = Settings(base_url="http://localhost:8080", refresh_interval_seconds=60)
        reconciler = SurfaceReconciler(
            settings=settings,
            registry=registry,
            upstreams=upstreams,
            policy_manager=None,
            observability=None,
        )
        reconciler.seed_snapshots()
        caplog.set_level(logging.WARNING)
        with caplog.at_level(logging.WARNING):
            await reconciler.tick()
            await reconciler.tick()
        matches = [
            r
            for r in caplog.records
            if "filters tools but publishes all" in r.getMessage()
            and r.name == "keystone_mcp.router.upstream"
        ]
        assert len(matches) == 1
        async with Client(main) as client:
            await client.list_tools()


def test_registry_validation_of_resource_fields(tmp_path: Path, monkeypatch):
    policy = UpstreamSecurityPolicy(allow_insecure_http=True, egress_allow_private=True)
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "notes",
                "url": "http://127.0.0.1/mcp",
                "namespace": "notes",
                "publish_resources": "maybe",
                "resource_include_prefixes": 5,
            }
        ],
    }
    messages = validate_upstream_registry(document, policy=policy)
    assert any("publish_resources must be a boolean" in m for m in messages)
    assert any("resource_include_prefixes must be a string or array" in m for m in messages)

    payload = [
        {
            "name": "notes",
            "url": "http://127.0.0.1/mcp",
            "namespace": "notes",
            "publish_resources": False,
            "resource_include_prefixes": ["hand"],
        }
    ]
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS", json.dumps(payload))
    settings = load_settings()
    assert settings.upstreams[0].publish_resources is False
    assert settings.upstreams[0].resource_include_prefixes == ("hand",)

    valid_path = tmp_path / "upstreams.yaml"
    valid_path.write_text(
        textwrap.dedent(
            """
            schema_version: 1
            entries:
              - name: notes
                url: http://127.0.0.1/mcp
                namespace: notes
                publish_resources: true
                resource_exclude_prefixes: [private_]
            """
        ),
        encoding="utf-8",
    )
    cli = subprocess.run(
        [
            sys.executable,
            "-m",
            "keystone_mcp.cli",
            "upstream",
            "validate",
            "--path",
            str(valid_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cli.returncode == 0


@pytest.mark.parametrize("client_mode", ["legacy", "modern"])
async def test_resource_named_like_tool_is_not_published(client_mode: str, monkeypatch):
    notes_tool = types.Tool(
        name="notes",
        description="notes tool",
        inputSchema={"type": "object", "properties": {}},
    )
    resource = types.Resource(
        uri="file:///same-name.md",
        name="notes",
        description="collides",
        mime_type="text/plain",
    )
    app = build_resource_upstream_app(tools=[notes_tool], resources=[resource])
    async with LifespanManager(app):
        before = _metric_collision("hello", "resource")
        main, settings, upstreams, registry = await _build_stack(app)
        assert _metric_collision("hello", "resource") > before

        async def _assert_missing(client: Client) -> None:
            assert await client.list_resources() == []
            tools = {t.name for t in await client.list_tools()}
            assert "hello_notes" in tools

        if client_mode == "legacy":
            async with Client(main) as client:
                await _assert_missing(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _assert_missing(client)

        async def _catalog_without_tool(_cfg, **kwargs):
            return UpstreamCatalogRead(
                tools=[],
                prompts=[],
                resources=[resource],
                templates=[],
            )

        monkeypatch.setattr(upstreams, "read_catalog", _catalog_without_tool)
        reconciler = SurfaceReconciler(
            settings=Settings(base_url="http://localhost:8080", refresh_interval_seconds=60),
            registry=registry,
            upstreams=upstreams,
            policy_manager=None,
            observability=None,
        )
        reconciler.seed_snapshots()
        await reconciler.tick()
        await reconciler.tick()
        published = published_uri_for_namespace("hello", "file:///same-name.md")

        if client_mode == "legacy":
            async with Client(main) as client:
                uris = {str(r.uri) for r in await client.list_resources()}
                assert published in uris
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    uris = {str(r.uri) for r in await client.list_resources()}
                    assert published in uris


@pytest.mark.parametrize("client_mode", ["legacy", "modern"])
async def test_resource_named_like_prompt_is_not_published(client_mode: str):
    app = build_resource_upstream_app(
        prompts=[
            types.Prompt(name="notes", description="prompt", arguments=[]),
        ],
        resources=[
            types.Resource(
                uri="file:///same-name.md",
                name="notes",
                description="collides",
                mime_type="text/plain",
            )
        ],
        tools=[],
    )
    async with LifespanManager(app):
        before = _metric_collision("hello", "resource")
        main, settings, _upstreams, _registry = await _build_stack(app)
        assert _metric_collision("hello", "resource") > before

        async def _assert(client: Client) -> None:
            assert await client.list_resources() == []
            prompts = {p.name for p in await client.list_prompts()}
            assert "hello_notes" in prompts

        if client_mode == "legacy":
            async with Client(main) as client:
                await _assert(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _assert(client)
