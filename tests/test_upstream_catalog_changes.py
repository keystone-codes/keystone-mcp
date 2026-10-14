"""Reconciler survives upstream catalog edits and listing failures (C01 acceptance)."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.utilities.tests import asgi_server
from mcp import types
from mcp.shared.exceptions import MCPError
from prometheus_client import REGISTRY

from keystone_mcp.config import Settings
from keystone_mcp.http.readiness import ReadinessProbe
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.rbac_middleware import RbacMiddleware
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from keystone_mcp.router.upstream_content import published_uri_for_namespace
from keystone_mcp.router.upstream_uri_middleware import UpstreamResourceUriMiddleware
from keystone_mcp.surface.client_sessions import ClientSessionRegistry, SessionTrackingMiddleware
from keystone_mcp.surface.reconciler import SurfaceReconciler
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from support.mutable_upstream import (
    UPSTREAM_MCP_URL,
    MutableUpstreamCatalog,
    asgi_http_client_factory,
    build_mutable_upstream_app,
)

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


def _build_stack(
    app,
    *,
    strip_prefix: str | None = None,
    extra_upstream: tuple[str, str] | None = None,
    monkeypatch=None,
    identity: bool = False,
):
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
    )
    kw: dict = {}
    if strip_prefix is not None:
        kw["strip_prefix"] = strip_prefix
    if identity:
        kw["identity_secret_env"] = "KEYSTONE_MCP_UPSTREAM_HELLO_IDENTITY_SECRET"
    upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello", **kw)
    if extra_upstream is not None:
        name, ns = extra_upstream
        upstreams.add_upstream(name, UPSTREAM_MCP_URL, namespace=ns)
    main.add_middleware(UpstreamResourceUriMiddleware(upstreams.content))
    return main, registry, upstreams, settings


def _reconciler(
    settings: Settings,
    registry: RouterRegistry,
    upstreams: UpstreamRegistry,
    *,
    client_sessions: ClientSessionRegistry | None = None,
) -> SurfaceReconciler:
    return SurfaceReconciler(
        settings=settings,
        registry=registry,
        upstreams=upstreams,
        policy_manager=None,
        observability=None,
        client_sessions=client_sessions,
    )


async def _client_ctx(main: FastMCP, settings: Settings, client_mode: str | None):
    if client_mode == "legacy":
        return Client(main)
    return asgi_server(main, path=settings.http_path)


@pytest.mark.parametrize("client_mode", ["legacy", None])
async def test_resource_removed_upstream_disappears_without_errors(client_mode: str | None):
    catalog = MutableUpstreamCatalog()
    app = build_mutable_upstream_app(catalog)
    async with LifespanManager(app):
        main, registry, upstreams, settings = _build_stack(app)
        client_sessions = ClientSessionRegistry()
        main.add_middleware(SessionTrackingMiddleware(client_sessions))
        rec = _reconciler(settings, registry, upstreams, client_sessions=client_sessions)
        await upstreams.discover_all()
        rec.seed_snapshots()

        received: list = []

        async def handler(message):
            received.append(message)

        if client_mode == "legacy":
            async with Client(main, mode="legacy", message_handler=handler) as client:
                await client.list_tools()
                catalog.resources = []
                catalog.templates = []
                await rec.tick()
                await rec.tick()
                assert await client.list_resources() == []
                assert await client.list_resource_templates() == []
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await client.list_tools()
                    catalog.resources = []
                    catalog.templates = []
                    await rec.tick()
                    await rec.tick()
                    assert await client.list_resources() == []
                    assert await client.list_resource_templates() == []

        assert upstreams.unavailable_namespaces() == {}
        if client_mode == "legacy":
            assert any(m.method == "notifications/resources/list_changed" for m in received)


@pytest.mark.parametrize("client_mode", ["legacy", None])
async def test_resource_description_change_is_applied(client_mode: str | None):
    catalog = MutableUpstreamCatalog()
    app = build_mutable_upstream_app(catalog)
    async with LifespanManager(app):
        main, registry, upstreams, settings = _build_stack(app)
        client_sessions = ClientSessionRegistry()
        main.add_middleware(SessionTrackingMiddleware(client_sessions))
        rec = _reconciler(settings, registry, upstreams, client_sessions=client_sessions)
        await upstreams.discover_all()
        rec.seed_snapshots()

        received: list = []

        async def handler(message):
            received.append(message)

        catalog.resources = [
            types.Resource(
                uri="file:///handbook.md",
                name="handbook",
                description="Updated handbook text",
                mime_type="text/plain",
            )
        ]
        catalog.templates = [
            types.ResourceTemplate(
                uri_template="notes://items/{id}",
                name="note",
                description="Updated note template",
                mime_type="text/plain",
            )
        ]
        if client_mode == "legacy":
            async with Client(main, mode="legacy", message_handler=handler) as client:
                await client.list_tools()
                await rec.tick()
                resources = await client.list_resources()
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await client.list_tools()
                    await rec.tick()
                    resources = await client.list_resources()

        assert upstreams.unavailable_namespaces() == {}
        assert len(resources) == 1
        assert resources[0].description == "Updated handbook text"
        if client_mode == "legacy":
            assert any(m.method == "notifications/resources/list_changed" for m in received)


@pytest.mark.parametrize("client_mode", ["legacy", None])
async def test_template_removed_is_gone_from_listing(client_mode: str | None, monkeypatch):
    catalog = MutableUpstreamCatalog()
    app = build_mutable_upstream_app(catalog)
    async with LifespanManager(app):
        main, registry, upstreams, settings = _build_stack(app)
        await upstreams.discover_all()
        rec = _reconciler(settings, registry, upstreams)
        rec.seed_snapshots()
        catalog.templates = []
        await rec.tick()
        await rec.tick()

        note_uri = _NOTE_TEMPLATE_PUBLISHED.replace("{id}", "7")
        if client_mode == "legacy":
            async with Client(main) as client:
                templates = await client.list_resource_templates()
                assert templates == []
                with pytest.raises(MCPError):
                    await client.read_resource(note_uri)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    templates = await client.list_resource_templates()
                    assert templates == []
                    with pytest.raises(MCPError):
                        await client.read_resource(note_uri)


async def test_prompt_with_strip_prefix_keeps_client_visible_name(tmp_path: Path, monkeypatch):
    observed: dict = {}
    catalog = MutableUpstreamCatalog()
    app = build_mutable_upstream_app(catalog, observed=observed)
    async with LifespanManager(app):
        main, registry, upstreams, settings = _build_stack(
            app, strip_prefix="sum", monkeypatch=monkeypatch, identity=True
        )
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(
            """\
version: "1.0.0"
default_deny: true
roles:
  member:
    allow: ["hello_summarize"]
""",
            encoding="utf-8",
        )
        settings = Settings(
            base_url="http://localhost:8080",
            rbac_mode="enforce",
            rbac_policy_path=str(policy_path),
            users_service_url="http://users:8000",
            users_service_token="token",
            redis_url="redis://localhost:6379/6",
        )
        resolver, backend, _ = build_in_memory_user_directory_resolver()
        backend.seed(ANN.email, roles=("member",))
        manager = RbacPolicyManager(
            settings,
            extra_catalog_names=lambda: (
                upstreams.content.rbac_names() | upstreams.content.legacy_rbac_names()
            ),
        )
        main.add_middleware(
            RbacMiddleware(manager, resolver, settings=settings, content_catalog=upstreams.content)
        )
        await upstreams.discover_all()
        manager.load_initial(registry)

        assert "hello_summarize" in upstreams.content.rbac_names()
        async with Client(main) as client:
            names = {p.name for p in await client.list_prompts()}
            assert "hello_summarize" in names
            await client.get_prompt("hello_summarize", {"topic": "x"})
        assert observed.get("prompt_headers") is not None


async def test_legacy_stripped_prompt_name_still_loads_policy(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
):
    catalog = MutableUpstreamCatalog()
    app = build_mutable_upstream_app(catalog)
    async with LifespanManager(app):
        main, registry, upstreams, settings = _build_stack(app, strip_prefix="sum")
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(
            """\
version: "1.0.0"
default_deny: true
roles:
  member:
    allow: ["hello_marize"]
""",
            encoding="utf-8",
        )
        settings = Settings(
            base_url="http://localhost:8080",
            rbac_mode="enforce",
            rbac_policy_path=str(policy_path),
            users_service_url="http://users:8000",
            users_service_token="token",
            redis_url="redis://localhost:6379/6",
        )
        resolver, backend, _ = build_in_memory_user_directory_resolver()
        backend.seed(ANN.email, roles=("member",))
        manager = RbacPolicyManager(
            settings,
            extra_catalog_names=lambda: (
                upstreams.content.rbac_names() | upstreams.content.legacy_rbac_names()
            ),
        )
        main.add_middleware(
            RbacMiddleware(manager, resolver, settings=settings, content_catalog=upstreams.content)
        )
        with caplog.at_level(logging.WARNING):
            await upstreams.discover_all()
            manager.load_initial(registry)
        async with Client(main) as client:
            with pytest.raises(MCPError, match="access denied"):
                await client.get_prompt("hello_summarize", {"topic": "t"})
        assert any("0.5.0 policy validation grants nothing" in r.message for r in caplog.records)


async def test_prompt_removed_with_strip_prefix_without_errors():
    catalog = MutableUpstreamCatalog()
    app = build_mutable_upstream_app(catalog)
    async with LifespanManager(app):
        main, registry, upstreams, settings = _build_stack(app, strip_prefix="sum")
        rec = _reconciler(settings, registry, upstreams)
        await upstreams.discover_all()
        rec.seed_snapshots()
        catalog.prompts = []
        await rec.tick()
        await rec.tick()
        async with Client(main) as client:
            assert await client.list_prompts() == []


async def test_prompts_listing_error_keeps_prompts_for_three_ticks():
    catalog = MutableUpstreamCatalog()
    app = build_mutable_upstream_app(catalog)
    async with LifespanManager(app):
        main, registry, upstreams, settings = _build_stack(app)
        client_sessions = ClientSessionRegistry()
        main.add_middleware(SessionTrackingMiddleware(client_sessions))
        rec = _reconciler(settings, registry, upstreams, client_sessions=client_sessions)
        await upstreams.discover_all()
        rec.seed_snapshots()
        catalog.fail_prompts_list = True
        for _ in range(3):
            await rec.tick()
        assert upstreams.unavailable_namespaces() == {}
        async with Client(main) as client:
            names = {p.name for p in await client.list_prompts()}
            assert "hello_summarize" in names
            assert "hello_greet" in {t.name for t in await client.list_tools()}


async def test_resources_listing_error_keeps_resources_for_three_ticks():
    catalog = MutableUpstreamCatalog()
    app = build_mutable_upstream_app(catalog)
    async with LifespanManager(app):
        main, registry, upstreams, settings = _build_stack(app)
        rec = _reconciler(settings, registry, upstreams)
        await upstreams.discover_all()
        rec.seed_snapshots()
        catalog.fail_resources_list = True
        for _ in range(3):
            await rec.tick()
        assert upstreams.unavailable_namespaces() == {}
        async with Client(main) as client:
            uris = {str(r.uri) for r in await client.list_resources()}
            assert _HANDBOOK_PUBLISHED in uris

        catalog.fail_resources_list = False
        catalog.fail_templates_list = True
        for _ in range(3):
            await rec.tick()
        async with Client(main) as client:
            templates = await client.list_resource_templates()
            assert _NOTE_TEMPLATE_PUBLISHED in {t.uri_template for t in templates}


async def test_tools_change_is_announced_even_if_resources_crash(monkeypatch, caplog):
    catalog = MutableUpstreamCatalog()
    app = build_mutable_upstream_app(catalog)
    async with LifespanManager(app):
        main, registry, upstreams, settings = _build_stack(app)
        client_sessions = ClientSessionRegistry()
        main.add_middleware(SessionTrackingMiddleware(client_sessions))
        rec = _reconciler(settings, registry, upstreams, client_sessions=client_sessions)
        await upstreams.discover_all()
        rec.seed_snapshots()

        received: list = []

        async def handler(message):
            received.append(message)

        def _boom(*_args, **_kwargs):
            raise RuntimeError("resources apply exploded")

        monkeypatch.setattr(upstreams, "_apply_resource_specs", _boom)
        catalog.tools = ["greet", "search"]
        with caplog.at_level(logging.ERROR):
            async with Client(main, mode="legacy", message_handler=handler) as client:
                await client.list_tools()
                await rec.tick()
        assert upstreams.unavailable_namespaces() == {}
        assert any(m.method == "notifications/tools/list_changed" for m in received)


async def test_require_all_readyz_stays_ok_after_resource_change():
    catalog = MutableUpstreamCatalog()
    app = build_mutable_upstream_app(catalog)
    async with LifespanManager(app):
        main, registry, upstreams, settings = _build_stack(app)
        rec = _reconciler(settings, registry, upstreams)
        await upstreams.discover_all()
        rec.seed_snapshots()
        catalog.resources = [
            types.Resource(
                uri="file:///handbook.md",
                name="handbook",
                description="Changed",
                mime_type="text/plain",
            )
        ]
        await rec.tick()
        probe = ReadinessProbe(
            redis=None,
            policy_manager=None,
            users_backend=None,
            upstreams=upstreams,
            require_all=True,
        )
        report = await probe.run()
        assert report.ready is True


def test_no_private_local_provider_access():
    root = Path(__file__).resolve().parents[1] / "src" / "keystone_mcp"
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        if "_local_provider" in path.read_text(encoding="utf-8"):
            offenders.append(str(path.relative_to(root.parent)))
    assert offenders == []


async def test_rejected_items_metric_counts_name_collision():
    from keystone_mcp.router.upstream import build_upstream_prompt_specs

    catalog = MutableUpstreamCatalog()
    app = build_mutable_upstream_app(catalog)
    async with LifespanManager(app):
        main, registry, upstreams, _settings = _build_stack(app)
        await upstreams.discover_all()
        cfg = upstreams._upstreams[0]
        upstreams.content._prompt_owners["hello_summarize"] = "hello:intruder"
        changed_prompt = types.Prompt(
            name="summarize",
            description="different description for fingerprint",
            arguments=[
                types.PromptArgument(name="topic", description="t", required=True),
            ],
        )
        specs = build_upstream_prompt_specs(cfg, [changed_prompt])
        raw = {"summarize": changed_prompt}
        before = REGISTRY.get_sample_value(
            "keystone_mcp_upstream_items_rejected_total",
            labels={"namespace": "hello", "kind": "prompt", "reason": "name_collision"},
        )
        upstreams._apply_prompt_specs(cfg, specs, raw)
        after = REGISTRY.get_sample_value(
            "keystone_mcp_upstream_items_rejected_total",
            labels={"namespace": "hello", "kind": "prompt", "reason": "name_collision"},
        )
        assert (after or 0) > (before or 0)
