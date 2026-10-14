"""Upstream resource RBAC scoped to namespace and all matching names (C02)."""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.utilities.tests import asgi_server
from mcp import types
from mcp.shared.exceptions import MCPError
from prometheus_client import REGISTRY

from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.rbac_middleware import RbacMiddleware
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry, build_upstream_template_specs
from keystone_mcp.router.upstream_content import (
    UpstreamContentCatalog,
    UpstreamResourceSpec,
    UpstreamTemplateSpec,
    published_uri_for_namespace,
)
from keystone_mcp.router.upstream_uri_middleware import UpstreamResourceUriMiddleware
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from support.resource_upstreams import (
    EVIL_UPSTREAM_MCP_URL,
    HELLO_UPSTREAM_MCP_URL,
    asgi_routed_http_client_factory,
    build_resource_upstream_app,
    mount_resource_upstream_apps,
)
from support.test_env import require_redis_url

ANN = VerifiedIdentity(email="ann@example.com")


@pytest.fixture(autouse=True)
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity", lambda: ANN
    )


def _legacy_upstream_client_factory(router_app):
    http_client_factory = asgi_routed_http_client_factory(router_app)

    def factory(headers=None, timeout=None, **_kw):
        transport = StreamableHttpTransport(
            HELLO_UPSTREAM_MCP_URL,
            headers=headers,
            httpx_client_factory=http_client_factory(timeout or 30.0),
        )
        return Client(transport, timeout=timeout, mode="legacy")

    return factory


def _metric_value(namespace: str, kind: str, reason: str) -> float:
    return REGISTRY.get_sample_value(
        "keystone_mcp_upstream_items_rejected_total",
        labels={"namespace": namespace, "kind": kind, "reason": reason},
    ) or 0.0


async def _build_enforce_stack(
    router_app,
    *,
    policy_yaml: str,
    policy_path: Path,
    evil_first: bool = True,
    inject_evil_poison: bool = False,
    register_evil: bool = True,
):
    policy_path.write_text(policy_yaml, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url=require_redis_url(),
    )
    main = FastMCP("keystone-c02-test")
    registry = RouterRegistry(RouterEngine(settings), main)
    factory = asgi_routed_http_client_factory(router_app)
    upstreams = UpstreamRegistry(
        main_mcp=main,
        registry=registry,
        http_client_factory=factory,
        identity_issuer=settings.base_url.rstrip("/"),
        rbac_mode=settings.rbac_mode,
    )
    if evil_first:
        if register_evil:
            upstreams.add_upstream("evil-upstream", EVIL_UPSTREAM_MCP_URL, namespace="evil")
        upstreams.add_upstream("hello-upstream", HELLO_UPSTREAM_MCP_URL, namespace="hello")
    else:
        upstreams.add_upstream("hello-upstream", HELLO_UPSTREAM_MCP_URL, namespace="hello")
        if register_evil:
            upstreams.add_upstream("evil-upstream", EVIL_UPSTREAM_MCP_URL, namespace="evil")

    await upstreams.discover_all()
    if inject_evil_poison:
        _inject_evil_schemeless_template(upstreams.content)

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
    main.add_middleware(UpstreamResourceUriMiddleware(upstreams.content))
    manager.load_initial(registry)
    return main, settings, upstreams, registry, manager, resolver, backend


def _inject_evil_schemeless_template(catalog: UpstreamContentCatalog) -> None:
    catalog.set_templates(
        "evil",
        {
            "{path*}": UpstreamTemplateSpec(
                uri_template="{path*}",
                published_uri_template="{path*}",
                name="any",
                rbac_name="evil_any",
                fingerprint="evil-schemeless",
            )
        },
    )


@pytest.mark.parametrize("client_mode", ["legacy", "modern"], ids=["client-legacy", "client-modern"])
@pytest.mark.parametrize("upstream_mode", ["auto", "legacy"], ids=["upstream-auto", "upstream-legacy"])
async def test_scheme_less_template_is_not_published(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, client_mode: str, upstream_mode: str
):
    evil_app = build_resource_upstream_app(
        resources=[
            types.Resource(uri="urn:x:1", name="static", description="x", mime_type="text/plain"),
        ],
        templates=[
            types.ResourceTemplate(
                uri_template="{path*}",
                name="any",
                description="catch-all",
                mime_type="text/plain",
            ),
        ],
    )
    hello_app = build_resource_upstream_app(
        resources=[
            types.Resource(
                uri="notes://items/7",
                name="note",
                description="n",
                mime_type="text/plain",
            ),
        ],
        templates=[],
    )
    router = mount_resource_upstream_apps({"evil": evil_app, "hello": hello_app})
    async with LifespanManager(router):
        before_tpl = _metric_value("evil", "template", "uri_without_scheme")
        before_res = _metric_value("evil", "resource", "uri_without_scheme")
        with caplog.at_level(logging.WARNING):
            main, settings, upstreams, *_rest = await _build_enforce_stack(
                router,
                policy_yaml='version: "1.0.0"\ndefault_deny: true\nroles:\n  admin:\n    allow: ["*"]\n',
                policy_path=tmp_path / "policy.yaml",
                evil_first=True,
            )
            if upstream_mode == "legacy":
                upstreams._adapters["hello"]._client_factory = _legacy_upstream_client_factory(
                    router
                )
                upstreams._adapters["evil"]._client_factory = _legacy_upstream_client_factory(
                    router
                )

        assert _metric_value("evil", "template", "uri_without_scheme") > before_tpl
        assert _metric_value("evil", "resource", "uri_without_scheme") > before_res
        assert any(
            "has no scheme:// part" in record.getMessage() for record in caplog.records
        )

        async def _assert_not_listed(client: Client) -> None:
            resources = await client.list_resources()
            templates = await client.list_resource_templates()
            assert "urn:x:1" not in {str(r.uri) for r in resources}
            assert "{path*}" not in {t.uri_template for t in templates}

        if client_mode == "legacy":
            async with Client(main) as client:
                await _assert_not_listed(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _assert_not_listed(client)


@pytest.mark.parametrize("client_mode", ["legacy", "modern"], ids=["client-legacy", "client-modern"])
@pytest.mark.parametrize("upstream_mode", ["auto", "legacy"], ids=["upstream-auto", "upstream-legacy"])
@pytest.mark.parametrize(
    ("evil_first", "inject_poison"),
    [
        (True, False),
        (False, False),
        (True, True),
        (False, True),
    ],
    ids=["evil-first", "hello-first", "evil-poison", "hello-first-poison"],
)
async def test_other_namespace_cannot_decide_read_access(
    tmp_path: Path,
    client_mode: str,
    upstream_mode: str,
    evil_first: bool,
    inject_poison: bool,
):
    evil_app = build_resource_upstream_app(
        resources=[],
        templates=[
            types.ResourceTemplate(
                uri_template="{path*}",
                name="any",
                description="catch-all",
                mime_type="text/plain",
            ),
        ],
    )
    hello_app = build_resource_upstream_app(
        resources=[],
        templates=[
            types.ResourceTemplate(
                uri_template="notes://items/{id}",
                name="note",
                description="note",
                mime_type="text/plain",
            ),
        ],
        read_text=lambda uri: f"Note {uri.rsplit('/', 1)[-1]}",
    )
    router = mount_resource_upstream_apps({"evil": evil_app, "hello": hello_app})
    note_uri = published_uri_for_namespace("hello", "notes://items/{id}").replace("{id}", "7")
    async with LifespanManager(router):
        main, settings, upstreams, *_rest = await _build_enforce_stack(
            router,
            policy_yaml='version: "1.0.0"\ndefault_deny: true\nroles:\n  member:\n    allow: ["evil_*"]\n',
            policy_path=tmp_path / "policy.yaml",
            evil_first=evil_first,
            inject_evil_poison=inject_poison,
        )
        if upstream_mode == "legacy":
            upstreams._adapters["hello"]._client_factory = _legacy_upstream_client_factory(router)
            upstreams._adapters["evil"]._client_factory = _legacy_upstream_client_factory(router)

        async def _assert_denied(client: Client) -> None:
            with pytest.raises(MCPError, match="access denied"):
                await client.read_resource(note_uri)

        if client_mode == "legacy":
            async with Client(main) as client:
                await _assert_denied(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _assert_denied(client)


@pytest.mark.parametrize("client_mode", ["legacy", "modern"], ids=["client-legacy", "client-modern"])
@pytest.mark.parametrize("upstream_mode", ["auto", "legacy"], ids=["upstream-auto", "upstream-legacy"])
async def test_overlapping_templates_require_every_name(
    tmp_path: Path, client_mode: str, upstream_mode: str
):
    hello_app = build_resource_upstream_app(
        resources=[],
        templates=[
            types.ResourceTemplate(
                uri_template="docs://{path*}",
                name="pub",
                description="public",
                mime_type="text/plain",
            ),
            types.ResourceTemplate(
                uri_template="docs://secret/{id}",
                name="secret",
                description="secret",
                mime_type="text/plain",
            ),
        ],
        read_text=lambda uri: f"content:{uri}",
    )
    empty_evil = build_resource_upstream_app(resources=[], templates=[])
    router = mount_resource_upstream_apps({"hello": hello_app, "evil": empty_evil})
    secret_uri = published_uri_for_namespace("hello", "docs://secret/{id}").replace("{id}", "42")
    readme_uri = published_uri_for_namespace("hello", "docs://readme")
    async with LifespanManager(router):
        main, settings, upstreams, registry, manager, _resolver, backend = await _build_enforce_stack(
            router,
            policy_yaml="""\
version: "1.0.0"
default_deny: true
roles:
  pub_only:
    allow: ["hello_pub"]
  pub_and_secret:
    allow: ["hello_pub", "hello_secret"]
""",
            policy_path=tmp_path / "policy.yaml",
            evil_first=True,
        )
        if upstream_mode == "legacy":
            upstreams._adapters["hello"]._client_factory = _legacy_upstream_client_factory(router)

        backend.seed(ANN.email, roles=("pub_only",))

        async def _run_reads(client: Client) -> None:
            with pytest.raises(MCPError, match="access denied"):
                await client.read_resource(secret_uri)
            blocks = await client.read_resource(readme_uri)
            assert blocks[0].text == f"content:{readme_uri}"

        if client_mode == "legacy":
            async with Client(main) as client:
                await _run_reads(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _run_reads(client)

        backend.seed(ANN.email, roles=("pub_and_secret",))
        manager.reload(registry)

        async def _run_allowed(client: Client) -> None:
            blocks = await client.read_resource(secret_uri)
            assert blocks[0].text == f"content:{secret_uri}"

        if client_mode == "legacy":
            async with Client(main) as client:
                await _run_allowed(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _run_allowed(client)


@pytest.mark.parametrize("client_mode", ["legacy", "modern"], ids=["client-legacy", "client-modern"])
async def test_listing_hides_resource_unless_every_name_allowed(tmp_path: Path, client_mode: str):
    hello_app = build_resource_upstream_app(
        resources=[
            types.Resource(
                uri="docs://readme",
                name="readme",
                description="readme",
                mime_type="text/plain",
            ),
        ],
        templates=[
            types.ResourceTemplate(
                uri_template="docs://{path*}",
                name="pub",
                description="public",
                mime_type="text/plain",
            ),
        ],
    )
    empty_evil = build_resource_upstream_app(resources=[], templates=[])
    router = mount_resource_upstream_apps({"hello": hello_app, "evil": empty_evil})
    readme_published = published_uri_for_namespace("hello", "docs://readme")
    async with LifespanManager(router):
        main, settings, _upstreams, _registry, _manager, _resolver, backend = await _build_enforce_stack(
            router,
            policy_yaml='version: "1.0.0"\ndefault_deny: true\nroles:\n  readme_only:\n    allow: ["hello_readme"]\n',
            policy_path=tmp_path / "policy.yaml",
            evil_first=True,
        )
        backend.seed(ANN.email, roles=("readme_only",))

        async def _assert_hidden(client: Client) -> None:
            resources = await client.list_resources()
            assert readme_published not in {str(r.uri) for r in resources}

        if client_mode == "legacy":
            async with Client(main) as client:
                await _assert_hidden(client)
        else:
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await _assert_hidden(client)


def test_rbac_names_for_uri_looks_only_in_own_namespace():
    catalog = UpstreamContentCatalog()
    catalog.set_templates(
        "alpha",
        build_upstream_template_specs(
            SimpleNamespace(namespace="alpha"),
            [
                SimpleNamespace(
                    uri_template="x://{a}/{b*}",
                    name="tpl",
                    title=None,
                    description="",
                    mime_type=None,
                )
            ],
        ),
    )
    catalog.set_templates(
        "beta",
        build_upstream_template_specs(
            SimpleNamespace(namespace="beta"),
            [
                SimpleNamespace(
                    uri_template="y://item/{id}",
                    name="item",
                    title=None,
                    description="",
                    mime_type=None,
                )
            ],
        ),
    )
    beta_uri = published_uri_for_namespace("beta", "y://item/99")
    assert catalog.rbac_names_for_uri(beta_uri) == ("beta_item",)
    assert catalog.rbac_names_for_uri("x://alpha/1/tail") == ("alpha_tpl",)
