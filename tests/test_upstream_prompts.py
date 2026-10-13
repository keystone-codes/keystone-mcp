"""Upstream prompt discovery, proxying and RBAC (Y06)."""

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
from mcp.shared.exceptions import MCPError

import keystone_mcp.surface.reconciler as reconciler_module
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.rbac_middleware import RbacMiddleware
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamListToolsError, UpstreamRegistry
from keystone_mcp.surface.client_sessions import ClientSessionRegistry, SessionTrackingMiddleware
from keystone_mcp.surface.reconciler import SurfaceReconciler
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)

ANN = VerifiedIdentity(email="ann@example.com")
_IDENTITY_SECRET = "s3cr3t-identity-" + "v" * 20


@pytest.fixture(autouse=True)
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity", lambda: ANN
    )


def _build_upstreams(
    app,
    *,
    observed: dict | None = None,
    prompts: bool = True,
    monkeypatch=None,
    identity: bool = True,
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
        rbac_mode=settings.rbac_mode,
    )
    upstream_kw: dict = {}
    if identity:
        upstream_kw["identity_secret_env"] = "KEYSTONE_MCP_UPSTREAM_HELLO_IDENTITY_SECRET"
    upstreams.add_upstream("hello-upstream", UPSTREAM_MCP_URL, namespace="hello", **upstream_kw)
    return main, registry, upstreams


async def test_prompt_is_published_with_namespace(monkeypatch):
    observed: dict = {}
    app = build_lowlevel_upstream_app(tools=["greet"], prompts=True, observed=observed)
    async with LifespanManager(app):
        main, _registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        await upstreams.discover_all()

        async with Client(main) as client:
            prompts = await client.list_prompts()
            names = {p.name for p in prompts}
            assert "hello_summarize" in names
            summarize = next(p for p in prompts if p.name == "hello_summarize")
            assert any(arg.name == "topic" for arg in (summarize.arguments or []))


async def test_get_prompt_reaches_upstream_with_identity(monkeypatch):
    observed: dict = {}
    app = build_lowlevel_upstream_app(tools=["greet"], prompts=True, observed=observed)
    async with LifespanManager(app):
        main, _registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        await upstreams.discover_all()

        async with Client(main) as client:
            result = await client.get_prompt("hello_summarize", {"topic": "x"})
        assert result.messages[0].content.text == "Summarize x"
        token = observed["prompt_headers"].get("x-keystone-identity")
        assert token is not None
        decoded = jwt.decode(
            token,
            _IDENTITY_SECRET,
            algorithms=["HS256"],
            audience="hello-upstream",
            issuer="http://localhost:8080",
        )
        assert decoded["mcp_method"] == "prompts/get"
        assert decoded["mcp_target"] == "summarize"


async def test_rbac_hides_and_denies_prompt(tmp_path: Path, monkeypatch):
    policy_greet_only = """\
version: "1.0.0"
default_deny: true
roles:
  member:
    allow: ["hello_greet"]
"""
    policy_wildcard = policy_greet_only.replace('["hello_greet"]', '["hello_*"]')
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(policy_greet_only, encoding="utf-8")

    app = build_lowlevel_upstream_app(tools=["greet"], prompts=True)
    async with LifespanManager(app):
        main, registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        settings = Settings(
            base_url="http://localhost:8080",
            rbac_mode="enforce",
            rbac_policy_path=str(policy_path),
            users_service_url="http://users:8000",
            users_service_token="token",
            redis_url="redis://localhost:6379/5",
        )
        resolver, backend, _revision = build_in_memory_user_directory_resolver()
        backend.seed(ANN.email, roles=("member",))
        manager = RbacPolicyManager(
            settings,
            extra_catalog_names=lambda: upstreams.content.rbac_names(),
        )
        main.add_middleware(RbacMiddleware(manager, resolver, settings=settings))
        await upstreams.discover_all()
        manager.load_initial(registry)

        async with Client(main) as client:
            prompts = await client.list_prompts()
            assert "hello_summarize" not in {p.name for p in prompts}
            with pytest.raises(MCPError, match="access denied"):
                await client.get_prompt("hello_summarize", {"topic": "x"})

        policy_path.write_text(policy_wildcard, encoding="utf-8")
        manager.reload(registry)

        async with Client(main) as client:
            prompts = await client.list_prompts()
            assert "hello_summarize" in {p.name for p in prompts}
            result = await client.get_prompt("hello_summarize", {"topic": "y"})
            assert result.messages[0].content.text == "Summarize y"


async def test_policy_pattern_matching_only_a_prompt_is_valid(tmp_path: Path, monkeypatch):
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
    app = build_lowlevel_upstream_app(tools=["greet"], prompts=True)
    async with LifespanManager(app):
        main, registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        settings = Settings(
            base_url="http://localhost:8080",
            rbac_mode="enforce",
            rbac_policy_path=str(policy_path),
            users_service_url="http://users:8000",
            users_service_token="token",
            redis_url="redis://localhost:6379/5",
        )
        await upstreams.discover_all()
        manager = RbacPolicyManager(
            settings,
            extra_catalog_names=lambda: upstreams.content.rbac_names(),
        )
        manager.load_initial(registry)


async def test_upstream_without_prompts_capability_is_skipped():
    observed: dict = {}
    app = build_lowlevel_upstream_app(tools=["greet"], prompts=False, observed=observed)
    async with LifespanManager(app):
        main, _registry, upstreams = _build_upstreams(app, identity=False)
        await upstreams.discover_all()
        assert observed.get("list_prompts_calls", 0) == 0


async def test_prompt_added_upstream_is_published_and_notified(monkeypatch):
    app = build_lowlevel_upstream_app(tools=["greet"], prompts=False)
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
            assert await client.list_prompts() == []

            app2 = build_lowlevel_upstream_app(tools=["greet"], prompts=True)
            async with LifespanManager(app2):
                real_fetch = reconciler_module.fetch_upstream_tools
                real_prompts = reconciler_module.fetch_upstream_prompts
                factory = asgi_http_client_factory(app2)

                async def fake_fetch(url, **kwargs):
                    kwargs["httpx_client_factory"] = factory(kwargs.get("timeout_seconds", 5.0))
                    return await real_fetch(url, **kwargs)

                async def fake_prompts(url, **kwargs):
                    kwargs["httpx_client_factory"] = factory(kwargs.get("timeout_seconds", 5.0))
                    return await real_prompts(url, **kwargs)

                reconciler_module.fetch_upstream_tools = fake_fetch
                reconciler_module.fetch_upstream_prompts = fake_prompts
                try:
                    await reconciler.tick()
                finally:
                    reconciler_module.fetch_upstream_tools = real_fetch
                    reconciler_module.fetch_upstream_prompts = real_prompts

            await asyncio.sleep(0)
            assert any(m.method == "notifications/prompts/list_changed" for m in received)
            names = {p.name for p in await client.list_prompts()}
            assert "hello_summarize" in names


@pytest.mark.parametrize("client_mode", ["legacy", "modern"])
async def test_client_meta_is_not_forwarded_to_upstream(monkeypatch, client_mode: str):
    observed: dict = {}
    app = build_lowlevel_upstream_app(tools=["greet"], prompts=True, observed=observed)
    async with LifespanManager(app):
        main, _registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        await upstreams.discover_all()

        meta = {"keystone-mcp/identity": "forged", "x-client": "1"}
        if client_mode == "legacy":
            async with Client(main) as client:
                await client.get_prompt("hello_summarize", {"topic": "x"}, meta=meta)
        else:
            settings = Settings(base_url="http://localhost:8080")
            async with asgi_server(main, path=settings.http_path) as running:
                async with running.client() as client:
                    await client.get_prompt("hello_summarize", {"topic": "x"}, meta=meta)

        assert "keystone-mcp/identity" not in observed.get("prompt_meta", {})
        assert "x-client" not in observed.get("prompt_meta", {})


async def test_prompts_failure_keeps_tools(monkeypatch, caplog: pytest.LogCaptureFixture):
    app = build_lowlevel_upstream_app(tools=["greet"], prompts=True)
    async with LifespanManager(app):
        main, registry, upstreams = _build_upstreams(app, monkeypatch=monkeypatch)
        await upstreams.discover_all()
        assert upstreams.unavailable_namespaces() == {}

        monkeypatch.setattr(
            "keystone_mcp.surface.reconciler.fetch_upstream_prompts",
            AsyncMock(side_effect=UpstreamListToolsError("list_prompts exploded")),
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
        assert any("upstream prompts refresh failed" in r.message for r in caplog.records)
        async with Client(main) as client:
            tools = await client.list_tools()
            assert "hello_greet" in {t.name for t in tools}
