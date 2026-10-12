"""Tests for /metrics exposure hardening."""

from __future__ import annotations

import httpx
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from support.login import dev_token_login

BASE_URL = "http://localhost:8080"


@pytest_asyncio.fixture
async def metrics_app():
    settings = Settings(base_url=BASE_URL, metrics_enabled=True)
    mcp, *_rest = build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=BASE_URL,
        ) as client:
            yield client


@pytest.mark.asyncio
async def test_metrics_available_without_forwarded_for(metrics_app: httpx.AsyncClient):
    response = await metrics_app.get("/metrics")
    assert response.status_code == 200
    assert "keystone_mcp_rbac_decisions_total" in response.text
    assert "keystone_mcp_tool_call_attempts_total" in response.text
    assert "keystone_mcp_tool_invocations_total" in response.text


@pytest.mark.asyncio
async def test_metrics_denied_when_forwarded_for_present(metrics_app: httpx.AsyncClient):
    response = await metrics_app.get(
        "/metrics",
        headers={"X-Forwarded-For": "203.0.113.1"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_upstream_available_gauge_is_exposed():
    settings = Settings(base_url=BASE_URL, metrics_enabled=True)
    mcp, _registry, _oauth, upstreams, _policy_manager, _observability, _reconciler = build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    upstreams.add_upstream("docs-mcp", "http://docs:8080/mcp", namespace="docs")
    upstreams.mark_unavailable("docs", "connection refused")

    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=BASE_URL,
        ) as client:
            response = await client.get("/metrics")
            assert response.status_code == 200
            assert 'keystone_mcp_upstream_available{namespace="docs"} 0.0' in response.text

            upstreams.mark_available("docs")
            response = await client.get("/metrics")
            assert 'keystone_mcp_upstream_available{namespace="docs"} 1.0' in response.text


@pytest.mark.asyncio
async def test_list_changed_metric_is_exposed():
    """Y05: ``keystone_mcp_list_changed_sessions_total{kind="tools"}`` is scraped."""
    settings = Settings(base_url=BASE_URL, metrics_enabled=True)
    mcp, _registry, _oauth, _upstreams, _policy_manager, observability, _reconciler = build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )

    observability.record_list_changed(kind="tools", sessions=2)

    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=BASE_URL,
        ) as client:
            response = await client.get("/metrics")
            assert response.status_code == 200
            assert 'keystone_mcp_list_changed_sessions_total{kind="tools"} 2.0' in response.text
