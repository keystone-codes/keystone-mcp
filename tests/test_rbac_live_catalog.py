"""Live published-name catalog: multiplicity, uniqueness refusal, loopback dump.

Fictional tool names: the mechanism under test is the router's own published-name
bookkeeping, not any deployment's catalog.
"""

from __future__ import annotations

import httpx
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from fastmcp import FastMCP

from keystone_mcp.adapters.base import Pattern
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.rbac.catalog import (
    LIVE_PUBLISHED_NAMES_PATH,
    DuplicateLivePublishedNameError,
    assert_unique_live_published_names,
    collect_live_tool_names,
    format_live_published_names,
    live_published_name_counts,
    parse_live_published_names,
    uniqueness_refusal_message,
)
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.server import build_server
from support.login import dev_token_login

BASE_URL = "http://localhost:8080"
_COLLIDING_PUBLISHED = "reports_present_release"


class _StubAdapter:
    async def invoke(self, **_kwargs):
        return {"state": "ok"}


def _registry_with_colliding_live_routes() -> RouterRegistry:
    """Two live routes, different route keys, the same published name.

    Namespaced route: namespace ``reports`` + name ``present_release``.
    Already-prefixed route: no namespace, name already in published form.
    """
    mcp = FastMCP("published-name-collision")
    registry = RouterRegistry(RouterEngine(Settings(base_url=BASE_URL)), mcp)
    adapter = _StubAdapter()
    registry.add_route(
        "present_release",
        adapter,
        pattern=Pattern.SYNC,
        mode="live",
        namespace="reports",
    )
    registry.add_route(_COLLIDING_PUBLISHED, adapter, pattern=Pattern.SYNC, mode="live")
    return registry


def test_collect_live_tool_names_is_a_sequence_not_a_set():
    names = collect_live_tool_names(_registry_with_colliding_live_routes())
    assert isinstance(names, tuple)
    assert not isinstance(names, (set, frozenset))


def test_two_live_routes_same_published_name_reports_multiplicity_2():
    """A set cannot hold multiplicity; this sequence can, so the clash is visible."""
    names = collect_live_tool_names(_registry_with_colliding_live_routes())
    counts = live_published_name_counts(names)
    assert counts[_COLLIDING_PUBLISHED] == 2
    assert names.count(_COLLIDING_PUBLISHED) == 2
    refusal = uniqueness_refusal_message(_COLLIDING_PUBLISHED, 2)
    with pytest.raises(DuplicateLivePublishedNameError, match=refusal) as excinfo:
        assert_unique_live_published_names(names)
    assert str(excinfo.value) == refusal


def test_unique_live_names_pass_uniqueness():
    mcp = FastMCP("published-name-unique")
    registry = RouterRegistry(RouterEngine(Settings(base_url=BASE_URL)), mcp)
    registry.add_route(
        "present_release",
        _StubAdapter(),
        pattern=Pattern.SYNC,
        mode="live",
        namespace="reports",
    )
    names = collect_live_tool_names(registry)
    assert names.count(_COLLIDING_PUBLISHED) == 1
    assert_unique_live_published_names(names)


def test_namespaced_routes_publish_distinct_names():
    mcp = FastMCP("published-name-distinct")
    registry = RouterRegistry(RouterEngine(Settings(base_url=BASE_URL)), mcp)
    adapter = _StubAdapter()
    for route_name in ("get_document", "ensure_document", "list_documents"):
        registry.add_route(
            route_name,
            adapter,
            pattern=Pattern.SYNC,
            mode="live",
            namespace="documents",
        )
    names = collect_live_tool_names(registry)
    for expected in (
        "documents_get_document",
        "documents_ensure_document",
        "documents_list_documents",
    ):
        assert names.count(expected) == 1
    assert_unique_live_published_names(names)


def test_dump_round_trip_preserves_multiplicity():
    names = (_COLLIDING_PUBLISHED, _COLLIDING_PUBLISHED)
    body = format_live_published_names(names)
    assert parse_live_published_names(body) == names


def test_empty_dump_round_trips():
    assert format_live_published_names(()) == ""
    assert parse_live_published_names("") == ()


@pytest_asyncio.fixture
async def live_names_client():
    # The route is off by default; this fixture exercises it, so turn it on.
    settings = Settings(base_url=BASE_URL, rbac_mode="off", internal_endpoints_enabled=True)
    mcp, registry, *_rest = build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    adapter = _StubAdapter()
    registry.add_route(
        "present_release",
        adapter,
        pattern=Pattern.SYNC,
        mode="live",
        namespace="reports",
    )
    registry.add_route(_COLLIDING_PUBLISHED, adapter, pattern=Pattern.SYNC, mode="live")
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=BASE_URL,
        ) as client:
            yield client


@pytest.mark.asyncio
async def test_loopback_dump_reports_multiplicity_2(live_names_client: httpx.AsyncClient):
    response = await live_names_client.get(LIVE_PUBLISHED_NAMES_PATH)
    assert response.status_code == 200
    dumped = parse_live_published_names(response.text)
    assert dumped.count(_COLLIDING_PUBLISHED) == 2
    refusal = uniqueness_refusal_message(_COLLIDING_PUBLISHED, 2)
    with pytest.raises(DuplicateLivePublishedNameError, match=refusal):
        assert_unique_live_published_names(dumped)


@pytest.mark.asyncio
async def test_loopback_dump_denied_when_forwarded_for_present(
    live_names_client: httpx.AsyncClient,
):
    response = await live_names_client.get(
        LIVE_PUBLISHED_NAMES_PATH,
        headers={"X-Forwarded-For": "203.0.113.1"},
    )
    assert response.status_code == 403
