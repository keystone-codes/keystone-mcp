"""Tests for upstream JSON Schema → router Param conversion."""

from __future__ import annotations

import pytest
from fastmcp import Client, FastMCP

from keystone_mcp.adapters.base import Pattern
from keystone_mcp.adapters.mcp_proxy import McpProxyAdapter
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.context import RouteContext
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.route import Route
from keystone_mcp.router.schema import omit_implicit_null_args, schema_to_params

ID = VerifiedIdentity(email="analyst@example.com")


def _ctx() -> RouteContext:
    return RouteContext(
        verified_identity=ID,
        task_id="t_test",
        canonical_args="{}",
        tool_name="test_tool",
        pattern=Pattern.SYNC,
        settings=Settings(base_url="http://localhost:8080"),
    )


def test_schema_to_params_preserves_nullable_anyof_types() -> None:
    params = schema_to_params(
        {
            "properties": {
                "bootstrap": {
                    "anyOf": [{"type": "boolean"}, {"type": "null"}],
                    "default": None,
                },
                "cursor_boundary": {
                    "anyOf": [{"type": "string"}, {"type": "null"}],
                    "default": None,
                },
                "max_files": {
                    "anyOf": [{"type": "integer"}, {"type": "null"}],
                    "default": None,
                },
            },
            "type": "object",
        }
    )
    by_name = {param.name: param for param in params}
    assert by_name["bootstrap"].type == bool | None
    assert by_name["cursor_boundary"].type == str | None
    assert by_name["max_files"].type == int | None
    assert all(param.allows_null for param in params)
    assert all(not param.required for param in params)


def test_schema_to_params_anyof_multiple_non_null_types() -> None:
    params = schema_to_params(
        {
            "properties": {
                "value": {
                    "anyOf": [
                        {"type": "string"},
                        {"type": "integer"},
                        {"type": "null"},
                    ],
                }
            },
            "type": "object",
        }
    )
    assert len(params) == 1
    assert params[0].type == (str | int | None)
    assert params[0].allows_null is True


def test_schema_to_params_required_with_default_null_and_explicit_nullable() -> None:
    params = schema_to_params(
        {
            "properties": {
                "mode": {
                    "anyOf": [{"type": "string"}, {"type": "null"}],
                    "default": None,
                }
            },
            "required": ["mode"],
            "type": "object",
        }
    )
    assert len(params) == 1
    assert params[0].required is True
    assert params[0].type == str | None
    assert params[0].allows_null is True


def test_schema_to_params_optional_without_explicit_null() -> None:
    params = schema_to_params(
        {
            "properties": {
                "bootstrap": {"type": "boolean", "default": False},
            },
            "type": "object",
        }
    )
    assert len(params) == 1
    assert params[0].type == bool | None
    assert params[0].allows_null is False


def test_omit_implicit_null_args_drops_optional_nulls() -> None:
    params = schema_to_params(
        {
            "properties": {
                "bootstrap": {"type": "boolean", "default": False},
                "cursor_boundary": {
                    "anyOf": [{"type": "string"}, {"type": "null"}],
                    "default": None,
                },
            },
            "type": "object",
        }
    )
    forwarded = omit_implicit_null_args(
        {
            "bootstrap": None,
            "cursor_boundary": None,
            "dataset_code": "101",
        },
        params,
    )
    assert forwarded == {"cursor_boundary": None, "dataset_code": "101"}


async def test_mcp_proxy_omits_implicit_null_args_before_upstream_call() -> None:
    from fastmcp import Client, FastMCP

    downstream = FastMCP("downstream")
    received: dict[str, object] = {}

    @downstream.tool()
    def export_delta(
        dataset_code: str,
        bootstrap: bool = False,
        cursor_boundary: str | None = None,
    ) -> dict:
        received["dataset_code"] = dataset_code
        received["bootstrap"] = bootstrap
        received["cursor_boundary"] = cursor_boundary
        return {"status": "ok"}

    adapter = McpProxyAdapter("http://unused")
    adapter._client_factory = lambda **_kw: Client(downstream)  # type: ignore[assignment]
    route = Route(
        name="export_delta",
        target=adapter,
        upstream_tool="export_delta",
        namespace="archive",
        mode="live",
        params=schema_to_params(
            {
                "properties": {
                    "dataset_code": {"type": "string"},
                    "bootstrap": {"type": "boolean", "default": False},
                    "cursor_boundary": {
                        "anyOf": [{"type": "string"}, {"type": "null"}],
                        "default": None,
                    },
                },
                "required": ["dataset_code"],
                "type": "object",
            }
        ),
    )

    out = await adapter.execute(
        route,
        _ctx(),
        {
            "dataset_code": "101",
            "bootstrap": None,
            "cursor_boundary": None,
        },
        None,
    )
    assert out.is_error is False
    assert received == {
        "dataset_code": "101",
        "bootstrap": False,
        "cursor_boundary": None,
    }


async def test_optional_field_before_required_publishes() -> None:
    """An optional field declared before a required one must still publish.

    Non-FastMCP upstreams (TypeScript SDK, Go SDK, the low-level Python SDK)
    routinely emit this field order; the handler signature must be built
    keyword-only so Python does not reject it as "non-default argument
    follows default argument".
    """
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"},
            "filter": {"type": "string"},
        },
        "required": ["query", "filter"],
    }
    mcp = FastMCP("t")
    registry = RouterRegistry(RouterEngine(Settings(base_url="http://localhost:8080")), mcp)

    class _StubAdapter:
        async def execute(self, route, ctx, args, request):
            return {"state": "done", "tool": route.published_name, "result": args}

    registry.add_route("search", _StubAdapter(), params=schema_to_params(schema), mode="live")

    async with Client(mcp) as client:
        tools = await client.list_tools()

    search_tool = next(t for t in tools if t.name == "search")
    assert search_tool.input_schema["required"] == ["query", "filter"]
    assert list(search_tool.input_schema["properties"]) == ["query", "limit", "filter"]


class _StubAdapter:
    async def execute(self, route, ctx, args, request):
        return {"state": "done", "tool": route.published_name, "result": args}


async def test_add_route_with_unpublishable_param_name_leaves_no_trace() -> None:
    """A brand-new route whose schema has a Python-keyword parameter name
    (``from``) cannot be built into a handler signature at all
    (``inspect.Parameter`` rejects keywords, and non-identifiers like
    ``max-results`` the same way). ``add_route`` must leave nothing behind
    when that happens: not in the registry, not published in FastMCP. This
    is the atomicity guarantee behind the "ghost tool" fix -- see
    ``test_add_route_update_failure_keeps_the_old_tool_published`` for the
    more dangerous update case.
    """
    schema = {
        "type": "object",
        "properties": {"from": {"type": "string"}},
        "required": ["from"],
    }
    mcp = FastMCP("t")
    registry = RouterRegistry(RouterEngine(Settings(base_url="http://localhost:8080")), mcp)

    with pytest.raises(ValueError, match="from"):
        registry.add_route("bad", _StubAdapter(), params=schema_to_params(schema), mode="live")

    assert registry.get("bad") is None
    assert "bad" not in registry.routes

    async with Client(mcp) as client:
        tools = await client.list_tools()
    assert not any(t.name == "bad" for t in tools)


async def test_add_route_update_failure_keeps_the_old_tool_published() -> None:
    """Re-registering an already-published route with a bad schema must not
    ghost the old one.

    Before the fix, ``add_route`` wrote the new ``Route`` into
    ``self._routes`` *before* attempting to publish it with FastMCP. When
    publishing the update failed (bad parameter name) the caller's
    exception handler removed that entry from the registry again -- but the
    *old*, still-published FastMCP tool was never touched, so it kept
    answering calls that the registry no longer knew about at all, and
    ``_remove_proxy_route`` could never find it again to clean it up.

    After the fix, the registry and FastMCP either both hold the new route
    or both still hold the old one -- never a mix.
    """
    good_schema = {
        "type": "object",
        "properties": {"query": {"type": "string"}},
        "required": ["query"],
    }
    bad_schema = {
        "type": "object",
        "properties": {"query": {"type": "string"}, "from": {"type": "string"}},
        "required": ["query", "from"],
    }
    mcp = FastMCP("t")
    registry = RouterRegistry(RouterEngine(Settings(base_url="http://localhost:8080")), mcp)

    registry.add_route("search", _StubAdapter(), params=schema_to_params(good_schema), mode="live")
    old_route = registry.get("search")
    assert old_route is not None

    with pytest.raises(ValueError, match="from"):
        registry.add_route(
            "search", _StubAdapter(), params=schema_to_params(bad_schema), mode="live"
        )

    # The registry still has the OLD route object -- not emptied out, not a
    # half-applied update.
    assert registry.get("search") is old_route

    async with Client(mcp) as client:
        tools = await client.list_tools()
    search_tool = next(t for t in tools if t.name == "search")
    assert list(search_tool.input_schema["properties"]) == ["query"]
