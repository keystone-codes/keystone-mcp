"""Stub adapter — canonical Model-M response by pattern (default target)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from keystone_mcp.adapters.base import stub_response

if TYPE_CHECKING:
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route


class StubAdapter:
    async def execute(
        self, route: "Route", ctx: "RouteContext", args: dict[str, Any], request: Any
    ) -> dict[str, Any]:
        return stub_response(ctx.pattern, ctx.task_id, route.name)
