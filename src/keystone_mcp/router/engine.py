"""Router engine.

Per call: resolve the verified identity (OAuth) -> deterministic task_id -> if
mode==stub return the canonical stub -> else build the transport context, run
the transform, execute the adapter, return the status-envelope result.

Rate limiting is not done here: it belongs to
:class:`~keystone_mcp.router.throttle_middleware.ThrottleMiddleware`, which is
the single place a tool call consumes an identity's budget.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from keystone_mcp import identity as identity_module
from keystone_mcp.adapters.base import stub_response
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity, canonical, make_task_id
from keystone_mcp.router.context import RouteContext
from keystone_mcp.router.route import Route

if TYPE_CHECKING:
    from fastmcp.tools.base import ToolResult


class UnauthorizedError(Exception):
    """Raised when no verified identity is present on the call."""


class RouterEngine:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def execute(
        self,
        route: Route,
        args: dict[str, Any] | None,
        identity: VerifiedIdentity | None = None,
    ) -> "dict[str, Any] | ToolResult":
        args = args or {}
        if identity is None:
            identity = identity_module.resolve_verified_identity()
        if identity is None:
            raise UnauthorizedError("no verified identity on request")

        task_id = make_task_id(identity, route.name, args, namespace=route.namespace)

        if route.mode == "stub":
            return stub_response(route.pattern, task_id, route.published_name)

        ctx = RouteContext(
            verified_identity=identity,
            task_id=task_id,
            # Deterministic canonical form, for transforms that need it.
            canonical_args=canonical(args),
            tool_name=route.published_name,
            pattern=route.pattern,
            settings=self._settings,
        )

        request = route.transform(ctx, args) if route.transform is not None else None
        return await route.target.execute(route, ctx, args, request)
