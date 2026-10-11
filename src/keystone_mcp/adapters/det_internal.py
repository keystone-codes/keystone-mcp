"""det_internal adapter — synchronous deterministic call.

PLACEHOLDER. No synchronous internal deterministic-call API is wired yet, so
this adapter returns a canonical stub flagged with ``det_internal=True``. A
deployment can register det routes against it today and make them live by
swapping the adapter body; no transport change is needed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route


class DetInternalAdapter:
    def __init__(self, fn: str) -> None:
        # Name of the deterministic function this route maps to (resolved by
        # the internal det-API once one is wired).
        self.fn = fn

    async def execute(
        self, route: "Route", ctx: "RouteContext", args: dict[str, Any], request: Any
    ) -> dict[str, Any]:
        return {
            "state": "done",
            "stub": True,
            "det_internal": True,
            "fn": self.fn,
            "tool": route.name,
            "task_id": ctx.task_id,
            "result": None,
            "note": "det_internal target is a placeholder; no det-API is wired",
        }
