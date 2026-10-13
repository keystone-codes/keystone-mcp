"""Publish an upstream proxy tool with its own JSON Schema, verbatim.

``RouterRegistry._register_tool`` builds an ordinary FastMCP tool from a
Python function signature derived from ``route.params`` (see
``RouterRegistry._make_handler``). That loses most of what helps an agent
call an upstream tool correctly (``enum``, bounds, nested objects, ``$defs``,
``outputSchema``, ``title``, ``annotations``) and rejects any upstream
parameter name that is not a legal Python identifier (e.g. ``max-results``) or
is a reserved keyword (``from``, ``class``).

``UpstreamProxyTool`` sidesteps both problems: it is a :class:`fastmcp.tools.
base.Tool` subclass whose ``parameters`` *is* the upstream's own (patched,
normalized) ``inputSchema``, published as-is. It never builds a Python
function signature, so it does not care whether the schema's property names
are valid identifiers; argument validation is left entirely to the upstream.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastmcp.exceptions import ToolError
from fastmcp.tools.base import Tool, ToolResult
from mcp.types import ToolAnnotations
from pydantic import PrivateAttr

from keystone_mcp.router.engine import UnauthorizedError

if TYPE_CHECKING:
    from keystone_mcp.router.engine import RouterEngine
    from keystone_mcp.router.route import Route


class UpstreamProxyTool(Tool):
    """One upstream tool, published with its own schema, executed via the router."""

    _route: "Route" = PrivateAttr()
    _engine: "RouterEngine" = PrivateAttr()

    async def run(self, arguments: dict[str, Any]) -> ToolResult:
        try:
            out = await self._engine.execute(self._route, arguments)
        except UnauthorizedError as exc:
            # Never return the denial as a structured dict here: this route
            # may publish the upstream's own outputSchema verbatim
            # (transparent mode, see for_route() below), and a strict client
            # validates structuredContent against it. {"state": "error", ...}
            # does not match that schema and would surface as a confusing
            # schema-validation failure instead of a plain denial. ToolError
            # sets isError on the MCP result (as every other denial path
            # does -- RbacMiddleware, ThrottleMiddleware), which skips that
            # client-side validation entirely.
            raise ToolError(str(exc)) from exc
        return self.convert_result(out)

    @classmethod
    def for_route(cls, route: "Route", engine: "RouterEngine") -> "UpstreamProxyTool":
        """Build the published tool for *route* from its upstream schema.

        ``route.input_schema`` must not be ``None``: callers
        (``RouterRegistry._register_tool``) only take this path when it is
        set.

        ``route.output_schema`` (the upstream's own ``outputSchema``, stored
        unconditionally on the route for fingerprinting) is only actually
        published when the route is ``live`` *and* its adapter is proxying
        transparently (``status_envelope`` false, or absent on a foreign
        adapter type that has no such flag -- treated as "has an envelope",
        i.e. never published). Otherwise an MCP client would validate
        ``structuredContent`` against the upstream's schema while the
        response is actually a stub or the legacy envelope, and reject it.
        """
        transparent = not getattr(route.target, "status_envelope", True)
        publish_output_schema = (
            route.mode == "live" and transparent and route.output_schema is not None
        )
        # route.annotations is stored in wire form (``readOnlyHint`` etc.,
        # see build_upstream_tool_specs) -- model_validate understands field
        # aliases, a plain **route.annotations unpack would not.
        annotations = (
            ToolAnnotations.model_validate(route.annotations) if route.annotations else None
        )

        tool = cls(
            name=route.name,
            description=route.description or None,
            title=route.title,
            parameters=route.input_schema,
            output_schema=route.output_schema if publish_output_schema else None,
            annotations=annotations,
            tags=set(route.tags),
            meta=route.meta or None,
        )
        tool._route = route
        tool._engine = engine
        return tool
