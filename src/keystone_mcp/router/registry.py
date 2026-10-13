"""Route registry and the ``add_route`` constructor.

``add_route`` registers a :class:`Route` and (when bound to a FastMCP server)
dynamically publishes an MCP tool whose handler delegates to the engine. The
tool signature is built from the route's :class:`Param` list so the agent sees a
stable, typed catalog; the verified identity is implicit (an OAuth claim), never
a tool parameter.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from keystone_mcp.adapters.base import Adapter, Pattern
from keystone_mcp.router.engine import RouterEngine, UnauthorizedError
from keystone_mcp.router.route import ConfigMode, Mode, Route, Transform

if TYPE_CHECKING:
    from fastmcp import FastMCP


@dataclass
class Param:
    """One inbound parameter of a tool signature."""

    name: str
    type: type = str
    required: bool = True
    default: Any = None
    description: str | None = None
    allows_null: bool = False


class RouterRegistry:
    def __init__(self, engine: RouterEngine, mcp: "FastMCP | None" = None) -> None:
        self._engine = engine
        self._mcp = mcp
        self._routes: dict[str, Route] = {}

    @property
    def routes(self) -> dict[str, Route]:
        return self._routes

    def get(self, name: str) -> Route | None:
        return self._routes.get(name)

    def owner_of_published_name(self, published_name: str) -> str | None:
        """Return the ``route_key`` of whichever route already publishes this name.

        Two different routes (different namespace or built-in vs. proxied)
        can resolve to the same client-visible ``published_name`` — see
        :func:`keystone_mcp.upstream_registry.validate.namespace_errors` for
        the namespace rules that keep this rare. Callers that are about to
        register a route under a name use this first to refuse the
        collision instead of silently shadowing the existing one.
        """
        for route_key, route in self._routes.items():
            if route.published_name == published_name:
                return route_key
        return None

    def add_route(
        self,
        name: str,
        target: Adapter,
        *,
        pattern: Pattern = Pattern.SYNC,
        params: list[Param] | None = None,
        description: str = "",
        transform: Transform | None = None,
        mode: Mode = "stub",
        admin: bool = False,
        upstream_tool: str | None = None,
        namespace: str | None = None,
        config_mode: ConfigMode | None = None,
        tags: set[str] | frozenset[str] | None = None,
        meta: dict[str, Any] | None = None,
        mcp: "FastMCP | None" = None,
        input_schema: dict[str, Any] | None = None,
        output_schema: dict[str, Any] | None = None,
        title: str | None = None,
        annotations: dict[str, Any] | None = None,
    ) -> Route:
        route = Route(
            name=name,
            target=target,
            pattern=pattern,
            params=params or [],
            description=description,
            transform=transform,
            mode=mode,
            admin=admin,
            upstream_tool=upstream_tool,
            namespace=namespace,
            config_mode=config_mode,
            tags=frozenset(tags or ()),
            meta=dict(meta or {}),
            input_schema=input_schema,
            output_schema=output_schema,
            title=title,
            annotations=annotations,
        )
        # Publish to FastMCP *before* writing to ``self._routes``. A route
        # with the same ``route_key`` may already be published (this call is
        # updating it with a new upstream schema): if ``_register_tool``
        # raises -- e.g. a parameter name that is not a legal Python
        # identifier, or is a reserved keyword such as ``from`` -- nothing
        # here is touched, so the previous route (if any) stays exactly as
        # it was in both the registry and FastMCP's own catalog. The old
        # order wrote the new route into ``self._routes`` first, so a
        # publish failure on an update left the registry either empty or
        # holding a route FastMCP never actually published, while the
        # previously-published FastMCP tool (if this was an update) kept
        # answering calls the registry no longer knew about at all -- a
        # "ghost tool" that could never be found again to remove.
        target_mcp = mcp if mcp is not None else self._mcp
        if target_mcp is not None:
            self._register_tool(route, target_mcp)
        self._routes[route.route_key] = route
        return route

    def remove_route(self, route_key: str) -> Route | None:
        """Drop a route from the registry without touching FastMCP publication."""
        return self._routes.pop(route_key, None)

    def set_mode(self, name: str, mode: Mode) -> None:
        """Flip a route stub<->live without touching the transport."""
        route = self._routes.get(name)
        if route is None:
            for candidate in self._routes.values():
                if candidate.name == name or candidate.route_key == name:
                    route = candidate
                    break
        if route is None:
            raise KeyError(name)
        route.mode = mode

    # ── FastMCP tool publication ──────────────────────────────────────────
    def _register_tool(self, route: Route, mcp: "FastMCP") -> None:
        if route.config_mode == "PROXY" and route.input_schema is not None:
            # Publish the upstream's own JSON Schema verbatim instead of
            # rebuilding one from `route.params` -- see UpstreamProxyTool.
            # Arbitrary argument names (not valid Python identifiers, or
            # reserved keywords like ``from``) are fine here: there is no
            # Python function signature to build.
            from keystone_mcp.router.proxy_tool import UpstreamProxyTool

            # Build the replacement *before* touching FastMCP's own storage:
            # if this raises (e.g. a malformed ``annotations`` patch), nothing
            # below runs, so a route that is being updated keeps whatever it
            # had published before -- the same atomicity ``add_route`` already
            # guarantees around this call (see its docstring).
            tool = UpstreamProxyTool.for_route(route, self._engine)
            try:
                mcp.local_provider.remove_tool(route.name)
            except KeyError:
                pass  # first registration, nothing to replace
            mcp.add_tool(tool)
            return
        handler = self._make_handler(route)
        tool_kwargs: dict[str, Any] = {
            "name": route.name,
            "description": route.description or None,
        }
        if route.tags:
            tool_kwargs["tags"] = set(route.tags)
        if route.meta:
            tool_kwargs["meta"] = route.meta
        mcp.tool(**tool_kwargs)(handler)

    def _make_handler(self, route: Route):
        engine = self._engine

        async def handler(**kwargs: Any) -> dict[str, Any]:
            try:
                return await engine.execute(route, kwargs)
            except UnauthorizedError as exc:
                return {"state": "error", "code": "unauthorized", "message": str(exc)}

        sig_params = []
        annotations: dict[str, Any] = {}
        for p in route.params:
            default = inspect.Parameter.empty if p.required else p.default
            sig_params.append(
                inspect.Parameter(
                    p.name,
                    inspect.Parameter.KEYWORD_ONLY,
                    default=default,
                    annotation=p.type,
                )
            )
            annotations[p.name] = p.type
        annotations["return"] = dict
        handler.__signature__ = inspect.Signature(sig_params)
        handler.__annotations__ = annotations
        handler.__name__ = route.name
        handler.__doc__ = route.description or None
        return handler
