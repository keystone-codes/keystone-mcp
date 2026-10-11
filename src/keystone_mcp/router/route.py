"""Route descriptor.

Each MCP tool is one Route:

    name       tool name the agent sees
    inbound    parameter signature + Model M pattern + response contract
    target     the adapter the call is dispatched to
    transform  optional transform(ctx, args) -> outbound request/payload;
               if None, passthrough 1:1 (bypass)
    mode       "stub" | "live", per-route enable switch
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Literal

from keystone_mcp.adapters.base import Pattern

if TYPE_CHECKING:
    from keystone_mcp.adapters.base import Adapter
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.registry import Param

Transform = Callable[["RouteContext", dict[str, Any]], Any]
Mode = Literal["stub", "live"]
ConfigMode = Literal["PROXY", "TRANSFORM", "HTTP_METHOD_MAP"]


@dataclass
class Route:
    name: str
    target: "Adapter"
    pattern: Pattern = Pattern.M_B
    params: list["Param"] = field(default_factory=list)
    description: str = ""
    transform: Transform | None = None
    mode: Mode = "stub"
    admin: bool = False  # catalog metadata: administrative scope, not a gate
    upstream_tool: str | None = None
    namespace: str | None = None
    config_mode: ConfigMode | None = None
    tags: frozenset[str] = field(default_factory=frozenset)
    meta: dict[str, Any] = field(default_factory=dict)
    # The upstream's own inputSchema/outputSchema/title/annotations (P07),
    # published verbatim via UpstreamProxyTool -- never rebuilt from `params`.
    # `output_schema`, `title` and `annotations` are the upstream's raw values;
    # whether `output_schema` actually reaches the client (transparent mode
    # only, see UpstreamProxyTool.for_route) is decided at publish time, not
    # stored here, so this field stays a stable signal for fingerprinting.
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    title: str | None = None
    annotations: dict[str, Any] | None = None

    @property
    def published_name(self) -> str:
        """Client-visible tool name after FastMCP mount namespace prefixing."""
        if self.namespace:
            return f"{self.namespace}_{self.name}"
        return self.name

    @property
    def route_key(self) -> str:
        """Unique registry key (avoids collisions across upstream namespaces)."""
        if self.namespace:
            return f"{self.namespace}:{self.name}"
        return self.name
