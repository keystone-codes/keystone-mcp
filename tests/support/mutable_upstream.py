"""Test upstream whose prompts/resources catalog can change between reconciler ticks."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx2
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from support.lowlevel_upstream import GREET_SCHEMA, UPSTREAM_BASE_URL, UPSTREAM_MCP_URL

__all__ = [
    "MutableUpstreamCatalog",
    "UPSTREAM_BASE_URL",
    "UPSTREAM_MCP_URL",
    "asgi_http_client_factory",
    "build_mutable_upstream_app",
]


@dataclass
class MutableUpstreamCatalog:
    tools: list[str] = field(default_factory=lambda: ["greet"])
    prompts: list[types.Prompt] | None = field(default_factory=lambda: [_default_prompt()])
    resources: list[types.Resource] | None = field(default_factory=lambda: [_default_resource()])
    templates: list[types.ResourceTemplate] | None = field(
        default_factory=lambda: [_default_template()]
    )
    fail_prompts_list: bool = False
    fail_resources_list: bool = False
    fail_templates_list: bool = False


def _default_prompt() -> types.Prompt:
    return types.Prompt(
        name="summarize",
        description="Summarize a topic.",
        arguments=[
            types.PromptArgument(
                name="topic",
                description="Topic to summarize",
                required=True,
            )
        ],
    )


def _default_resource() -> types.Resource:
    return types.Resource(
        uri="file:///handbook.md",
        name="handbook",
        description="Handbook",
        mime_type="text/plain",
    )


def _default_template() -> types.ResourceTemplate:
    return types.ResourceTemplate(
        uri_template="notes://items/{id}",
        name="note",
        description="Note item",
        mime_type="text/plain",
    )


def build_mutable_upstream_app(
    catalog: MutableUpstreamCatalog,
    *,
    observed: dict[str, Any] | None = None,
) -> Starlette:
    async def _on_list_tools(
        ctx: Any, _params: types.PaginatedRequestParams | None
    ) -> types.ListToolsResult:
        tool_defs = []
        for name in catalog.tools:
            if name == "greet":
                tool_defs.append(
                    types.Tool(name="greet", description="Greet", inputSchema=GREET_SCHEMA)
                )
            else:
                tool_defs.append(
                    types.Tool(
                        name=name,
                        description=name,
                        inputSchema={"type": "object", "properties": {}},
                    )
                )
        return types.ListToolsResult(tools=tool_defs)

    async def _on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        if params.name == "greet":
            name = (params.arguments or {}).get("name", "world")
            content = [types.TextContent(type="text", text=f"Hello, {name}!")]
        else:
            content = [types.TextContent(type="text", text=params.name)]
        return types.CallToolResult(content=content)

    async def _on_list_prompts(
        ctx: Any, _params: types.PaginatedRequestParams | None
    ) -> types.ListPromptsResult:
        if observed is not None:
            observed["list_prompts_calls"] = observed.get("list_prompts_calls", 0) + 1
        if catalog.fail_prompts_list:
            raise RuntimeError("prompts list failed")
        if catalog.prompts is None:
            return types.ListPromptsResult(prompts=[])
        return types.ListPromptsResult(prompts=list(catalog.prompts))

    async def _on_get_prompt(
        ctx: Any, params: types.GetPromptRequestParams
    ) -> types.GetPromptResult:
        if observed is not None:
            request = ctx.request
            headers = {k.lower(): v for k, v in request.headers.items()} if request else {}
            observed["prompt_headers"] = headers
        topic = (params.arguments or {}).get("topic", "")
        return types.GetPromptResult(
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(type="text", text=f"Summarize {topic}"),
                )
            ]
        )

    async def _on_list_resources(
        ctx: Any, _params: types.PaginatedRequestParams | None
    ) -> types.ListResourcesResult:
        if observed is not None:
            observed["list_resources_calls"] = observed.get("list_resources_calls", 0) + 1
        if catalog.fail_resources_list:
            raise RuntimeError("resources list failed")
        if catalog.resources is None:
            return types.ListResourcesResult(resources=[])
        return types.ListResourcesResult(resources=list(catalog.resources))

    async def _on_list_resource_templates(
        ctx: Any, _params: types.PaginatedRequestParams | None
    ) -> types.ListResourceTemplatesResult:
        if catalog.fail_templates_list:
            raise RuntimeError("templates list failed")
        if catalog.templates is None:
            return types.ListResourceTemplatesResult(resource_templates=[])
        return types.ListResourceTemplatesResult(resource_templates=list(catalog.templates))

    async def _on_read_resource(
        ctx: Any, params: types.ReadResourceRequestParams
    ) -> types.ReadResourceResult:
        uri = str(params.uri)
        if uri == "file:///handbook.md":
            text = "Handbook"
        elif uri.startswith("notes://items/"):
            item_id = uri.rsplit("/", 1)[-1]
            text = f"Note {item_id}"
        else:
            raise ValueError(f"unknown resource: {uri}")
        return types.ReadResourceResult(
            contents=[
                types.TextResourceContents(uri=uri, text=text, mime_type="text/plain"),
            ]
        )

    server: Server = Server(
        "mutable-upstream",
        on_list_tools=_on_list_tools,
        on_call_tool=_on_call_tool,
        on_list_prompts=_on_list_prompts,
        on_get_prompt=_on_get_prompt,
        on_list_resources=_on_list_resources,
        on_list_resource_templates=_on_list_resource_templates,
        on_read_resource=_on_read_resource,
    )

    manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)

    class _McpEndpoint:
        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            await manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def _lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with manager.run():
            yield

    return Starlette(
        routes=[Route("/mcp", endpoint=_McpEndpoint(), methods=["GET", "POST", "DELETE"])],
        lifespan=_lifespan,
    )


def asgi_http_client_factory(
    app: Starlette,
    *,
    streaming: bool = False,
) -> Callable[[float], Callable[..., httpx2.AsyncClient]]:
    from support.lowlevel_upstream import asgi_http_client_factory as _base

    return _base(app, streaming=streaming)
