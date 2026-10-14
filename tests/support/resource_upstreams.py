"""Low-level upstream apps with configurable resources and templates (C02 tests)."""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator, Callable, Sequence

import httpx2
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send

from support.lowlevel_upstream import _TOOL_DEFINITIONS, UPSTREAM_BASE_URL

HELLO_UPSTREAM_MCP_URL = f"{UPSTREAM_BASE_URL}/hello/mcp"
EVIL_UPSTREAM_MCP_URL = f"{UPSTREAM_BASE_URL}/evil/mcp"


def build_resource_upstream_app(
    *,
    resources: Sequence[types.Resource] | None = None,
    templates: Sequence[types.ResourceTemplate] | None = None,
    read_text: Callable[[str], str] | None = None,
) -> Starlette:
    """Minimal MCP server exposing only resource catalog handlers."""

    resource_list = list(resources or ())
    template_list = list(templates or ())

    def _default_read(uri: str) -> str:
        return f"body:{uri}"

    reader = read_text or _default_read

    async def _on_list_tools(_ctx: object, _params: object) -> types.ListToolsResult:
        return types.ListToolsResult(
            tools=[_TOOL_DEFINITIONS["greet"]],
        )

    async def _on_call_tool(
        _ctx: object, params: types.CallToolRequestParams
    ) -> types.CallToolResult:
        if params.name != "greet":
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"unknown tool: {params.name}")],
                is_error=True,
            )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="Hello, world!")],
        )

    async def _on_list_resources(
        _ctx: object, _params: types.PaginatedRequestParams | None
    ) -> types.ListResourcesResult:
        return types.ListResourcesResult(resources=list(resource_list))

    async def _on_list_resource_templates(
        _ctx: object, _params: types.PaginatedRequestParams | None
    ) -> types.ListResourceTemplatesResult:
        return types.ListResourceTemplatesResult(resource_templates=list(template_list))

    async def _on_read_resource(
        _ctx: object, params: types.ReadResourceRequestParams
    ) -> types.ReadResourceResult:
        uri = str(params.uri)
        text = reader(uri)
        return types.ReadResourceResult(
            contents=[
                types.TextResourceContents(
                    uri=uri,
                    text=text,
                    mime_type="text/plain",
                )
            ]
        )

    server = Server(
        "resource-upstream",
        on_list_tools=_on_list_tools,
        on_call_tool=_on_call_tool,
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


def mount_resource_upstream_apps(apps_by_prefix: dict[str, Starlette]) -> Starlette:
    """Combine several upstream Starlette apps under ``/<prefix>/mcp``."""

    @contextlib.asynccontextmanager
    async def _combined_lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with contextlib.AsyncExitStack() as stack:
            for sub_app in apps_by_prefix.values():
                lifespan = sub_app.router.lifespan_context
                if lifespan is not None:
                    await stack.enter_async_context(lifespan(sub_app))
            yield

    return Starlette(
        routes=[Mount(f"/{prefix}", app=app) for prefix, app in apps_by_prefix.items()],
        lifespan=_combined_lifespan,
    )


def asgi_routed_http_client_factory(
    router_app: Starlette,
    *,
    streaming: bool = False,
) -> Callable[[float], Callable[..., httpx2.AsyncClient]]:
    """Like ``asgi_http_client_factory`` but for a multi-upstream router."""

    def builder(timeout_seconds: float) -> Callable[..., httpx2.AsyncClient]:
        httpx_timeout = timeout_seconds + (5.0 if streaming else 0.0)

        def factory(
            headers: dict[str, str] | None = None,
            timeout: object = None,  # noqa: ARG001
            auth: object = None,
            **_kwargs: object,
        ) -> httpx2.AsyncClient:
            if streaming:
                from fastmcp.utilities.asgi_transport import StreamingASGITransport

                transport: httpx2.AsyncBaseTransport = StreamingASGITransport(app=router_app)
            else:
                transport = httpx2.ASGITransport(app=router_app)
            return httpx2.AsyncClient(
                transport=transport,
                base_url=UPSTREAM_BASE_URL,
                headers=headers,
                timeout=httpx2.Timeout(httpx_timeout),
                auth=auth,
                follow_redirects=False,
            )

        return factory

    return builder
