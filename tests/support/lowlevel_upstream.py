"""A test upstream built on the low-level MCP SDK, not FastMCP.

FastMCP wraps every tool answer in ``structuredContent`` and builds a tidy
``inputSchema`` for its own tools, which hides two bugs in the proxy:

- an ``inputSchema`` with an optional property declared before a required one
  (perfectly valid JSON Schema) breaks route registration;
- a tool that answers with plain text (not JSON) cannot be parsed back by the
  proxy.

Servers built on the TypeScript SDK, the Go SDK, or this low-level Python SDK
all behave this way. This module stands in for one of them in proxy tests, so
it imports only ``mcp``, ``starlette``, and ``httpx`` — never that other
Python framework.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import time
from collections.abc import AsyncIterator, Callable, Collection
from typing import Any

import anyio
import httpx2
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp_types.version import MODERN_PROTOCOL_VERSIONS
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

#: In-process base URL used by :func:`asgi_http_client_factory` clients.
UPSTREAM_BASE_URL = "http://upstream.test"
UPSTREAM_MCP_URL = "http://upstream.test/mcp"

# Smallest possible PNG payload (just the file signature). Its bytes are
# opaque to the tests; only the content block's shape (type, mimeType) and
# that it survives the round trip matter.
_PNG_BYTES = b"\x89PNG\r\n\x1a\n"

GREET_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Who to greet"},
    },
    "required": ["name"],
}

#: Property order is deliberate: the optional ``limit`` sits before the
#: required ``filter``. Valid JSON Schema, and exactly what a foreign SDK may
#: emit — the proxy must not assume required properties come first.
SEARCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "description": "Search query text"},
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 50,
            "default": 10,
        },
        "filter": {"type": "string", "enum": ["all", "mine"]},
    },
    "required": ["query", "filter"],
}

_EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}

#: ``from`` is a Python keyword and ``max-results`` is not a legal Python
#: identifier. Before P07 the proxy built a handler's Python function
#: signature from the schema, so a tool like this could never be published at
#: all ("ghost tool", FX-proxy #1); publishing the upstream's own raw schema
#: sidesteps that -- there is no signature to build.
ODD_NAMES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "from": {"type": "string", "description": "Sender address"},
        "max-results": {"type": "integer", "default": 5},
    },
    "required": ["from"],
}

#: A tool that reports progress while it runs, to exercise progress while it runs, to exercise
#: ``notifications/progress`` forwarding. ``steps`` is keyword-only from the
#: caller's point of view (JSON Schema has no positional arguments).
COUNT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "steps": {"type": "integer", "default": 3},
    },
}

SLOW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "tag": {"type": "string", "default": ""},
    },
}

ASK_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "ok": {"type": "boolean"},
        "choice": {"type": "string", "enum": ["a", "b"], "default": "a"},
    },
    "required": ["ok"],
}

ASK_WEIRD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"x": {"type": ["string", "null"]}},
}

_EMPTY_ASK_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}

_TOOL_DEFINITIONS: dict[str, types.Tool] = {
    "greet": types.Tool(
        name="greet",
        description="Greet someone by name.",
        inputSchema=GREET_SCHEMA,
    ),
    "search": types.Tool(
        name="search",
        description="Search documents.",
        inputSchema=SEARCH_SCHEMA,
    ),
    "report": types.Tool(
        name="report",
        description="Build a short multi-block report.",
        inputSchema=_EMPTY_SCHEMA,
    ),
    "fail": types.Tool(
        name="fail",
        description="Always fails, to exercise upstream error propagation.",
        inputSchema=_EMPTY_SCHEMA,
    ),
    "whoami": types.Tool(
        name="whoami",
        description="Echo the request headers the upstream received.",
        inputSchema=_EMPTY_SCHEMA,
    ),
    "odd_names": types.Tool(
        name="odd_names",
        description="Echo arguments whose names are not Python identifiers.",
        inputSchema=ODD_NAMES_SCHEMA,
    ),
    "count": types.Tool(
        name="count",
        description="Count to `steps`, reporting progress along the way.",
        inputSchema=COUNT_SCHEMA,
    ),
    "slow": types.Tool(
        name="slow",
        description="Sleep for a long time; used to exercise cancellation.",
        inputSchema=SLOW_SCHEMA,
    ),
    "ask": types.Tool(
        name="ask",
 description="Ask the client a form question (elicitation tests).",
        inputSchema=_EMPTY_ASK_SCHEMA,
    ),
    "ask_url": types.Tool(
        name="ask_url",
        description="Ask the client via URL elicitation (declined by Keystone).",
        inputSchema=_EMPTY_ASK_SCHEMA,
    ),
    "ask_weird": types.Tool(
        name="ask_weird",
        description="Ask with a schema json_schema_to_type cannot parse.",
        inputSchema=_EMPTY_ASK_SCHEMA,
    ),
}

#: ``list_tools`` publishes tools in this order when all of them are selected.
#: ``count`` is deliberately excluded from the *default* selection (``tools=None``
#: below) so the long-standing tool count every existing test asserts does not
#: shift just because progress tooling was added; pass it explicitly via ``tools`` or
#: ``extra_tools`` to include it.
_TOOL_ORDER: tuple[str, ...] = ("greet", "search", "report", "fail", "whoami", "odd_names")


def build_lowlevel_upstream_app(
    *,
    tools: Collection[str] | None = None,
    extra_tools: Collection[str] | None = None,
    prompts: bool = False,
    resources: bool = False,
    observed: dict[str, Any] | None = None,
    require_bearer: str | None = None,
    stateless: bool = True,
    json_response: bool = True,
) -> Starlette:
    """Build a Starlette app around a low-level ``mcp.server.lowlevel.Server``.

    ``tools`` restricts which tools are registered (default: the original six
    -- ``count`` is not one of them, see ``_TOOL_ORDER``), so a test can
    target one tool without depending on fixes the others still need.
    ``extra_tools`` adds tools on top of the default six without changing it
    (e.g. ``extra_tools={"count"}``). ``observed``, when given, receives the
    last call's request headers (lower-cased keys) under
    ``observed["headers"]`` — written by the ``whoami`` tool — and, for a
    tokenless ``count`` call, ``observed["progress_token"] = None``.

    ``require_bearer``, when given, makes both ``list_tools`` and
    ``call_tool`` reject a request whose ``Authorization`` header is not
    exactly ``Bearer <require_bearer>`` — standing in for a real upstream that
    requires Keystone's ``auth.bearer_env`` token (P08). A ``list_tools``
    rejection surfaces to the caller as a failed discovery; a ``call_tool``
    rejection surfaces as an error ``CallToolResult`` (the low-level SDK's
    call-tool wrapper always turns a raised exception into one, the same way
    the ``fail`` tool below does).

    ``stateless`` and ``json_response`` are passed straight through to
 ``StreamableHTTPSessionManager`` (default: unchanged from before progress forwarding landed). A
    progress notification can only reach the client before the final response
    when ``json_response=False`` -- a ``json_response=True`` session buffers
    the whole answer and sends it as one JSON body, on both protocol eras.

    ``StreamableHTTPSessionManager.run()`` can only be entered once per
    instance, so call this again to get a fresh app for each test.
    """
    selected = set(_TOOL_ORDER) if tools is None else set(tools)
    if extra_tools:
        selected |= set(extra_tools)
    unknown = selected - set(_TOOL_DEFINITIONS)
    if unknown:
        raise ValueError(f"unknown tool(s): {sorted(unknown)}")

    # The low-level SDK v2 `Server` no longer takes handlers via the
    # `@server.list_tools()` / `@server.call_tool()` decorators (removed); it
    # takes `on_list_tools` / `on_call_tool` in its constructor instead, each
    # called as `(ctx, params) -> result`. The old decorator-based `Server`
    # also turned a raised exception into an error `CallToolResult`
    # automatically; SDK v2's low-level `Server` does not (only the separate,
    # higher-level `mcp.server.mcpserver` does), so `_on_call_tool` below does
    # that wrapping itself to keep the `fail` tool and the bearer check
    # behaving the same as before.

    def _check_bearer(ctx: Any) -> None:
        if require_bearer is None:
            return
        request = ctx.request
        headers = {k.lower(): v for k, v in request.headers.items()} if request else {}
        if headers.get("authorization") != f"Bearer {require_bearer}":
            raise PermissionError("missing or invalid bearer token")

    async def _on_list_tools(ctx: Any, _params: Any) -> types.ListToolsResult:
        _check_bearer(ctx)
        # Ordered by _TOOL_DEFINITIONS' own (insertion) order, not _TOOL_ORDER,
        # so an explicitly-selected tool outside the default six (e.g. just
        # {"count"}) is still found.
        tools = [_TOOL_DEFINITIONS[name] for name in _TOOL_DEFINITIONS if name in selected]
        return types.ListToolsResult(tools=tools)

    async def _run_tool(ctx: Any, name: str, arguments: dict[str, Any]) -> list[types.ContentBlock]:
        if name == "greet":
            if observed is not None:
                request = ctx.request
                headers = {k.lower(): v for k, v in request.headers.items()} if request else {}
                observed["headers"] = headers
            return [types.TextContent(type="text", text=f"Hello, {arguments['name']}!")]

        if name == "search":
            query = arguments["query"]
            tool_filter = arguments["filter"]
            limit = arguments.get("limit")
            return [
                types.TextContent(
                    type="text",
                    text=f"Found 3 documents for '{query}' (filter={tool_filter}, limit={limit})",
                )
            ]

        if name == "report":
            return [
                types.TextContent(type="text", text="Summary: 2 items"),
                types.TextContent(type="text", text="Details: a, b"),
                types.ImageContent(
                    type="image",
                    data=base64.b64encode(_PNG_BYTES).decode("ascii"),
                    mimeType="image/png",
                ),
            ]

        if name == "fail":
            raise ValueError("upstream failure: quota exceeded")

        if name == "odd_names":
            sender = arguments["from"]
            max_results = arguments.get("max-results")
            return [
                types.TextContent(
                    type="text",
                    text=f"from={sender} max-results={max_results}",
                )
            ]

        if name == "whoami":
            request = ctx.request
            headers = {k.lower(): v for k, v in request.headers.items()} if request else {}
            if observed is not None:
                observed["headers"] = headers
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "x-author-email": headers.get("x-author-email"),
                            "authorization": headers.get("authorization"),
                        }
                    ),
                )
            ]

        if name == "slow":
            tag = arguments.get("tag", "")
            if observed is not None:
                observed["slow_running"] = observed.get("slow_running", 0) + 1
                started = observed.get("slow_started")
                if isinstance(started, asyncio.Event):
                    started.set()
            try:
                await anyio.sleep(30)
            except anyio.get_cancelled_exc_class():
                if observed is not None:
                    observed["slow_cancelled_at"] = time.monotonic()
                    observed.setdefault("slow_cancelled_tags", []).append(tag)
                raise
            finally:
                if observed is not None:
                    observed["slow_running"] = max(0, observed.get("slow_running", 1) - 1)
            return [types.TextContent(type="text", text=f"slow done {tag}")]

        if name == "count":
            steps = arguments.get("steps", 3)
            # ServerRequestContext.meta is the SDK's own RequestParamsMeta --
            # unlike the client-side request context's raw wire _meta dict,
            # it is validated and its key is already snake_case regardless of
            # the wire's camelCase progressToken (mcp_types/_types.py,
            # RequestParamsMeta).
            token = ctx.meta.get("progress_token") if ctx.meta else None
            if token is not None:
                for i in range(1, steps + 1):
                    await ctx.session.report_progress(i, steps, f"step {i}")
            elif observed is not None:
                observed["progress_token"] = None
            return [types.TextContent(type="text", text=f"counted {steps}")]

        raise ValueError(f"unknown tool: {name}")

    def _client_supports_elicitation(ctx: Any) -> bool:
        return ctx.session.check_client_capability(
            types.ClientCapabilities(
                elicitation=types.ElicitationCapability(
                    form=types.FormElicitationCapability(),
                )
            )
        )

    def _format_elicit_answer(result: types.ElicitResult) -> str:
        content = result.content
        if isinstance(content, dict):
            payload = json.dumps(content, sort_keys=True)
        elif content is None:
            payload = ""
        else:
            payload = str(content)
        return f"answer={result.action}:{payload}"

    async def _ask_tool(
        ctx: Any,
        params: types.CallToolRequestParams,
        *,
        schema: dict[str, Any],
        url_mode: bool = False,
    ) -> types.CallToolResult | types.InputRequiredResult:
        if not _client_supports_elicitation(ctx):
            return types.CallToolResult(
                content=[types.TextContent(type="text", text="no-elicitation")],
            )

        modern = ctx.protocol_version in MODERN_PROTOCOL_VERSIONS
        if modern:
            if params.input_responses is None:
                if url_mode:
                    request = types.ElicitRequest(
                        params=types.ElicitRequestURLParams(
                            message="Proceed?",
                            url="https://upstream.test/confirm",
                        )
                    )
                else:
                    request = types.ElicitRequest(
                        params=types.ElicitRequestFormParams(
                            message="Proceed?",
                            requested_schema=schema,
                        )
                    )
                return types.InputRequiredResult(input_requests={"q": request})
            response = params.input_responses.get("q")
            if not isinstance(response, types.ElicitResult):
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text="no-answer")],
                    is_error=True,
                )
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=_format_elicit_answer(response))],
            )

        if url_mode:
            result = await ctx.session.elicit_url(
                "Proceed?",
                "https://upstream.test/confirm",
                related_request_id=ctx.request_id,
            )
        else:
            result = await ctx.session.elicit_form(
                "Proceed?",
                schema,
                related_request_id=ctx.request_id,
            )
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=_format_elicit_answer(result))],
        )

    async def _on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
        try:
            _check_bearer(ctx)
            if params.name == "ask":
                asked = await _ask_tool(ctx, params, schema=ASK_SCHEMA)
                if isinstance(asked, types.InputRequiredResult):
                    return asked
                return asked
            if params.name == "ask_url":
                asked = await _ask_tool(ctx, params, schema=ASK_SCHEMA, url_mode=True)
                if isinstance(asked, types.InputRequiredResult):
                    return asked
                return asked
            if params.name == "ask_weird":
                asked = await _ask_tool(ctx, params, schema=ASK_WEIRD_SCHEMA)
                if isinstance(asked, types.InputRequiredResult):
                    return asked
                return asked
            content = await _run_tool(ctx, params.name, params.arguments or {})
        except Exception as exc:  # noqa: BLE001 — mirrors the old SDK's auto-wrap
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(exc))],
                is_error=True,
            )
        return types.CallToolResult(content=content)

    async def _on_list_prompts(
        ctx: Any, _params: types.PaginatedRequestParams | None
    ) -> types.ListPromptsResult:
        _check_bearer(ctx)
        if observed is not None:
            observed["list_prompts_calls"] = observed.get("list_prompts_calls", 0) + 1
        return types.ListPromptsResult(
            prompts=[
                types.Prompt(
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
            ]
        )

    async def _on_get_prompt(
        ctx: Any, params: types.GetPromptRequestParams
    ) -> types.GetPromptResult:
        _check_bearer(ctx)
        request = ctx.request
        headers = {k.lower(): v for k, v in request.headers.items()} if request else {}
        if observed is not None:
            observed["prompt_headers"] = headers
            meta = getattr(params, "meta", None)
            if meta is not None:
                observed["prompt_meta"] = dict(meta)
            else:
                observed["prompt_meta"] = {}
        topic = (params.arguments or {}).get("topic", "")
        return types.GetPromptResult(
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(type="text", text=f"Summarize {topic}"),
                )
            ]
        )

    server_kwargs: dict[str, Any] = {
        "on_list_tools": _on_list_tools,
        "on_call_tool": _on_call_tool,
    }

    async def _on_list_resources(
        ctx: Any, _params: types.PaginatedRequestParams | None
    ) -> types.ListResourcesResult:
        _check_bearer(ctx)
        if observed is not None:
            observed["list_resources_calls"] = observed.get("list_resources_calls", 0) + 1
        return types.ListResourcesResult(
            resources=[
                types.Resource(
                    uri="file:///handbook.md",
                    name="handbook",
                    description="Handbook",
                    mime_type="text/plain",
                )
            ]
        )

    async def _on_list_resource_templates(
        ctx: Any, _params: types.PaginatedRequestParams | None
    ) -> types.ListResourceTemplatesResult:
        _check_bearer(ctx)
        return types.ListResourceTemplatesResult(
            resource_templates=[
                types.ResourceTemplate(
                    uri_template="notes://items/{id}",
                    name="note",
                    description="Note item",
                    mime_type="text/plain",
                )
            ]
        )

    async def _on_read_resource(
        ctx: Any, params: types.ReadResourceRequestParams
    ) -> types.ReadResourceResult:
        _check_bearer(ctx)
        request = ctx.request
        headers = {k.lower(): v for k, v in request.headers.items()} if request else {}
        if observed is not None:
            observed["resource_headers"] = headers
            meta = getattr(params, "meta", None)
            observed["resource_meta"] = dict(meta) if meta is not None else {}
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
                types.TextResourceContents(
                    uri=uri,
                    text=text,
                    mime_type="text/plain",
                )
            ]
        )

    if prompts:
        server_kwargs["on_list_prompts"] = _on_list_prompts
        server_kwargs["on_get_prompt"] = _on_get_prompt
    if resources:
        server_kwargs["on_list_resources"] = _on_list_resources
        server_kwargs["on_list_resource_templates"] = _on_list_resource_templates
        server_kwargs["on_read_resource"] = _on_read_resource

    server: Server = Server("hello-upstream", **server_kwargs)

    manager = StreamableHTTPSessionManager(
        app=server, stateless=stateless, json_response=json_response
    )

    class _McpEndpoint:
        """Raw ASGI endpoint handing the request straight to the session manager.

        Deliberately mounted via ``Route``, not ``Mount``: ``Mount`` redirects a
        bare ``/mcp`` request to ``/mcp/`` with a 307, and the MCP client does
        not follow it.
        """

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
    max_response_bytes: int | None = None,
) -> Callable[[float], Callable[..., httpx2.AsyncClient]]:
    """``HttpClientFactoryBuilder`` that routes every request into *app* in-process.

    Mirrors the shape of ``keystone_mcp.adapters.mcp_proxy._http_client_factory``:
    the returned builder is called with a resolved per-call timeout (seconds)
    and produces the actual http client factory, which always uses that
    timeout and ignores whatever timeout the caller passed in.

    The client handed to the proxy client's HTTP transport (MCP SDK 2 era)
    must be an ``httpx2.AsyncClient`` -- an ``httpx.AsyncClient`` rejects the
    ``auth`` object that transport passes in with ``TypeError``.
    """

    def builder(timeout_seconds: float) -> Callable[..., httpx2.AsyncClient]:
        # Keep the socket read budget above the MCP call timeout so courtesy
 # cancel can be sent before httpx2 gives up (timeout test).
        httpx_timeout = timeout_seconds + (5.0 if streaming else 0.0)

        def factory(
            headers: dict[str, str] | None = None,
            timeout: Any = None,  # noqa: ARG001 — superseded by timeout_seconds
            auth: Any = None,
            **_kwargs: Any,
        ) -> httpx2.AsyncClient:
            if streaming:
                from fastmcp.utilities.asgi_transport import StreamingASGITransport

                transport: httpx2.AsyncBaseTransport = StreamingASGITransport(app=app)
            else:
                transport = httpx2.ASGITransport(app=app)
            if max_response_bytes is not None:
                from keystone_mcp.adapters.mcp_proxy import limit_response_size

                transport = limit_response_size(transport, max_response_bytes)
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
