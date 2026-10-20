"""hello-upstream: a tiny demo MCP server for Keystone-MCP's docker-compose demo.

Built on the low-level ``mcp`` SDK, not FastMCP: FastMCP wraps every tool
answer in ``structuredContent`` and builds a tidy ``inputSchema``, which would
hide exactly the kind of server this demo wants to show -- one whose schema
puts an optional property before a required one (perfectly valid JSON Schema,
and something many non-Python MCP servers produce) and whose tools answer
with plain text. This module imports only ``mcp``, ``starlette``, ``uvicorn``
and ``pyjwt`` (via ``keystone_identity.py`` below) -- never that other Python
framework.

This file is a standalone copy of the two original demo tools (``greet``,
``search``) from ``tests/support/lowlevel_upstream.py`` (the proxy test
fixture), wired up as a real HTTP server instead of an in-process ASGI app,
plus a third tool (``whoami``) added to show ``X-Keystone-Identity``
verification. See that module for the test-only variant, and ``README.md``
here for what the tools are for.

The container (``Dockerfile``) pins MCP Python SDK 1.x on purpose, and this
file is written against that SDK's decorator-based ``Server`` API
(``@server.list_tools()``, ``@server.call_tool()``). Keystone-MCP's own test
suite imports this same file under its *own* dependencies, which are SDK 2.x
(``mcp>=2,<3``) -- a different, constructor-based API
(``on_list_tools=...``, ``on_call_tool=...``) with no decorators at all. Both
branches below share the same tool logic (``_run_tool``); ``_build_server``
just picks whichever registration style the installed SDK supports.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from typing import Any

import anyio
import uvicorn

# Copied verbatim from examples/keystone-identity/python/keystone_identity.py
# (not installed as a package -- tests/test_identity_examples.py pins this
# file byte-for-byte equal to that original so the two copies never drift
# apart). Verifies X-Keystone-Identity exactly the way any other upstream
# service would, following docs/connecting-services.md.
from keystone_identity import IdentityError, KeystoneIdentity, verify_keystone_identity
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

try:
    from mcp_types.version import MODERN_PROTOCOL_VERSIONS
except ImportError:  # pragma: no cover -- MCP SDK 1.x in the demo image
    MODERN_PROTOCOL_VERSIONS = frozenset()

# ``InputRequiredResult`` exists only in MCP Python SDK 2.x; the demo Docker
# image deliberately stays on 1.x (see ``Dockerfile``).
_InputRequiredResult = getattr(types, "InputRequiredResult", None)


def _is_input_required_result(result: object) -> bool:
    return _InputRequiredResult is not None and isinstance(result, _InputRequiredResult)


HOST = "0.0.0.0"
PORT = 8081

#: Set this to make the demo verify X-Keystone-Identity instead of trusting
#: the unsigned, deprecated X-Author-Email outright. Unset (the 0.4.0
#: behaviour) by default so the demo keeps working without it. Named without
#: the KEYSTONE_MCP_ prefix: this is hello-upstream's own setting, not
#: Keystone-MCP's.
HELLO_IDENTITY_SECRET = os.environ.get("HELLO_IDENTITY_SECRET", "").strip()

#: This upstream's own registry entry name -- the assertion's ``aud``.
HELLO_IDENTITY_AUDIENCE = os.environ.get("HELLO_IDENTITY_AUDIENCE", "hello").strip()
HELLO_IDENTITY_ISSUER = os.environ.get("HELLO_IDENTITY_ISSUER", "").strip()


def _otel_export_configured() -> bool:
    return bool(os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip())


def _configure_otel_provider_once() -> None:
    if not _otel_export_configured():
        return
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        return
    existing = trace.get_tracer_provider()
    if isinstance(existing, TracerProvider):
        return
    service_name = os.environ.get("OTEL_SERVICE_NAME", "hello-upstream")
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)


@contextmanager
def _hello_tool_span(tool_name: str, headers: dict[str, str] | None = None):
    if not _otel_export_configured():
        yield
        return
    try:
        from opentelemetry import context as otel_context
        from opentelemetry import trace
        from opentelemetry.propagate import extract
    except ImportError:
        yield
        return
    tracer = trace.get_tracer("hello-upstream")
    carrier = dict(headers or {})
    token = otel_context.attach(extract(carrier))
    try:
        with tracer.start_as_current_span(f"hello.{tool_name}"):
            yield
    finally:
        otel_context.detach(token)


class _HelloTracingMiddleware:
    """Extract W3C trace context from inbound HTTP (when OTLP export is configured)."""

    def __init__(self, app: Callable) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http" or not _otel_export_configured():
            await self.app(scope, receive, send)
            return
        try:
            from opentelemetry import context as otel_context
            from opentelemetry.propagate import extract
        except ImportError:
            await self.app(scope, receive, send)
            return
        headers = {
            name.decode("latin-1").lower(): value.decode("latin-1")
            for name, value in scope.get("headers") or []
        }
        token = otel_context.attach(extract(headers))
        try:
            await self.app(scope, receive, send)
        finally:
            otel_context.detach(token)


GREET_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Who to greet"},
    },
    "required": ["name"],
}

#: Property order is deliberate: the optional ``limit`` sits before the
#: required ``filter``. Valid JSON Schema, and exactly what a foreign SDK may
#: emit -- Keystone-MCP's proxy must not assume required properties come
#: first.
SEARCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "description": "Search query text"},
        "limit": {
            "type": "integer",
            "minimum": 1,
            "maximum": 50,
            "default": 5,
            "description": "How many results to return",
        },
        "filter": {"type": "string", "enum": ["all", "mine"]},
    },
    "required": ["query", "filter"],
}

SLOW_COUNT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "n": {
            "type": "integer",
            "minimum": 1,
            "maximum": 120,
            "description": "Count up to n, reporting progress once per second",
        },
    },
    "required": ["n"],
}

ASK_NAME_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "name": {"type": "string", "description": "Your name"},
    },
    "required": ["name"],
}

_EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}

_TOOLS: list[types.Tool] = [
    types.Tool(name="greet", description="Greet someone by name.", inputSchema=GREET_SCHEMA),
    types.Tool(name="search", description="Search documents.", inputSchema=SEARCH_SCHEMA),
    types.Tool(
        name="whoami",
        description="Return the verified caller identity, if X-Keystone-Identity checking is on.",
        inputSchema=_EMPTY_SCHEMA,
    ),
    types.Tool(
        name="slow_count",
        description="Count up to n with progress notifications; respects cancellation.",
        inputSchema=SLOW_COUNT_SCHEMA,
    ),
    types.Tool(
        name="ask_name",
        description="Ask the connected client for a name via form elicitation when supported.",
        inputSchema=_EMPTY_SCHEMA,
    ),
]


@dataclass
class _ToolCtx:
    session: Any
    meta: Any
    call_meta: Any
    request_id: Any
    protocol_version: str
    params: Any
    headers: dict[str, str]


def _headers_from_request(request: Any) -> dict[str, str]:
    if request is None:
        return {}
    return {k.lower(): v for k, v in request.headers.items()}


def _progress_token(*sources: Any) -> Any:
    for meta in sources:
        if meta is None:
            continue
        if isinstance(meta, dict):
            token = meta.get("progressToken") or meta.get("progress_token")
        else:
            token = getattr(meta, "progress_token", None) or getattr(meta, "progressToken", None)
        if token is not None:
            return token
    return None


def _verify_identity(headers: dict[str, str]) -> KeystoneIdentity | None:
    """Verify ``X-Keystone-Identity``, or ``None`` when no secret is configured.

    Raises ``ValueError`` when a secret *is* configured but the header is
    missing, forged, signed with a different secret, or signed for a
    different audience -- ``_run_tool`` lets this propagate, and both
    ``_build_server`` branches turn it into an error ``CallToolResult``
    (the SDK 1.x decorator path does this automatically; the SDK 2.x
    constructor path does it explicitly).
    """
    if not HELLO_IDENTITY_SECRET:
        return None
    token = headers.get("x-keystone-identity")
    try:
        return verify_keystone_identity(
            token,
            secrets=[HELLO_IDENTITY_SECRET],
            audience=HELLO_IDENTITY_AUDIENCE,
            issuer=HELLO_IDENTITY_ISSUER,
        )
    except IdentityError as exc:
        raise ValueError(f"identity rejected: {exc}") from exc


def _greet(arguments: dict[str, Any], headers: dict[str, str]) -> str:
    """Greet by name; mention the caller when Keystone-MCP identified one.

    With ``HELLO_IDENTITY_SECRET`` set, this trusts only a verified
    ``X-Keystone-Identity``. Without it, this falls back to the unsigned,
    deprecated ``X-Author-Email`` -- trust it only on a private network you
    control; see ../../docs/connecting-services.md.
    """
    name = arguments["name"]
    identity = _verify_identity(headers)
    if identity is not None:
        roles = ", ".join(identity.roles)
        return f"Hello, {name}! You are {identity.email or identity.sub} (roles: {roles})."
    email = headers.get("x-author-email")
    if email:
        return f"Hello, {name}! You are {email}."
    return f"Hello, {name}!"


def _search(arguments: dict[str, Any]) -> str:
    query = arguments["query"]
    tool_filter = arguments["filter"]
    limit = arguments.get("limit") or 5
    lines = [f"{i + 1}. Result for '{query}' (filter={tool_filter})" for i in range(limit)]
    return "\n".join(lines)


def _whoami(headers: dict[str, str]) -> str:
    """Return the verified identity fields as JSON text.

    Without ``HELLO_IDENTITY_SECRET`` configured, answers
    ``{"verified": false, ...}`` with whatever (unverified) X-Author-Email
    was sent, exactly like ``greet``'s fallback.
    """
    identity = _verify_identity(headers)
    if identity is None:
        return json.dumps({"verified": False, "x-author-email": headers.get("x-author-email")})
    return json.dumps(
        {
            "verified": True,
            "sub": identity.sub,
            "sub_type": identity.sub_type,
            "roles": list(identity.roles),
            "auth_method": identity.auth_method,
            "interactive": identity.interactive,
            "client_id": identity.client_id,
            "mcp_target": identity.mcp_target,
        }
    )


def _client_supports_elicitation(session: Any) -> bool:
    if session is None:
        return False
    return session.check_client_capability(
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


async def _slow_count(arguments: dict[str, Any], ctx: _ToolCtx | None) -> list[types.ContentBlock]:
    n = int(arguments["n"])
    token = _progress_token(
        *(
            (
                ctx.call_meta,
                ctx.meta,
            )
            if ctx
            else ()
        )
    )
    session = ctx.session if ctx is not None else None
    report_progress = getattr(session, "report_progress", None) if session is not None else None
    send_progress = (
        getattr(session, "send_progress_notification", None) if session is not None else None
    )
    request_id = ctx.request_id if ctx is not None else None
    try:
        for i in range(1, n + 1):
            if token is not None and session is not None:
                message = f"tick {i}/{n}"
                if report_progress is not None:
                    await report_progress(float(i), float(n), message)
                elif send_progress is not None:
                    await send_progress(
                        token,
                        float(i),
                        float(n),
                        message,
                        related_request_id=request_id,
                    )
            await anyio.sleep(1)
    except anyio.get_cancelled_exc_class():
        raise
    return [types.TextContent(type="text", text=f"counted to {n}")]


async def _ask_name(ctx: _ToolCtx | None) -> list[types.ContentBlock] | Any:
    if ctx is None or ctx.session is None:
        return [types.TextContent(type="text", text="elicitation not available in this SDK")]

    if not _client_supports_elicitation(ctx.session):
        return [types.TextContent(type="text", text="no-elicitation")]

    message = "What is your name?"
    modern = ctx.protocol_version in MODERN_PROTOCOL_VERSIONS
    if modern and ctx.params is not None and _InputRequiredResult is not None:
        if ctx.params.input_responses is None:
            request = types.ElicitRequest(
                params=types.ElicitRequestFormParams(
                    message=message,
                    requested_schema=ASK_NAME_SCHEMA,
                )
            )
            return _InputRequiredResult(input_requests={"name": request})
        response = ctx.params.input_responses.get("name")
        if not isinstance(response, types.ElicitResult):
            return [types.TextContent(type="text", text="no-answer")]
        return [types.TextContent(type="text", text=_format_elicit_answer(response))]

    elicit_form = getattr(ctx.session, "elicit_form", None)
    if elicit_form is not None:
        result = await elicit_form(
            message,
            ASK_NAME_SCHEMA,
            related_request_id=ctx.request_id,
        )
        return [types.TextContent(type="text", text=_format_elicit_answer(result))]

    elicit = getattr(ctx.session, "elicit", None)
    if elicit is not None:
        result = await elicit(message, ASK_NAME_SCHEMA)
        return [types.TextContent(type="text", text=_format_elicit_answer(result))]

    return [types.TextContent(type="text", text="elicitation not available in this SDK")]


async def _run_tool(
    name: str,
    arguments: dict[str, Any],
    headers: dict[str, str],
    *,
    ctx: _ToolCtx | None = None,
) -> list[types.ContentBlock] | Any:
    if name == "greet":
        return [types.TextContent(type="text", text=_greet(arguments, headers))]
    if name == "search":
        return [types.TextContent(type="text", text=_search(arguments))]
    if name == "whoami":
        return [types.TextContent(type="text", text=_whoami(headers))]
    if name == "slow_count":
        return await _slow_count(arguments, ctx)
    if name == "ask_name":
        return await _ask_name(ctx)
    raise ValueError(f"unknown tool: {name}")


def _tool_ctx_from_server_request(server: Server, headers: dict[str, str]) -> _ToolCtx | None:
    rc = getattr(server, "request_context", None)
    if rc is None:
        return None
    session = getattr(rc, "session", None)
    params = getattr(rc, "params", None)
    call_meta = None
    if params is not None:
        call_meta = getattr(params, "meta", None) or getattr(params, "_meta", None)
    return _ToolCtx(
        session=session,
        meta=getattr(rc, "meta", None),
        call_meta=call_meta,
        request_id=getattr(rc, "request_id", None),
        protocol_version=getattr(rc, "protocol_version", ""),
        params=params,
        headers=headers,
    )


def _tool_ctx_from_handler(ctx: Any, headers: dict[str, str], params: Any) -> _ToolCtx:
    call_meta = getattr(params, "meta", None) or getattr(params, "_meta", None)
    return _ToolCtx(
        session=getattr(ctx, "session", None),
        meta=getattr(ctx, "meta", None),
        call_meta=call_meta,
        request_id=getattr(ctx, "request_id", None),
        protocol_version=getattr(ctx, "protocol_version", ""),
        params=params,
        headers=headers,
    )


def _build_server() -> Server:
    server: Server = Server("hello-upstream")

    if hasattr(server, "list_tools"):
        # MCP Python SDK 1.x (what the Dockerfile installs): tools are
        # registered via decorators, and a raised exception from
        # ``call_tool`` is wrapped into an error ``CallToolResult``
        # automatically.
        @server.list_tools()
        async def _list_tools() -> list[types.Tool]:
            return _TOOLS

        @server.call_tool()
        async def _call_tool(name: str, arguments: dict[str, Any]) -> list[types.ContentBlock]:
            request = server.request_context.request
            headers = _headers_from_request(request)
            tool_ctx = _tool_ctx_from_server_request(server, headers)
            with _hello_tool_span(name, headers):
                result = await _run_tool(name, arguments, headers, ctx=tool_ctx)
            if _is_input_required_result(result):
                raise ValueError("elicitation not available in this SDK")
            return result

        return server

    # MCP Python SDK 2.x (what Keystone-MCP's own test suite installs):
    # ``Server`` takes ``on_list_tools``/``on_call_tool`` in its constructor
    # instead (the decorators were removed), and does not auto-wrap a raised
    # exception, so that is done here explicitly.
    async def _on_list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
        return types.ListToolsResult(tools=_TOOLS)

    async def _on_call_tool(
        ctx: Any, params: Any
    ) -> types.CallToolResult | types.InputRequiredResult:
        headers = _headers_from_request(getattr(ctx, "request", None))
        tool_ctx = _tool_ctx_from_handler(ctx, headers, params)
        try:
            with _hello_tool_span(params.name, headers):
                result = await _run_tool(params.name, params.arguments or {}, headers, ctx=tool_ctx)
        except Exception as exc:  # noqa: BLE001 -- mirrors SDK 1.x's auto-wrap
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=str(exc))],
                is_error=True,
            )
        if isinstance(result, types.InputRequiredResult):
            return result
        return types.CallToolResult(content=result)

    return Server("hello-upstream", on_list_tools=_on_list_tools, on_call_tool=_on_call_tool)


server = _build_server()

manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)


class _McpEndpoint:
    """Raw ASGI endpoint handing the request straight to the session manager.

    Deliberately mounted via ``Route``, not ``Mount``: ``Mount`` redirects a
    bare ``/mcp`` request to ``/mcp/`` with a 307, and the MCP client does not
    follow it.
    """

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await manager.handle_request(scope, receive, send)


async def _healthz(_request: Any) -> JSONResponse:
    return JSONResponse({"status": "ok"})


@asynccontextmanager
async def _lifespan(_app: Starlette) -> AsyncIterator[None]:
    async with manager.run():
        yield


_starlette_app = Starlette(
    routes=[
        Route("/mcp", endpoint=_McpEndpoint(), methods=["GET", "POST", "DELETE"]),
        Route("/healthz", endpoint=_healthz, methods=["GET"]),
    ],
    lifespan=_lifespan,
)
_configure_otel_provider_once()
app = _HelloTracingMiddleware(_starlette_app) if _otel_export_configured() else _starlette_app


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)
