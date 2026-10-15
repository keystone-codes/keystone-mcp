"""MCP proxy adapter — forwards tool calls to a downstream MCP server over HTTP.

Used by upstream ``proxy_1to1`` routes. The verified identity is propagated to
the upstream as ``X-Author-Email`` (unsigned, deprecated since 0.5.0). When
the upstream's registry entry sets ``auth.identity_secret_env``, a signed
``X-Keystone-Identity`` JWT (see :mod:`keystone_mcp.identity_assertion`) is
sent as well, carrying the subject, the roles RBAC used, and which tool was
called. When it sets ``auth.bearer_env``, an ``Authorization: Bearer <token>``
header (read from that environment variable by :meth:`keystone_mcp.router.
upstream.UpstreamRegistry.add_upstream`) is sent alongside it on every call.

By default (``status_envelope=False``) the adapter is transparent: the
upstream's answer — every content block, ``structuredContent``, ``_meta`` and
``isError`` — reaches the client unchanged, as a :class:`fastmcp.tools.base.
ToolResult`. With ``status_envelope=True`` (``KEYSTONE_MCP_PROXY_STATUS_ENVELOPE=
true``) the adapter instead reproduces the 0.3.x behaviour: the response is
wrapped in the status envelope ``{"state", "tool", "task_id", "result"}`` and
a ``status`` field of ``error``/``refused``/``accepted`` is mapped to an
error, a rate-limit error, or a pending task.

While the call runs, progress notifications the upstream sends are relayed to
the client, when the client asked for them -- the actual call to the upstream
and that relaying both go through :mod:`keystone_mcp.router.upstream_call`,
the one place Keystone talks to an upstream MCP server.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Callable

import httpx2
import pydantic_core
from fastmcp import Client
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_context
from fastmcp.tools.base import InputRequiredToolResult, ToolResult

from keystone_mcp.identity import upstream_identity_headers
from keystone_mcp.identity_assertion import (
    IDENTITY_HEADER,
    IDENTITY_META_KEY,
    IdentityAssertionSigner,
)

if TYPE_CHECKING:
    from mcp.shared._httpx_utils import McpHttpClientFactory

    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route
    from keystone_mcp.router.upstream_connection import UpstreamConnection
    from keystone_mcp.router.upstream_guard import UpstreamGuard

logger = logging.getLogger(__name__)

_warned_upstream_timeout_keys: set[str] = set()

DEFAULT_UPSTREAM_MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class UpstreamResponseTooLargeError(RuntimeError):
    """Raised when an upstream HTTP response body exceeds the configured limit."""


class _CountingAsyncByteStream(httpx2.AsyncByteStream):
    """Wraps an httpx2 response stream and enforces a byte budget."""

    def __init__(self, stream: httpx2.AsyncByteStream, *, max_bytes: int) -> None:
        self._stream = stream
        self._max_bytes = max_bytes
        self._count = 0

    async def __aiter__(self) -> Any:
        async for chunk in self._stream:
            self._count += len(chunk)
            if self._count > self._max_bytes:
                await self.aclose()
                raise UpstreamResponseTooLargeError(
                    f"upstream response exceeds {self._max_bytes} bytes"
                )
            yield chunk

    async def aclose(self) -> None:
        await self._stream.aclose()


class ResponseSizeLimitTransport(httpx2.AsyncBaseTransport):
    """httpx2 transport wrapper that caps the size of each response body."""

    def __init__(self, transport: httpx2.AsyncBaseTransport, *, max_bytes: int) -> None:
        self._transport = transport
        self._max_bytes = max_bytes

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        response = await self._transport.handle_async_request(request)
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self._max_bytes:
                    await response.aclose()
                    raise UpstreamResponseTooLargeError(
                        f"upstream response exceeds {self._max_bytes} bytes"
                    )
            except ValueError:
                pass
        response.stream = _CountingAsyncByteStream(response.stream, max_bytes=self._max_bytes)
        return response

    async def aclose(self) -> None:
        await self._transport.aclose()


def limit_response_size(
    transport: httpx2.AsyncBaseTransport, max_bytes: int
) -> httpx2.AsyncBaseTransport:
    """Wrap *transport* so each HTTP response body is at most *max_bytes*."""
    if isinstance(transport, ResponseSizeLimitTransport):
        return ResponseSizeLimitTransport(transport._transport, max_bytes=max_bytes)
    return ResponseSizeLimitTransport(transport, max_bytes=max_bytes)


class _NonClosingTransport(httpx2.AsyncBaseTransport):
    """Wraps a shared pool transport so per-session httpx clients do not close it."""

    def __init__(self, inner: httpx2.AsyncBaseTransport) -> None:
        self._inner = inner

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        return None


def _http_client_factory(
    tool_timeout_seconds: float,
    *,
    max_response_bytes: int = DEFAULT_UPSTREAM_MAX_RESPONSE_BYTES,
    shared_transport: httpx2.AsyncHTTPTransport | None = None,
) -> "McpHttpClientFactory":
    """Build the transport's HTTP client with the per-tool timeout applied.

    Without this the per-tool budget bounded only the MCP request and not the
    underlying socket. The transport hands this factory an ``auth`` object
    built for ``httpx2`` (``fastmcp.client.auth.bearer.BearerAuth``), so the
    returned client must be an ``httpx2.AsyncClient`` — an ``httpx.AsyncClient``
    rejects that ``auth`` argument with a ``TypeError``. Our own HTTP code
    elsewhere in Keystone stays on ``httpx``; only this fastmcp boundary moves.

    Matches the MCP HTTP client factory protocol ``(headers, timeout, auth)``;
    the caller's ``timeout`` is deliberately replaced by the per-tool budget.
    """

    def factory(
        headers: dict[str, str] | None = None,
        timeout: Any = None,  # noqa: ARG001 — superseded by the per-tool budget
        auth: Any = None,
        **_kwargs: Any,
    ) -> httpx2.AsyncClient:
        if shared_transport is not None:
            inner: httpx2.AsyncBaseTransport = _NonClosingTransport(shared_transport)
        else:
            inner = httpx2.AsyncHTTPTransport()
        transport = limit_response_size(inner, max_response_bytes)
        return httpx2.AsyncClient(
            transport=transport,
            headers=headers,
            timeout=httpx2.Timeout(tool_timeout_seconds),
            auth=auth,
            follow_redirects=False,
        )

    return factory


#: Builds the client used for one upstream call. It receives the same
#: ``headers`` (carrying the verified identity) and ``timeout`` the default
#: transport would be built with, so an injected client is subject to both
#: rather than silently dropping them.
ClientFactory = Callable[..., Client]

#: ``StreamableHttpTransport`` http client factory for a resolved per-tool
#: timeout.
HttpClientFactoryBuilder = Callable[[float], "McpHttpClientFactory"]


class McpProxyAdapter:
    """Proxy a tool call to another MCP server (streamable HTTP)."""

    def __init__(
        self,
        connection_or_url: "UpstreamConnection | str",
        *,
        tool_timeout_seconds: float = 180.0,
        tool_timeout_overrides: dict[str, float] | None = None,
        client_factory: ClientFactory | None = None,
        http_client_factory: HttpClientFactoryBuilder | None = None,
        status_envelope: bool = False,
        proxy_elicitation: bool = True,
        extra_headers: Mapping[str, str] | None = None,
        identity_signer: IdentityAssertionSigner | None = None,
        max_response_bytes: int = DEFAULT_UPSTREAM_MAX_RESPONSE_BYTES,
        guard: "UpstreamGuard | None" = None,
    ) -> None:
        from keystone_mcp.router.upstream_connection import HttpUpstreamConnection

        if isinstance(connection_or_url, str):
            self._connection: UpstreamConnection = HttpUpstreamConnection(
                "",
                connection_or_url,
                http_client_factory=http_client_factory,
                client_factory=client_factory,
            )
        else:
            self._connection = connection_or_url
        self._tool_timeout_seconds = tool_timeout_seconds
        self._tool_timeout_overrides = dict(tool_timeout_overrides or {})
        self._max_response_bytes = max_response_bytes
        self._client_factory = client_factory
        if http_client_factory is not None:
            self._http_client_factory = http_client_factory
        elif isinstance(self._connection, HttpUpstreamConnection):
            if self._connection._http_client_factory is None:
                limit = max_response_bytes

                def _default_builder(timeout: float) -> "McpHttpClientFactory":
                    return _http_client_factory(timeout, max_response_bytes=limit)

                self._connection._http_client_factory = _default_builder
        self._status_envelope = status_envelope
        self._proxy_elicitation = proxy_elicitation
        # e.g. the upstream's ``Authorization: Bearer ...`` (auth.bearer_env).
        # Copied once at construction time, never logged as a whole.
        self._extra_headers = dict(extra_headers or {})
        # Signs X-Keystone-Identity; None means this upstream has no
        # auth.identity_secret_env and gets only the unsigned X-Author-Email.
        self._identity_signer = identity_signer
        self._guard = guard

    @classmethod
    def for_url(
        cls,
        url: str,
        **kwargs: Any,
    ) -> McpProxyAdapter:
        """Build an HTTP-only adapter (tests and legacy call sites)."""
        return cls(url, **kwargs)

    @property
    def _client_factory(self) -> ClientFactory | None:
        from keystone_mcp.router.upstream_connection import HttpUpstreamConnection

        conn = self._connection
        if isinstance(conn, HttpUpstreamConnection):
            return conn._client_factory
        return None

    @_client_factory.setter
    def _client_factory(self, factory: ClientFactory | None) -> None:
        from keystone_mcp.router.upstream_connection import HttpUpstreamConnection

        conn = self._connection
        if isinstance(conn, HttpUpstreamConnection):
            conn._client_factory = factory

    @property
    def _http_client_factory(self) -> HttpClientFactoryBuilder | None:
        from keystone_mcp.router.upstream_connection import HttpUpstreamConnection

        conn = self._connection
        if isinstance(conn, HttpUpstreamConnection):
            return conn._http_client_factory
        return None

    @_http_client_factory.setter
    def _http_client_factory(self, factory: HttpClientFactoryBuilder | None) -> None:
        from keystone_mcp.router.upstream_connection import HttpUpstreamConnection

        conn = self._connection
        if isinstance(conn, HttpUpstreamConnection):
            conn._http_client_factory = factory

    @property
    def guard(self) -> "UpstreamGuard | None":
        return self._guard

    @property
    def status_envelope(self) -> bool:
        """``True`` when this adapter wraps answers in the legacy envelope.

        ``False`` (the default) means it is transparent. Consulted by
        :meth:`keystone_mcp.router.proxy_tool.UpstreamProxyTool.for_route` to
        decide whether the upstream's own ``outputSchema`` can be published
        (only safe when the response actually matches it).
        """
        return self._status_envelope

    def _timeout_for(self, route: "Route") -> float:
        published = route.published_name
        if published in self._tool_timeout_overrides:
            return self._tool_timeout_overrides[published]
        upstream_key = route.upstream_tool or route.name
        if upstream_key in self._tool_timeout_overrides:
            if upstream_key not in _warned_upstream_timeout_keys:
                _warned_upstream_timeout_keys.add(upstream_key)
                logger.warning(
                    "KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS key %r is an upstream tool name; "
                    "use the published name %r (upstream names are deprecated since 0.6.0)",
                    upstream_key,
                    published,
                )
            return self._tool_timeout_overrides[upstream_key]
        return self._tool_timeout_seconds

    async def execute(
        self,
        route: "Route",
        ctx: "RouteContext",
        args: dict[str, Any],
        request: Any,
    ) -> dict[str, Any] | ToolResult:
        # Local import: keystone_mcp.router (via router/__init__.py ->
        # router.upstream) imports this module, so a module-level import here
        # would be circular (see the identity_assertion.py note on the same
        # problem). Captured first, in the request's own task: it is this
        # call's only chance to see the client request that is waiting on it
        # (DownstreamCall.current's docstring explains why that matters).
        from keystone_mcp.router.upstream_call import (
            DownstreamCall,
            attach_upstream_elicitation_callback,
            call_upstream_tool,
            downstream_supports_form_elicitation,
            make_elicitation_callback,
            parse_for_status_envelope,
        )

        downstream = DownstreamCall.current()

        if request is not None:
            payload = request
        else:
            from keystone_mcp.router.schema import omit_implicit_null_args

            payload = omit_implicit_null_args(dict(args), route.params)
        tool_name = route.upstream_tool or route.name
        timeout = self._timeout_for(route)
        # AUTHOR_EMAIL_HEADER last: extra_headers (e.g. a bearer token) must
        # not be able to override the verified identity header. The signed
        # assertion is built after extra_headers too, for the same reason —
        # neither can be overridden by a static header from the registry.
        call_meta: dict[str, Any] | None = None
        headers: dict[str, str] = {}
        if self._connection.transport == "http" and route.input_schema:
            from mcp.shared.inbound import mcp_param_headers, x_mcp_header_map

            header_map = x_mcp_header_map(route.input_schema)
            if header_map:
                try:
                    headers.update(mcp_param_headers(header_map, payload))
                except Exception as exc:  # noqa: BLE001 — upstream will reject the call
                    logger.debug(
                        "Mcp-Param header omitted for %s: %s",
                        route.published_name,
                        exc,
                    )
        if self._connection.transport == "http":
            from keystone_mcp.observability.tracing import inject_trace_headers

            inject_trace_headers(headers)
        headers.update(self._extra_headers)
        if self._identity_signer is not None:
            token = self._identity_signer.sign(
                identity=ctx.verified_identity,
                task_id=ctx.task_id,
                mcp_method="tools/call",
                mcp_target=tool_name,
                timeout_seconds=timeout,
                rbac_mode=ctx.settings.rbac_mode,
            )
            if self._connection.transport == "stdio":
                call_meta = {IDENTITY_META_KEY: token}
            else:
                headers[IDENTITY_HEADER] = token
        if self._connection.transport == "http":
            headers.update(upstream_identity_headers(ctx.verified_identity))

        from keystone_mcp.router.stdio_process import UpstreamProcessUnavailableError

        elicitation_callback = None
        if (
            self._proxy_elicitation
            and self._connection.transport == "http"
            and downstream is not None
            and downstream_supports_form_elicitation(downstream.session)
        ):
            elicitation_callback = make_elicitation_callback(
                downstream,
                namespace=route.namespace,
                tool_name=tool_name,
            )

        input_responses = None
        request_state = None
        try:
            fctx = get_context()
            input_responses = fctx.input_responses
            request_state = fctx.request_state
        except RuntimeError:
            pass

        from keystone_mcp.observability.tracing import traced, upstream_call_span_attrs
        from keystone_mcp.router.upstream_connection import HttpUpstreamConnection

        span_attrs = upstream_call_span_attrs(
            namespace=route.namespace,
            transport=self._connection.transport,
            mcp_method="tools/call",
            upstream_tool=tool_name,
        )

        async def _invoke_upstream() -> dict[str, Any] | ToolResult:
            max_attempts = 2 if isinstance(self._connection, HttpUpstreamConnection) else 1
            raw = None
            parsed = None
            with traced("keystone.upstream.call", **span_attrs):
                for attempt in range(max_attempts):
                    try:
                        client = self._connection.call_client(headers=headers, timeout=timeout)
                    except UpstreamProcessUnavailableError:
                        raise ToolError(f"upstream {route.namespace} is unavailable") from None
                    except ToolError:
                        raise
                    except Exception as exc:
                        if (
                            attempt + 1 < max_attempts
                            and isinstance(self._connection, HttpUpstreamConnection)
                            and self._connection.prepare_stale_era_retry(exc)
                        ):
                            continue
                        from keystone_mcp.router.upstream_errors import (
                            log_upstream_failure,
                            rethrow_upstream_error,
                        )

                        log_upstream_failure(
                            route.namespace,
                            exc,
                            upstream_tool=tool_name,
                        )
                        rethrow_upstream_error(
                            route.namespace,
                            exc,
                            timeout=timeout,
                        )
                    if elicitation_callback is not None:
                        attach_upstream_elicitation_callback(client, elicitation_callback)
                    try:
                        async with client:
                            raw = await call_upstream_tool(
                                client,
                                tool_name,
                                payload,
                                timeout=timeout,
                                meta=call_meta,
                                downstream=downstream,
                                log_namespace=route.namespace,
                                input_responses=input_responses,
                                request_state=request_state,
                                proxy_elicitation=self._proxy_elicitation,
                            )
                            if isinstance(raw, InputRequiredToolResult):
                                return raw
                            if self._status_envelope:
                                # Parsed inside the ``async with`` block: _parse_call_tool_result
                                # decodes against the upstream's output schema, cached on the
                                # still-open session.
                                parsed = await parse_for_status_envelope(client, tool_name, raw)
                        break
                    except UpstreamResponseTooLargeError as exc:
                        from keystone_mcp.observability.metrics import record_upstream_item_rejected

                        record_upstream_item_rejected(
                            namespace=route.namespace,
                            kind="response",
                            reason="response_too_large",
                        )
                        raise ToolError(
                            f"upstream {route.namespace} answer is larger than "
                            f"{self._max_response_bytes} bytes"
                        ) from exc
                    except ToolError:
                        raise
                    except Exception as exc:
                        if (
                            attempt + 1 < max_attempts
                            and isinstance(self._connection, HttpUpstreamConnection)
                            and self._connection.prepare_stale_era_retry(exc)
                        ):
                            continue
                        from keystone_mcp.router.upstream_errors import (
                            log_upstream_failure,
                            rethrow_upstream_error,
                        )

                        log_upstream_failure(
                            route.namespace,
                            exc,
                            upstream_tool=tool_name,
                        )
                        rethrow_upstream_error(
                            route.namespace,
                            exc,
                            timeout=timeout,
                        )

            if self._status_envelope:
                return self._wrap_status_envelope(parsed, route, ctx)

            from keystone_mcp.router.proxy_components import strip_upstream_connection_meta

            raw = raw.model_copy(update={"meta": strip_upstream_connection_meta(raw.meta)})
            return ToolResult.from_mcp_result(raw)

        if self._guard is not None:
            async with self._guard.call(
                timeout=timeout,
                slot_wait_timeout=min(timeout, 30.0),
            ):
                return await _invoke_upstream()
        return await _invoke_upstream()

    @staticmethod
    def _wrap_status_envelope(result: Any, route: "Route", ctx: "RouteContext") -> dict[str, Any]:
        """Reproduce the 0.3.x envelope: ``{state, tool, task_id, result}``.

        Raises :class:`fastmcp.exceptions.ToolError` on an upstream error —
        what the FastMCP client itself did in 0.3.x with its default
        ``raise_on_error=True`` — so the error handling further up the stack
        (observability, client-visible tool error) sees the same shape as
        before.
        """
        published = route.published_name
        tool_name = route.upstream_tool or route.name

        if result.is_error:
            content = list(result.content) or []
            text = content[0].text if content and hasattr(content[0], "text") else None
            raise ToolError(text or f"Tool '{tool_name}' returned an error")

        data = result.data
        if data is not None:
            data = pydantic_core.to_jsonable_python(data)
        else:
            content = list(result.content) or []
            text_blocks = [block.text for block in content if hasattr(block, "text")]
            dropped = len(content) - len(text_blocks)
            if dropped:
                logger.warning(
                    "proxy status envelope drops %d non-text content block(s) from %s",
                    dropped,
                    route.published_name,
                )
            raw = "\n".join(text_blocks)
            if not raw:
                data = {}
            else:
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    data = raw

        if isinstance(data, dict):
            status = data.get("status")
            if status == "error":
                return {
                    "state": "error",
                    "tool": published,
                    "task_id": ctx.task_id,
                    "code": data.get("error_code") or "upstream_error",
                    "message": data.get("error_message") or "downstream error",
                }
            if status == "refused":
                return {
                    "state": "error",
                    "tool": published,
                    "task_id": ctx.task_id,
                    "code": "rate_limited",
                    "message": data.get("error_message") or "rate limit exceeded",
                }
            if status == "accepted":
                return {
                    "state": "pending",
                    "tool": published,
                    "task_id": ctx.task_id,
                    "result": data,
                }

        return {
            "state": "done",
            "tool": published,
            "task_id": ctx.task_id,
            "result": data,
        }
