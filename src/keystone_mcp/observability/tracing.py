"""Optional OpenTelemetry tracing (KEYSTONE_MCP_OTEL_ENABLED)."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# OpenTelemetry semantic convention attribute names (stable HTTP/DB naming).
HTTP_REQUEST_METHOD = "http.request.method"
HTTP_ROUTE = "http.route"
HTTP_RESPONSE_STATUS_CODE = "http.response.status_code"
DB_SYSTEM_NAME = "db.system.name"
DB_OPERATION_NAME = "db.operation.name"

_tracing_active = False
_tracing_handle: TracingHandle | None = None


@dataclass
class TracingHandle:
    def shutdown(self) -> None:
        raise NotImplementedError


class _TracingHandleImpl(TracingHandle):
    def __init__(self, provider: Any) -> None:
        self._provider = provider

    def shutdown(self) -> None:
        self._provider.shutdown()


def configure_tracing(settings: Any) -> TracingHandle | None:
    """Install a global TracerProvider when otel is enabled."""
    global _tracing_active, _tracing_handle
    if not settings.otel_enabled:
        _tracing_active = False
        _tracing_handle = None
        return None
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        from keystone_mcp.config import ConfigError

        raise ConfigError(
            "KEYSTONE_MCP_OTEL_ENABLED=true needs the otel extra: "
            "pip install 'keystone-mcp-gateway[otel]'"
        ) from exc

    import os

    import keystone_mcp

    service_name = os.environ.get("OTEL_SERVICE_NAME", "keystone-mcp")
    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": keystone_mcp.__version__,
        }
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    _tracing_active = True
    handle = _TracingHandleImpl(provider)
    _tracing_handle = handle
    return handle


def shutdown_tracing() -> None:
    global _tracing_handle, _tracing_active
    if _tracing_handle is not None:
        _tracing_handle.shutdown()
        _tracing_handle = None
    _tracing_active = False


def is_tracing_active() -> bool:
    return _tracing_active


def set_tracing_active_for_tests(active: bool) -> None:
    """Test hook: mark tracing on without configuring OTLP export."""
    global _tracing_active
    _tracing_active = active


def tracer() -> Any | None:
    if not _tracing_active:
        return None
    from opentelemetry import trace

    import keystone_mcp

    return trace.get_tracer("keystone_mcp", keystone_mcp.__version__)


def current_trace_ids() -> tuple[str, str] | None:
    if not _tracing_active:
        return None
    from opentelemetry import trace

    span = trace.get_current_span()
    ctx = span.get_span_context()
    if not ctx.is_valid:
        return None
    return (format(ctx.trace_id, "032x"), format(ctx.span_id, "016x"))


@contextlib.contextmanager
def traced(name: str, **attrs: Any):
    if not _tracing_active:
        yield None
        return
    tr = tracer()
    if tr is None:
        yield None
        return
    with tr.start_as_current_span(name) as span:
        for key, value in attrs.items():
            if value is not None:
                span.set_attribute(key, value)
        yield span


def inject_trace_headers(headers: dict[str, str]) -> None:
    if not _tracing_active:
        return
    from opentelemetry.propagate import inject

    inject(headers)


def classify_http_route(
    path: str,
    *,
    mcp_path: str,
    metrics_path: str,
) -> str | None:
    """Return a low-cardinality route group, or None to skip tracing (probes)."""
    if path in ("/healthz", "/readyz"):
        return None
    normalized_mcp = mcp_path.rstrip("/") or "/mcp"
    if path == normalized_mcp or path.startswith(f"{normalized_mcp}/"):
        return "mcp"
    if path == metrics_path:
        return "metrics"
    if path == "/token":
        return "/token"
    if path == "/authorize":
        return "/authorize"
    if path == "/register":
        return "/register"
    if path == "/revoke":
        return "/revoke"
    if path == "/login":
        return "/login"
    if path.startswith("/login/"):
        return "/login/{provider}"
    if path.startswith("/.well-known/"):
        return "/.well-known/*"
    return "other"


class TracingMiddleware:
    """ASGI middleware: extract W3C context and open a server HTTP span."""

    def __init__(self, app: Callable, *, settings: Any) -> None:
        self.app = app
        self._settings = settings
        metrics_path = settings.metrics_path.strip() or "/metrics"

        self._mcp_path = settings.http_path
        self._metrics_path = metrics_path

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http" or not _tracing_active:
            await self.app(scope, receive, send)
            return

        from opentelemetry import trace
        from opentelemetry.propagate import extract
        from opentelemetry.trace import SpanKind, Status, StatusCode

        from keystone_mcp.observability.logging.context import get_request_id

        method = scope.get("method", "GET")
        path = scope.get("path", "")
        route_group = classify_http_route(
            path,
            mcp_path=self._mcp_path,
            metrics_path=self._metrics_path,
        )
        if route_group is None:
            await self.app(scope, receive, send)
            return

        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or ()
        }
        ctx = extract(headers)
        tr = tracer()
        if tr is None:
            await self.app(scope, receive, send)
            return

        span_name = f"{method} {route_group}"
        status_code = 500

        async def send_wrapper(message: dict) -> None:
            nonlocal status_code
            if message.get("type") == "http.response.start":
                status_code = int(message.get("status", 500))
            await send(message)

        token = trace.context_api.attach(ctx)
        try:
            with tr.start_as_current_span(span_name, kind=SpanKind.SERVER) as span:
                span.set_attribute(HTTP_REQUEST_METHOD, method)
                span.set_attribute(HTTP_ROUTE, route_group)
                request_id = get_request_id()
                if request_id:
                    span.set_attribute("keystone.request_id", request_id)
                try:
                    await self.app(scope, receive, send_wrapper)
                except Exception:
                    span.set_status(Status(StatusCode.ERROR))
                    raise
                else:
                    span.set_attribute(HTTP_RESPONSE_STATUS_CODE, status_code)
                    if status_code >= 500:
                        span.set_status(Status(StatusCode.ERROR))
        finally:
            trace.context_api.detach(token)


def install_test_tracer_provider(provider: Any) -> None:
    """Tests: replace the global provider (see OpenTelemetry set_tracer_provider)."""
    from opentelemetry import trace
    from opentelemetry.util._once import Once

    # OTEL allows one set_tracer_provider per process; tests reset the Once gate.
    trace._TRACER_PROVIDER_SET_ONCE = Once()  # noqa: SLF001
    trace._TRACER_PROVIDER = None  # noqa: SLF001
    trace.set_tracer_provider(provider)
    set_tracing_active_for_tests(True)


def upstream_call_span_attrs(
    *,
    namespace: str | None,
    transport: str,
    mcp_method: str,
    upstream_tool: str,
) -> dict[str, Any]:
    return {
        "keystone.upstream.namespace": namespace or "",
        "keystone.upstream.transport": transport,
        "keystone.mcp.method": mcp_method,
        "keystone.upstream.tool": upstream_tool,
    }
