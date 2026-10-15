"""hello-upstream continues W3C trace context."""

from __future__ import annotations

import importlib.util
import sys
import uuid
from pathlib import Path

import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from keystone_mcp.observability.tracing import install_test_tracer_provider, shutdown_tracing
from support.lowlevel_upstream import UPSTREAM_MCP_URL, asgi_http_client_factory

pytest.importorskip("opentelemetry.sdk")

REPO_ROOT = Path(__file__).resolve().parents[1]
HELLO_UPSTREAM_DIR = REPO_ROOT / "examples" / "hello-upstream"
SERVER_PATH = HELLO_UPSTREAM_DIR / "server.py"

CLIENT_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
CLIENT_SPAN_ID = "00f067aa0ba902b7"
CLIENT_TRACEPARENT = f"00-{CLIENT_TRACE_ID}-{CLIENT_SPAN_ID}-01"
EXPECTED_TRACE_ID = int(CLIENT_TRACE_ID, 16)


@pytest.fixture
def tracing_exporter() -> InMemorySpanExporter:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    install_test_tracer_provider(provider)
    exporter.clear()
    yield exporter
    exporter.clear()
    shutdown_tracing()


def _load_hello_module(monkeypatch):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    monkeypatch.delenv("HELLO_IDENTITY_SECRET", raising=False)

    if str(HELLO_UPSTREAM_DIR) not in sys.path:
        sys.path.insert(0, str(HELLO_UPSTREAM_DIR))

    spec = importlib.util.spec_from_file_location(f"_hello_trace_{uuid.uuid4().hex}", SERVER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


async def test_hello_greet_continues_caller_trace(
    monkeypatch, tracing_exporter: InMemorySpanExporter
):
    hello = _load_hello_module(monkeypatch)

    async with LifespanManager(hello.app):
        http_client_factory = asgi_http_client_factory(hello.app)
        transport = StreamableHttpTransport(
            UPSTREAM_MCP_URL,
            headers={"traceparent": CLIENT_TRACEPARENT},
            httpx_client_factory=http_client_factory(30.0),
        )
        async with Client(transport) as client:
            result = await client.call_tool_mcp("greet", {"name": "World"})

    assert result.is_error is False
    greet_spans = [s for s in tracing_exporter.get_finished_spans() if s.name == "hello.greet"]
    assert len(greet_spans) == 1
    assert greet_spans[0].context.trace_id == EXPECTED_TRACE_ID
