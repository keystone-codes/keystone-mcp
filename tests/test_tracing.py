"""OpenTelemetry tracing."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

import httpx2
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import ConfigError, Settings, load_settings
from keystone_mcp.observability.tracing import (
    install_test_tracer_provider,
    set_tracing_active_for_tests,
    shutdown_tracing,
)
from keystone_mcp.server import _http_asgi_middleware, bootstrap_platform, build_server
from support.login import dev_token_login
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)
from support.oauth_harness import BASE_URL
from support.service_bearer import ADMIN_EMAIL, POLICY_YAML, SERVICE_NAME
from support.test_env import require_redis_url, users_revision_key

pytest.importorskip("opentelemetry.sdk")

CLIENT_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
CLIENT_SPAN_ID = "00f067aa0ba902b7"
CLIENT_TRACEPARENT = f"00-{CLIENT_TRACE_ID}-{CLIENT_SPAN_ID}-01"


def _keystone_http_client_factory(app: object):
    def factory(headers=None, timeout=None, auth=None, **_kw):
        return httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url=BASE_URL,
            headers=dict(headers or {}),
            timeout=timeout or httpx2.Timeout(30.0),
            auth=auth,
            follow_redirects=True,
        )

    return factory


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
    set_tracing_active_for_tests(False)


def _span_names(exporter: InMemorySpanExporter) -> list[str]:
    return [span.name for span in exporter.get_finished_spans()]


def _all_attributes(exporter: InMemorySpanExporter) -> list[dict]:
    out: list[dict] = []
    for span in exporter.get_finished_spans():
        out.append(dict(span.attributes or {}))
    return out


def _trace_ids(exporter: InMemorySpanExporter) -> set[int]:
    return {span.context.trace_id for span in exporter.get_finished_spans()}


@asynccontextmanager
async def _traced_app(tmp_path: Path, *, otel_enabled: bool = True):
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(POLICY_YAML, encoding="utf-8")
    observed: dict = {}
    upstream_app = build_lowlevel_upstream_app(tools=["greet", "whoami"], observed=observed)
    settings = Settings(
        base_url=BASE_URL,
        deployment_profile="local",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        rbac_audit_subject_salt="trace-test-salt",
        redis_url=require_redis_url(),
        users_redis_revision_key=users_revision_key("trace"),
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/keystone-users.db",
        upstreams_json=json.dumps(
            [
                {
                    "name": "hello-upstream",
                    "url": UPSTREAM_MCP_URL,
                    "namespace": "hello",
                    "enabled": True,
                }
            ]
        ),
        otel_enabled=otel_enabled,
        rbac_audit_enabled=True,
        log_format="json",
        enabled_login_methods=frozenset({"api_key"}),
        primary_login_method="api_key",
    )
    from keystone_mcp.observability.logging.configure import configure_logging
    from keystone_mcp.observability.tracing import set_tracing_active_for_tests

    set_tracing_active_for_tests(otel_enabled)
    from keystone_mcp.users import service

    configure_logging(settings)
    from keystone_mcp.users.db import make_session_factory, session_scope
    from keystone_mcp.users.factory import build_users_store

    store = build_users_store(
        Settings(users_db_url=settings.users_db_url, redis_url=settings.redis_url)
    )
    await store.migrate()
    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_user(
            session,
            email=ADMIN_EMAIL,
            full_name="Admin",
            roles=["administrator"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )
        service.create_service_account(
            session,
            name=SERVICE_NAME,
            description=None,
            roles=["machine"],
            created_by="test",
        )
        _row, service_key = service.issue_api_key(
            session,
            subject=f"svc:{SERVICE_NAME}",
            label="ci",
            expires_in_days=90,
            created_by=ADMIN_EMAIL,
        )
    mcp, registry, _oauth, upstreams, policy_manager, observability, _rec = build_server(
        settings=settings,
        users_store=store,
        oauth_store=InMemoryOAuthStore(),
        login_providers=[dev_token_login({"admin-dev"})],
        register_builtin_catalog=True,
    )
    registry.add_route("human_only", StubAdapter(), mode="live", description="Human gate probe")
    in_process = asgi_http_client_factory(upstream_app)
    upstreams.http_client_factory = in_process
    for adapter in upstreams._adapters.values():  # noqa: SLF001
        adapter._http_client_factory = in_process  # noqa: SLF001
    app = mcp.http_app(
        path=settings.http_path,
        middleware=_http_asgi_middleware(settings) or None,
    )
    async with LifespanManager(upstream_app):
        async with LifespanManager(app):
            await bootstrap_platform(
                upstreams,
                registry,
                settings,
                policy_manager,
                observability=observability,
                users_store=store,
                login_providers=[dev_token_login({"admin-dev"})],
            )
            yield settings, app, service_key, observed


@pytest.mark.asyncio
async def test_one_tool_call_builds_one_trace(tracing_exporter, tmp_path):
    client_trace = int(CLIENT_TRACE_ID, 16)
    async with _traced_app(tmp_path) as (settings, app, service_key, _observed):
        transport = StreamableHttpTransport(
            settings.transport_url,
            headers={
                "Authorization": f"Bearer {service_key}",
                "traceparent": CLIENT_TRACEPARENT,
            },
            httpx_client_factory=_keystone_http_client_factory(app),
        )
        async with Client(transport) as client:
            await client.call_tool("hello_greet", {"name": "Trace"})

    names = _span_names(tracing_exporter)
    assert any(n.startswith("POST ") for n in names)
    assert "keystone.token.verify" in names
    assert "keystone.rbac.decide" in names
    assert "keystone.directory.resolve" in names
    assert "keystone.upstream.call" in names
    assert client_trace in _trace_ids(tracing_exporter)
    upstream = next(s for s in tracing_exporter.get_finished_spans() if s.name == "keystone.upstream.call")
    assert upstream.parent is not None


@pytest.mark.asyncio
async def test_upstream_receives_traceparent_header_and_meta(tracing_exporter, tmp_path):
    async with _traced_app(tmp_path) as (settings, app, service_key, observed):
        transport = StreamableHttpTransport(
            settings.transport_url,
            headers={
                "Authorization": f"Bearer {service_key}",
                "traceparent": CLIENT_TRACEPARENT,
            },
            httpx_client_factory=_keystone_http_client_factory(app),
        )
        async with Client(transport) as client:
            await client.call_tool("hello_whoami", {})

    headers = observed.get("headers") or {}
    tp = headers.get("traceparent", "")
    assert CLIENT_TRACE_ID in tp.replace("-", "")


@pytest.mark.asyncio
async def test_traceparent_cannot_override_identity_headers(tracing_exporter, tmp_path, monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_HELLO_BEARER", "s3cr3t-value")
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(
        POLICY_YAML.replace('allow: ["hello_greet", "hello_whoami"]', 'allow: ["hello_whoami"]'),
        encoding="utf-8",
    )
    observed: dict = {}
    upstream_app = build_lowlevel_upstream_app(
        tools=["whoami"],
        observed=observed,
        require_bearer="s3cr3t-value",
    )

    @asynccontextmanager
    async def _harness():
        settings = Settings(
            base_url=BASE_URL,
            deployment_profile="local",
            rbac_mode="enforce",
            rbac_policy_path=str(policy_path),
            rbac_audit_subject_salt="trace-test-salt",
            redis_url=require_redis_url(),
            users_redis_revision_key=users_revision_key("trace"),
            users_backend="local",
            users_db_url=f"sqlite:///{tmp_path}/keystone-users-bearer.db",
            upstreams_json=json.dumps(
                [
                    {
                        "name": "hello-upstream",
                        "url": UPSTREAM_MCP_URL,
                        "namespace": "hello",
                        "enabled": True,
                        "auth": {"bearer_env": "KEYSTONE_MCP_UPSTREAM_HELLO_BEARER"},
                    }
                ]
            ),
            otel_enabled=True,
            log_format="json",
            rbac_audit_enabled=True,
            enabled_login_methods=frozenset({"api_key"}),
            primary_login_method="api_key",
        )
        from keystone_mcp.observability.logging.configure import configure_logging
        from keystone_mcp.observability.tracing import set_tracing_active_for_tests
        from keystone_mcp.users import service
        from keystone_mcp.users.db import make_session_factory, session_scope
        from keystone_mcp.users.factory import build_users_store

        configure_logging(settings)
        set_tracing_active_for_tests(True)
        store = build_users_store(
            Settings(users_db_url=settings.users_db_url, redis_url=settings.redis_url)
        )
        await store.migrate()
        factory = make_session_factory(store._engine)  # noqa: SLF001
        with session_scope(factory) as session:
            service.create_user(
                session,
                email=ADMIN_EMAIL,
                full_name="Admin",
                roles=["administrator"],
                note=None,
                created_by="test",
                allowed_roles=None,
            )
            service.create_service_account(
                session,
                name=SERVICE_NAME,
                description=None,
                roles=["machine"],
                created_by="test",
            )
            _row, service_key = service.issue_api_key(
                session,
                subject=f"svc:{SERVICE_NAME}",
                label="ci",
                expires_in_days=90,
                created_by=ADMIN_EMAIL,
            )
        mcp, registry, _oauth, upstreams, policy_manager, observability, _rec = build_server(
            settings=settings,
            users_store=store,
            oauth_store=InMemoryOAuthStore(),
            login_providers=[dev_token_login({"admin-dev"})],
            register_builtin_catalog=True,
        )
        in_process = asgi_http_client_factory(upstream_app)
        upstreams.http_client_factory = in_process
        for adapter in upstreams._adapters.values():  # noqa: SLF001
            adapter._http_client_factory = in_process  # noqa: SLF001
        app = mcp.http_app(
            path=settings.http_path,
            middleware=_http_asgi_middleware(settings) or None,
        )
        async with LifespanManager(upstream_app):
            async with LifespanManager(app):
                await bootstrap_platform(
                    upstreams,
                    registry,
                    settings,
                    policy_manager,
                    observability=observability,
                    users_store=store,
                    login_providers=[dev_token_login({"admin-dev"})],
                )
                yield settings, app, service_key

    async with _harness() as (settings, app, service_key):
        transport = StreamableHttpTransport(
            settings.transport_url,
            headers={
                "Authorization": f"Bearer {service_key}",
                "traceparent": CLIENT_TRACEPARENT,
            },
            httpx_client_factory=_keystone_http_client_factory(app),
        )
        async with Client(transport) as client:
            await client.call_tool("hello_whoami", {})
    headers = observed.get("headers") or {}
    assert headers.get("authorization") == "Bearer s3cr3t-value"


@pytest.mark.asyncio
async def test_no_pii_in_span_attributes(tracing_exporter, tmp_path):
    async with _traced_app(tmp_path) as (settings, app, service_key, _observed):
        transport = StreamableHttpTransport(
            settings.transport_url,
            headers={
                "Authorization": f"Bearer {service_key}",
                "traceparent": CLIENT_TRACEPARENT,
            },
            httpx_client_factory=_keystone_http_client_factory(app),
        )
        async with Client(transport) as client:
            await client.call_tool("hello_greet", {"name": "Ann"})
    blob = json.dumps(_all_attributes(tracing_exporter))
    for needle in ("admin@", "km:oauth:", "Bearer ", "ksk_"):
        assert needle not in blob


@pytest.mark.asyncio
async def test_unknown_tool_name_is_unknown_in_span(tracing_exporter, tmp_path):
    async with _traced_app(tmp_path) as (settings, app, service_key, _observed):
        transport = StreamableHttpTransport(
            settings.transport_url,
            headers={
                "Authorization": f"Bearer {service_key}",
                "traceparent": CLIENT_TRACEPARENT,
            },
            httpx_client_factory=_keystone_http_client_factory(app),
        )
        async with Client(transport) as client:
            with pytest.raises((ToolError, RuntimeError, ValueError)):
                await client.call_tool("no_such_tool", {})
    rbac = next(
        s for s in tracing_exporter.get_finished_spans() if s.name == "keystone.rbac.decide"
    )
    assert rbac.attributes.get("keystone.tool") == "unknown"


@pytest.mark.asyncio
async def test_probes_have_no_spans(tracing_exporter, tmp_path):
    async with _traced_app(tmp_path) as (_settings, app, _service_key, _observed):
        import httpx2

        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url=BASE_URL,
        ) as http:
            assert (await http.get("/healthz")).status_code == 200
            assert (await http.get("/readyz")).status_code in (200, 503)
    for span in tracing_exporter.get_finished_spans():
        route = (span.attributes or {}).get("http.route")
        assert route not in ("/healthz", "/readyz")


@pytest.mark.asyncio
def test_log_lines_carry_trace_id(tracing_exporter):
    from keystone_mcp.observability.logging.formatters import JsonFormatter
    from keystone_mcp.observability.tracing import traced

    with traced("keystone.test"):
        record = logging.LogRecord(
            name="keystone_mcp.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="tool call",
            args=(),
            exc_info=None,
        )
        record.request_id = "req-test-1"
        payload = json.loads(JsonFormatter().format(record))
    assert payload["request_id"] == "req-test-1"
    assert payload.get("trace_id")
    assert payload.get("span_id")


def test_audit_event_carries_trace_id(tracing_exporter, caplog):
    from keystone_mcp.observability.audit import AuthzAuditRecorder, policy_fields
    from keystone_mcp.observability.tracing import traced
    caplog.set_level(logging.INFO)
    recorder = AuthzAuditRecorder(
        enabled=True,
        list_tools_allow_sample_rate=1.0,
        subject_salt="audit-salt",
    )
    with traced("keystone.rbac.decide"):
        recorder.record_decision(
            tool_name="hello_greet",
            email="svc:ci@example.com",
            allowed=True,
            reason=None,
            roles=frozenset({"machine"}),
            policy=policy_fields(None),
            cache_hit=False,
            operation="call_tool",
            request_id="req-audit",
        )
    audit_lines = [r.getMessage() for r in caplog.records if "rbac audit" in r.getMessage()]
    assert audit_lines
    assert any("trace_id" in ln for ln in audit_lines)


@pytest.mark.asyncio
async def test_disabled_tracing_creates_no_spans_and_no_header(tracing_exporter, tmp_path):
    async with _traced_app(tmp_path, otel_enabled=False) as (settings, app, service_key, observed):
        transport = StreamableHttpTransport(
            settings.transport_url,
            headers={"Authorization": f"Bearer {service_key}"},
            httpx_client_factory=_keystone_http_client_factory(app),
        )
        async with Client(transport) as client:
            await client.call_tool("hello_whoami", {})
    keystone_spans = [s for s in tracing_exporter.get_finished_spans() if s.name.startswith("keystone.")]
    assert keystone_spans == []
    headers = observed.get("headers") or {}
    assert "traceparent" not in headers


def test_enabled_without_sdk_refuses_start(monkeypatch):
    import builtins

    monkeypatch.setenv("KEYSTONE_MCP_OTEL_ENABLED", "true")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", BASE_URL)
    real_import = builtins.__import__

    def _fake_import(name, globals=None, locals=None, fromlist=(), level=0):  # noqa: ANN001
        if name.startswith("opentelemetry.sdk") or name.startswith("opentelemetry.exporter"):
            raise ImportError("blocked for test")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    settings = load_settings()
    from keystone_mcp.observability.tracing import configure_tracing

    with pytest.raises(ConfigError, match="otel extra"):
        configure_tracing(settings)
