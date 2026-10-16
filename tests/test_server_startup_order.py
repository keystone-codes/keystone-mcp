"""HTTP port opens before upstream discovery; deferred bootstrap and /readyz."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from asgi_lifespan import LifespanManager
from fastmcp.utilities.tests import asgi_server

from keystone_mcp import server
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.http.readiness import BootstrapState
from keystone_mcp.rbac.loader import PolicyLoadError
from keystone_mcp.router.upstream import UpstreamUnavailableError
from keystone_mcp.server import build_server, run_deferred_bootstrap
from support.login import dev_token_login
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)

BASE_URL = "http://localhost:8080"
VALID_TOKEN = "valid-test-token"

RBAC_POLICY = """\
version: "1.0.0"
default_deny: true
roles:
  administrator:
    allow: ["hello_greet"]
requires_human_identity: []
critical_tools: []
"""


def _clear_deferred_holders() -> None:
    server._deferred_bootstrap_holder["factory"] = None
    server._bootstrap_state_holder["state"] = None
    server._startup_failure_holder["error"] = None


@pytest.fixture(autouse=True)
def _reset_deferred_holders():
    _clear_deferred_holders()
    yield
    _clear_deferred_holders()


def _settings(**overrides) -> Settings:
    overrides.setdefault("refresh_interval_seconds", 3600)
    overrides.setdefault("upstream_discovery_retries", 1)
    overrides.setdefault("upstream_discovery_timeout_seconds", 30.0)
    return Settings(base_url=BASE_URL, **overrides)


def _wire_deferred(
    settings: Settings,
    *,
    upstream_app=None,
    discovery_gate: asyncio.Event | None = None,
    policy_path: Path | None = None,
    rbac_mode: str = "off",
    upstream_require_all: bool = False,
    login_providers=None,
):
    state = BootstrapState(deferred=True)
    server._bootstrap_state_holder["state"] = state
    providers = login_providers if login_providers is not None else [dev_token_login({VALID_TOKEN})]
    mcp, registry, _oauth, upstreams, policy_manager, observability, reconciler = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        login_providers=providers,
        register_builtin_catalog=False,
    )
    if upstream_app is not None:
        upstreams.http_client_factory = asgi_http_client_factory(upstream_app)
        upstreams.add_upstream("hello", UPSTREAM_MCP_URL, namespace="hello")
    if discovery_gate is not None:
        real_discover = upstreams.discover_all

        async def _gated_discover() -> dict[str, int]:
            await discovery_gate.wait()
            return await real_discover()

        upstreams.discover_all = _gated_discover  # type: ignore[method-assign]
    if policy_path is not None:
        assert policy_manager is not None

    async def _factory() -> None:
        await run_deferred_bootstrap(
            upstreams,
            registry,
            settings,
            policy_manager,
            observability=observability,
            login_providers=providers,
            reconciler=reconciler,
            state=state,
        )

    server._deferred_bootstrap_holder["factory"] = _factory
    return mcp, registry, upstreams, policy_manager, state, settings


async def test_port_opens_before_upstream_discovery():
    gate = asyncio.Event()
    settings = _settings()
    upstream_app = build_lowlevel_upstream_app()
    mcp, registry, _upstreams, _pm, state, settings = _wire_deferred(
        settings,
        upstream_app=upstream_app,
        discovery_gate=gate,
    )

    async with LifespanManager(upstream_app):
        async with asgi_server(mcp, path=settings.http_path) as running:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=running.app, client=("127.0.0.1", 12345)),
                base_url=BASE_URL,
            ) as client:
                health = await client.get("/healthz")
                assert health.status_code == 200

                ready = await client.get("/readyz")
                assert ready.status_code == 503
                body = ready.json()
                assert body["checks"]["bootstrap"] == "pending"

                gate.set()
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    if state.status == "ready":
                        break
                    await asyncio.sleep(0.05)
                assert state.status == "ready"

                ready2 = await client.get("/readyz")
                assert ready2.status_code == 200
                assert ready2.json()["checks"]["bootstrap"] == "ok"

                assert registry.owner_of_published_name("hello_greet") is not None


async def test_readyz_pending_when_rbac_off():
    gate = asyncio.Event()
    settings = _settings(rbac_mode="off")
    upstream_app = build_lowlevel_upstream_app()
    mcp, _registry, _upstreams, policy_manager, state, settings = _wire_deferred(
        settings,
        upstream_app=upstream_app,
        discovery_gate=gate,
    )
    assert policy_manager is None

    async with LifespanManager(upstream_app):
        async with asgi_server(mcp, path=settings.http_path) as running:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=running.app, client=("127.0.0.1", 12345)),
                base_url=BASE_URL,
            ) as client:
                ready = await client.get("/readyz")
                assert ready.status_code == 503
                assert ready.json()["checks"]["bootstrap"] == "pending"
                assert ready.json()["checks"]["rbac_policy"] == "skipped"

                gate.set()
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline and state.status != "ready":
                    await asyncio.sleep(0.05)
                assert state.status == "ready"


async def test_require_all_failure_exits_after_listening(monkeypatch: pytest.MonkeyPatch):
    shutdown_calls: list[int] = []

    def _fake_shutdown() -> None:
        shutdown_calls.append(1)

    monkeypatch.setattr(server, "_request_shutdown", _fake_shutdown)

    settings = _settings(
        upstream_require_all=True,
        upstream_discovery_retries=1,
        upstream_discovery_timeout_seconds=1.0,
    )
    state = BootstrapState(deferred=True)
    server._bootstrap_state_holder["state"] = state
    mcp, registry, _oauth, upstreams, policy_manager, observability, reconciler = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        login_providers=[dev_token_login({VALID_TOKEN})],
        register_builtin_catalog=False,
    )
    upstreams.add_upstream("ghost", "http://10.255.255.254:59999/mcp", namespace="ghost")

    async def _factory() -> None:
        await run_deferred_bootstrap(
            upstreams,
            registry,
            settings,
            policy_manager,
            observability=observability,
            login_providers=[dev_token_login({VALID_TOKEN})],
            reconciler=reconciler,
            state=state,
        )

    server._deferred_bootstrap_holder["factory"] = _factory

    async with asgi_server(mcp, path=settings.http_path) as running:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=running.app, client=("127.0.0.1", 12345)),
            base_url=BASE_URL,
        ) as client:
            assert (await client.get("/healthz")).status_code == 200
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and state.status != "failed":
                await asyncio.sleep(0.05)
            ready = await client.get("/readyz")
            assert ready.status_code == 503
            assert ready.json()["checks"]["bootstrap"] == "fail"

    assert len(shutdown_calls) == 1
    err = server._startup_failure_holder["error"]
    assert isinstance(err, UpstreamUnavailableError)
    assert "KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true" in str(err)


async def test_policy_error_exits_after_listening(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    shutdown_calls: list[int] = []

    def _fake_shutdown() -> None:
        shutdown_calls.append(1)

    monkeypatch.setattr(server, "_request_shutdown", _fake_shutdown)

    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text("roles: not-a-mapping\n", encoding="utf-8")
    settings = _settings(
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        rbac_audit_subject_salt="startup-order-test",
        upstream_discovery_retries=1,
    )
    upstream_app = build_lowlevel_upstream_app()
    mcp, registry, upstreams, policy_manager, state, settings = _wire_deferred(
        settings, upstream_app=upstream_app, policy_path=policy_path, rbac_mode="enforce"
    )

    async with asgi_server(mcp, path=settings.http_path) as running:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=running.app, client=("127.0.0.1", 12345)),
            base_url=BASE_URL,
        ) as client:
            assert (await client.get("/healthz")).status_code == 200
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and state.status != "failed":
                await asyncio.sleep(0.05)
            ready = await client.get("/readyz")
            assert ready.status_code == 503
            assert ready.json()["checks"]["bootstrap"] == "fail"

    assert len(shutdown_calls) == 1
    err = server._startup_failure_holder["error"]
    assert isinstance(err, PolicyLoadError)


def test_main_exits_1_when_deferred_bootstrap_failed(monkeypatch: pytest.MonkeyPatch):
    from unittest.mock import MagicMock

    fake_mcp = MagicMock()

    def _fake_build_server(*, settings):
        return (fake_mcp, None, None, None, None, None, None)

    async def _fake_bootstrap_users_store(*args, **kwargs):
        return None

    monkeypatch.setattr(server, "build_server", _fake_build_server)
    monkeypatch.setattr(server, "bootstrap_users_store", _fake_bootstrap_users_store)
    monkeypatch.setattr(server, "install_policy_reload_signal", lambda *a, **k: None)
    server._startup_failure_holder["error"] = UpstreamUnavailableError("boom")

    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 1


async def test_sighup_during_startup_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    import signal as signal_mod

    if not hasattr(signal_mod, "SIGHUP"):
        pytest.skip("SIGHUP not available on this platform")

    gate = asyncio.Event()
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(RBAC_POLICY, encoding="utf-8")
    settings = _settings(
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        rbac_audit_subject_salt="sighup-test",
    )
    upstream_app = build_lowlevel_upstream_app()
    mcp, registry, _upstreams, policy_manager, state, settings = _wire_deferred(
        settings,
        upstream_app=upstream_app,
        discovery_gate=gate,
        policy_path=policy_path,
        rbac_mode="enforce",
    )
    assert policy_manager is not None

    captured: list[Any] = []

    def fake_signal(signum, handler):
        captured.append(handler)

    monkeypatch.setattr(signal_mod, "signal", fake_signal)
    server.install_policy_reload_signal(
        registry, policy_manager, bootstrap_state=state, reconciler=None
    )
    assert captured
    handler = captured[0]

    async with LifespanManager(upstream_app):
        async with asgi_server(mcp, path=settings.http_path) as running:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=running.app, client=("127.0.0.1", 12345)),
                base_url=BASE_URL,
            ) as client:
                await client.get("/readyz")
                assert state.is_pending()
                with caplog.at_level("INFO", logger="keystone_mcp.server"):
                    handler(signal_mod.SIGHUP, None)
                assert any(
                    "SIGHUP ignored: startup still in progress" in r.message for r in caplog.records
                )

                gate.set()
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline and state.status != "ready":
                    await asyncio.sleep(0.05)


async def test_login_provider_warm_up_runs_in_parallel():
    from support.fake_login import FakeRedirectProvider

    class _SlowWarmUp(FakeRedirectProvider):
        async def warm_up(self) -> None:
            await asyncio.sleep(1)

    providers = [_SlowWarmUp("a"), _SlowWarmUp("b"), _SlowWarmUp("c")]
    settings = _settings()
    state = BootstrapState(deferred=True)
    server._bootstrap_state_holder["state"] = state
    mcp, registry, _oauth, upstreams, policy_manager, observability, reconciler = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        login_providers=providers,
        register_builtin_catalog=False,
    )

    async def _factory() -> None:
        await run_deferred_bootstrap(
            upstreams,
            registry,
            settings,
            policy_manager,
            observability=observability,
            login_providers=providers,
            reconciler=reconciler,
            state=state,
        )

    server._deferred_bootstrap_holder["factory"] = _factory

    started = time.monotonic()
    async with asgi_server(mcp, path=settings.http_path):
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and state.status != "ready":
            await asyncio.sleep(0.05)
    elapsed = time.monotonic() - started
    assert state.status == "ready"
    assert elapsed < 2.0
