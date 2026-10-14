"""Tests for ``GET /readyz``: Redis, active RBAC policy, users-directory ping.

Unlike ``/healthz`` (process alive, never fails -- see ``test_healthz_unchanged``
below), ``/readyz`` answers whether this replica can actually serve work.
Detail (``checks``) is shown only to callers judged internal the same way
``/metrics`` is (see ``test_internal_endpoints.py``), but -- unlike
``/metrics`` -- an external caller is never refused: it just gets the coarse
``ok``/``degraded`` status with no per-check detail, and no WARNING is logged
for that (a load balancer polls every few seconds from every replica).
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.login_pending_store import InMemoryLoginPendingStore
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.http.readiness import ReadinessProbe
from keystone_mcp.rbac.policy import hash_policy_bytes
from keystone_mcp.server import bootstrap_rbac_policy, build_server
from support.login import dev_token_login
from support.test_env import require_redis_url

BASE_URL = "http://localhost:8080"
STDIO_SERVER = str(Path(__file__).parent / "support" / "stdio_upstream.py")

RBAC_POLICY = """\
version: "1.0.0"
default_deny: true
roles:
  administrator:
    allow: ["e2e_ping"]
requires_human_identity: []
critical_tools: []
"""


@pytest.fixture
def redis_url() -> str:
    url = require_redis_url()
    return url


async def _get(app, path: str, *, client_host: str, headers=None):
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=(client_host, 12345)),
            base_url=BASE_URL,
        ) as client:
            return await client.get(path, headers=headers)


def _app(settings: Settings, **build_kwargs):
    mcp, *_rest = build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        register_builtin_catalog=False,
        **build_kwargs,
    )
    return mcp.http_app(path=settings.http_path)


# ── /healthz is untouched by /readyz ────────────────────────────────────────
async def test_healthz_unchanged():
    settings = Settings(base_url=BASE_URL)
    app = _app(settings, oauth_store=InMemoryOAuthStore())
    response = await _get(app, "/healthz", client_host="203.0.113.1")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


# ── No dependencies configured: everything is skipped, readiness is ok ─────
async def test_readyz_ok_without_dependencies():
    settings = Settings(base_url=BASE_URL)
    app = _app(settings, oauth_store=InMemoryOAuthStore())
    response = await _get(app, "/readyz", client_host="203.0.113.1")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_readyz_internal_caller_sees_checks():
    settings = Settings(base_url=BASE_URL)
    app = _app(settings, oauth_store=InMemoryOAuthStore())
    response = await _get(app, "/readyz", client_host="127.0.0.1")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["checks"] == {
        "redis": "skipped",
        "rbac_policy": "skipped",
        "users_directory": "skipped",
        "bootstrap": "ok",
    }


async def test_readyz_details_need_allowed_host():
    settings = Settings(base_url=BASE_URL)
    app = _app(settings, oauth_store=InMemoryOAuthStore())
    evil = await _get(
        app,
        "/readyz",
        client_host="127.0.0.1",
        headers={"Host": "evil.com"},
    )
    assert evil.status_code in (200, 503)
    evil_body = evil.json()
    assert "checks" not in evil_body
    assert "upstreams" not in evil_body

    localhost = await _get(
        app,
        "/readyz",
        client_host="127.0.0.1",
        headers={"Host": "localhost:8080"},
    )
    assert "checks" in localhost.json()

    by_ip = await _get(
        app,
        "/readyz",
        client_host="127.0.0.1",
        headers={"Host": "127.0.0.1:8080"},
    )
    assert "checks" in by_ip.json()


async def test_readyz_forwarded_request_gets_no_checks():
    settings = Settings(base_url=BASE_URL)
    app = _app(settings, oauth_store=InMemoryOAuthStore())
    response = await _get(
        app,
        "/readyz",
        client_host="127.0.0.1",
        headers={"X-Forwarded-For": "203.0.113.1"},
    )
    assert "checks" not in response.json()


# ── Redis ────────────────────────────────────────────────────────────────────
class _PingFails:
    """Stands in for a Redis client whose ``ping`` raises."""

    async def ping(self) -> None:
        raise ConnectionError("redis down")


async def test_readyz_redis_down_is_503():
    settings = Settings(base_url=BASE_URL)
    store = InMemoryOAuthStore()
    store.redis = _PingFails()  # the only attribute ReadinessProbe reads off `store`
    app = _app(
        settings,
        oauth_store=store,
        login_pending_store=InMemoryLoginPendingStore(),
    )
    response = await _get(app, "/readyz", client_host="127.0.0.1")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["redis"] == "fail"


async def test_readyz_redis_timeout_is_503():
    """``timeout_seconds`` is a server.py-internal constant, so this drives
    :class:`ReadinessProbe` directly rather than through the constructed app.
    """

    class _SlowPing:
        async def ping(self) -> None:
            await asyncio.sleep(5)

    probe = ReadinessProbe(
        redis=_SlowPing(),
        policy_manager=None,
        users_backend=None,
        timeout_seconds=0.1,
    )
    report = await probe.run()
    assert report.ready is False
    assert report.checks["redis"] == "fail"


async def test_readyz_real_redis_ok(redis_url: str):
    settings = Settings(base_url=BASE_URL, redis_url=redis_url)
    app = _app(settings)  # oauth_store=None -> build_server wires real Redis
    response = await _get(app, "/readyz", client_host="127.0.0.1")
    assert response.status_code == 200
    assert response.json()["checks"]["redis"] == "ok"


# ── RBAC policy ──────────────────────────────────────────────────────────────
def _rbac_settings(tmp_path: Path) -> Settings:
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(RBAC_POLICY, encoding="utf-8")
    return Settings(
        base_url=BASE_URL,
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        rbac_audit_subject_salt="test-readyz-salt",
    )


async def test_readyz_rbac_policy_not_loaded_is_503(tmp_path: Path):
    settings = _rbac_settings(tmp_path)
    mcp, registry, _oauth, _upstreams, _policy_manager, _observability, _reconciler = build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    registry.add_route("e2e_ping", StubAdapter(), mode="live", description="test route")
    app = mcp.http_app(path=settings.http_path)
    # No bootstrap_rbac_policy call: the policy has never been loaded.
    response = await _get(app, "/readyz", client_host="127.0.0.1")
    assert response.status_code == 503
    assert response.json()["checks"]["rbac_policy"] == "fail"


async def test_readyz_rbac_policy_loaded_is_ok(tmp_path: Path):
    settings = _rbac_settings(tmp_path)
    mcp, registry, _oauth, _upstreams, policy_manager, _observability, _reconciler = build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    registry.add_route("e2e_ping", StubAdapter(), mode="live", description="test route")
    bootstrap_rbac_policy(policy_manager, registry)
    app = mcp.http_app(path=settings.http_path)
    response = await _get(app, "/readyz", client_host="127.0.0.1")
    assert response.status_code == 200
    assert response.json()["checks"]["rbac_policy"] == "ok"


# ── Users directory ──────────────────────────────────────────────────────────
class _FailingPingBackend:
    async def ping(self) -> None:
        raise RuntimeError("database is gone")


class _HttpLikeBackendNoPing:
    """Mimics ``HttpUserDirectoryBackend``: no ``ping`` method at all."""

    async def resolve_user(self, email: str):  # pragma: no cover - not exercised
        raise NotImplementedError

    async def aclose(self) -> None:
        return None


class _StubDirectoryResolver:
    """Duck-types just enough of ``UserDirectoryResolver`` for this test.

    ``build_server`` only reads ``.backend`` off it for the readiness probe;
    it never calls ``.resolve()`` here because the test never makes an
    authenticated tool call.
    """

    def __init__(self, backend: object) -> None:
        self.backend = backend


async def _rbac_app_with_backend(tmp_path: Path, backend: object):
    settings = _rbac_settings(tmp_path)
    mcp, registry, _oauth, _upstreams, policy_manager, _observability, _reconciler = build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=_StubDirectoryResolver(backend),
        register_builtin_catalog=False,
    )
    registry.add_route("e2e_ping", StubAdapter(), mode="live", description="test route")
    bootstrap_rbac_policy(policy_manager, registry)
    return mcp.http_app(path=settings.http_path)


async def test_readyz_users_backend_ping_failure_is_503(tmp_path: Path):
    app = await _rbac_app_with_backend(tmp_path, _FailingPingBackend())
    response = await _get(app, "/readyz", client_host="127.0.0.1")
    assert response.status_code == 503
    body = response.json()
    assert body["checks"]["users_directory"] == "fail"
    assert body["checks"]["rbac_policy"] == "ok"  # isolates the failing check


async def test_readyz_http_users_backend_is_skipped(tmp_path: Path):
    app = await _rbac_app_with_backend(tmp_path, _HttpLikeBackendNoPing())
    response = await _get(app, "/readyz", client_host="127.0.0.1")
    assert response.status_code == 200
    assert response.json()["checks"]["users_directory"] == "skipped"


def _build_app_with_stdio_upstream(monkeypatch: pytest.MonkeyPatch, **settings_kw: object) -> tuple:
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(
            [
                {
                    "name": "notes",
                    "namespace": "notes",
                    "transport": "stdio",
                    "command": sys.executable,
                    "args": [STDIO_SERVER],
                    "enabled": True,
                }
            ]
        ),
    )
    settings = Settings(base_url=BASE_URL, **settings_kw)
    built = build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    return built[0], built[3], settings


async def test_readyz_internal_body_lists_upstreams(monkeypatch: pytest.MonkeyPatch):
    mcp, upstreams, settings = _build_app_with_stdio_upstream(monkeypatch)
    assert "notes" in upstreams._sub_servers
    app = mcp.http_app(path=settings.http_path)
    response = await _get(app, "/readyz", client_host="127.0.0.1")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "notes" in body["upstreams"]
    assert body["upstreams"]["notes"]["transport"] == "stdio"


async def _noop_start_connections(*, wait: float | None = None) -> None:
    return


async def test_readyz_ignores_unavailable_upstream_by_default(monkeypatch: pytest.MonkeyPatch):
    mcp, upstreams, settings = _build_app_with_stdio_upstream(monkeypatch)
    monkeypatch.setattr(upstreams, "start_connections", _noop_start_connections)
    upstreams.mark_unavailable("notes", "down for test")
    app = mcp.http_app(path=settings.http_path)
    response = await _get(app, "/readyz", client_host="127.0.0.1")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["upstreams"]["notes"]["available"] is False
    assert "upstreams" not in body.get("checks", {})


async def test_readyz_require_all_fails_when_upstream_unavailable(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL", "true")
    mcp, upstreams, settings = _build_app_with_stdio_upstream(
        monkeypatch, upstream_require_all=True
    )
    monkeypatch.setattr(upstreams, "start_connections", _noop_start_connections)
    upstreams.mark_unavailable("notes", "down for test")
    app = mcp.http_app(path=settings.http_path)
    response = await _get(app, "/readyz", client_host="127.0.0.1")
    assert response.status_code == 503
    body = response.json()
    assert body["checks"]["upstreams"] == "fail"
    assert body["upstreams"]["notes"]["available"] is False


# ── Logging: one WARNING per degradation, not one per poll ──────────────────
async def test_readyz_logs_degradation_once(caplog: pytest.LogCaptureFixture):
    class _AlwaysFails:
        async def ping(self) -> None:
            raise ConnectionError("down")

    probe = ReadinessProbe(redis=_AlwaysFails(), policy_manager=None, users_backend=None)
    with caplog.at_level(logging.WARNING, logger="keystone_mcp.http.readiness"):
        await probe.run()
        await probe.run()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "readiness degraded" in warnings[0].message
    assert "redis=fail" in warnings[0].message


async def test_readyz_internal_caller_sees_policy_content_hash(
    tmp_path: Path,
    redis_url: str,
):
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_bytes = RBAC_POLICY.encode("utf-8")
    policy_path.write_bytes(policy_bytes)
    settings = Settings(
        base_url=BASE_URL,
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        rbac_audit_subject_salt="test-readyz-salt",
        redis_url=redis_url,
    )
    mcp, registry, _oauth, _upstreams, policy_manager, _observability, _reconciler = build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        register_builtin_catalog=False,
    )
    registry.add_route("e2e_ping", StubAdapter(), mode="live", description="test route")
    bootstrap_rbac_policy(policy_manager, registry)
    app = mcp.http_app(path=settings.http_path)
    response = await _get(app, "/readyz", client_host="127.0.0.1")
    body = response.json()
    assert body["policy_content_hash"] == hash_policy_bytes(policy_bytes)
    assert body["policy_in_sync"] is None


async def test_readyz_external_caller_does_not_see_policy_hash(tmp_path: Path):
    settings = _rbac_settings(tmp_path)
    mcp, registry, _oauth, _upstreams, policy_manager, _observability, _reconciler = build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    registry.add_route("e2e_ping", StubAdapter(), mode="live", description="test route")
    bootstrap_rbac_policy(policy_manager, registry)
    app = mcp.http_app(path=settings.http_path)
    response = await _get(app, "/readyz", client_host="203.0.113.1")
    body = response.json()
    assert "policy_content_hash" not in body
    assert "policy_in_sync" not in body
