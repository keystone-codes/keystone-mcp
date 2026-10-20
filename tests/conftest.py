"""Shared fixtures + a helper that drives the full OAuth flow like a client.

The helper emulates exactly what Claude Desktop's OAuth connector does:
discovery (PRM -> ASM) -> dynamic client registration -> /authorize with PKCE
S256 + resource indicator -> login -> code exchange at /token.
"""

from __future__ import annotations

import os
import warnings

import httpx2
import pytest
import pytest_asyncio
import redis
from fastmcp.utilities.tests import asgi_server

from keystone_mcp import server
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import _http_asgi_middleware, build_server
from support.login import dev_token_login
from support.oauth_harness import (
    BASE_URL,
    REDIRECT_URI,
    VALID_TOKEN,
    Harness,
    authorize_to_login,
    make_pkce,
    obtain_access_token,
    refresh_access_token,
    register_client,
)
from support.test_env import (
    RUN_KEY_ROOT,
    policy_revision_key,
    real_redis_url,
    redis_key_prefix,
    users_revision_key,
)

pytest_plugins = ["support.test_env"]

__all__ = [
    "BASE_URL",
    "Harness",
    "REDIRECT_URI",
    "VALID_TOKEN",
    "authorize_to_login",
    "make_pkce",
    "obtain_access_token",
    "refresh_access_token",
    "register_client",
]


@pytest.fixture(autouse=True)
def _reset_subject_salt():
    from keystone_mcp.observability.subject import configure_subject_salt

    configure_subject_salt("")
    yield
    configure_subject_salt("")


@pytest.fixture(autouse=True)
def _isolated_keystone_env(monkeypatch, tmp_path):
    """Scrub stray ``KEYSTONE_MCP_*`` from the shell and set known-good defaults."""
    for key in list(os.environ):
        if key.startswith("KEYSTONE_MCP_") and key != "KEYSTONE_MCP_REDIS_URL":
            monkeypatch.delenv(key, raising=False)

    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP", "true")
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE", "true")
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{tmp_path}/keystone-users.db")
    monkeypatch.setenv("KEYSTONE_MCP_ENV_FILE", "")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_KEY_PREFIX", redis_key_prefix("oauth"))
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_PENDING_KEY_PREFIX", redis_key_prefix("login"))
    monkeypatch.setenv("KEYSTONE_MCP_USERS_REDIS_REVISION_KEY", users_revision_key())
    monkeypatch.setenv("KEYSTONE_MCP_POLICY_REDIS_REVISION_KEY", policy_revision_key())


@pytest.fixture(autouse=True)
def _reset_deferred_bootstrap_holders():
    """Reset the module-global startup holders before and after every test.

    A few tests (``test_server_main.py``, ``test_shutdown_grace.py``) call
    the real ``server.main()`` with a stubbed ``build_server`` that returns
    ``upstreams=None``, to check an unrelated detail (an env file, a uvicorn
    kwarg). ``main()`` unconditionally sets
    ``server._deferred_bootstrap_holder["factory"]`` to a closure over
    whatever ``build_server`` returned, win or lose. Left in place, the next
    test that starts the real ASGI lifespan -- most of the suite -- runs
    that stale closure as a background task, which immediately raises
    (``'NoneType' object has no attribute 'start_connections'``) and reaches
    a startup refusal that the test never substituted a fake for.
    """
    server._deferred_bootstrap_holder["factory"] = None
    server._bootstrap_state_holder["state"] = None
    server._startup_failure_holder["error"] = None
    yield
    server._deferred_bootstrap_holder["factory"] = None
    server._bootstrap_state_holder["state"] = None
    server._startup_failure_holder["error"] = None


@pytest.fixture(autouse=True)
def _guard_request_shutdown(monkeypatch):
    """Never let a real startup refusal send SIGTERM to the test process.

    ``server._request_shutdown`` defaults to ``os.kill(os.getpid(), SIGTERM)``:
    correct for a real gateway, fatal for the test run, since it kills the
    whole ``pytest`` process from deep inside a single test with no final
    summary line. This fixture replaces it with a recorder before every
    test. A test that substitutes its own fake (as
    ``test_server_startup_order.py`` does) layers its fake on top of this
    one via the same ``monkeypatch`` fixture, and is left alone. Any other
    test whose code path reaches a real startup refusal fails loudly
    instead of killing the run.
    """
    calls: list[BaseException | None] = []

    def _record() -> None:
        calls.append(server._startup_failure_holder.get("error"))

    monkeypatch.setattr(server, "_request_shutdown", _record)
    yield
    if calls and server._request_shutdown is _record:
        pytest.fail(f"startup refused during the test: {calls[-1]!r}")


@pytest.fixture(scope="session", autouse=True)
def _cleanup_run_keys():
    yield
    url = real_redis_url()
    if not url:
        return
    try:
        client = redis.Redis.from_url(url, decode_responses=False)
        cursor = 0
        while True:
            cursor, keys = client.scan(cursor, match=f"{RUN_KEY_ROOT}*", count=500)
            if keys:
                client.delete(*keys)
            if cursor == 0:
                break
    except OSError as exc:
        warnings.warn(f"Redis run-key cleanup failed: {exc}", stacklevel=1)


@pytest_asyncio.fixture
async def harness():
    settings = Settings(base_url=BASE_URL, refresh_interval_seconds=0)
    store = InMemoryOAuthStore()
    mcp, registry, oauth, _upstreams, _policy_manager, _observability, _reconciler = build_server(
        settings=settings,
        oauth_store=store,
        login_providers=[dev_token_login({VALID_TOKEN})],
    )
    async with asgi_server(mcp, path=settings.http_path) as running:
        # Not ``running.http_client()``: that client's transport owns an anyio
        # task group that must be entered and exited by the same asyncio
        # task, but pytest-asyncio runs an async-generator fixture's setup and
        # its teardown (after `yield`) as two different tasks, which trips
        # anyio's "exit cancel scope in a different task" guard. The plain
        # HTTP OAuth endpoints this client talks to (/register, /authorize,
        # /login, /token) never stream, so the classic, non-streaming
        # ``httpx2.ASGITransport`` -- which owns no such task group -- serves
        # them just as well and survives spanning the fixture's yield.
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=running.app), base_url=BASE_URL
        ) as client:
            yield Harness(
                running=running, registry=registry, oauth=oauth, settings=settings, client=client
            )


@pytest_asyncio.fixture
async def production_http_harness():
    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        deployment_profile="local",
        log_access_enabled=True,
    )
    store = InMemoryOAuthStore()
    mcp, registry, oauth, _upstreams, _policy_manager, _observability, _reconciler = build_server(
        settings=settings,
        oauth_store=store,
        login_providers=[dev_token_login({VALID_TOKEN})],
    )
    async with asgi_server(
        mcp,
        path=settings.http_path,
        middleware=_http_asgi_middleware(settings),
    ) as running:
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=running.app), base_url=BASE_URL
        ) as client:
            yield Harness(
                running=running, registry=registry, oauth=oauth, settings=settings, client=client
            )


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--snapshot-update",
        action="store_true",
        default=False,
        help="Rewrite HTML snapshots under tests/data/login-pages/",
    )


@pytest.fixture
def snapshot_update(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--snapshot-update"))
