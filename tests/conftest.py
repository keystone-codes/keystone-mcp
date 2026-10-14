"""Shared fixtures + a helper that drives the full OAuth flow like a client.

The helper emulates exactly what Claude Desktop's OAuth connector does:
discovery (PRM -> ASM) -> dynamic client registration -> /authorize with PKCE
S256 + resource indicator -> login -> code exchange at /token.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import warnings
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
import pytest_asyncio
import redis
from fastmcp.utilities.tests import ASGIServer, asgi_server

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import _http_asgi_middleware, build_server
from support.login import dev_token_login
from support.test_env import (
    RUN_KEY_ROOT,
    policy_revision_key,
    real_redis_url,
    redis_key_prefix,
    users_revision_key,
)

pytest_plugins = ["support.test_env"]

VALID_TOKEN = "valid-test-token"
BASE_URL = "http://localhost:8080"
REDIRECT_URI = "http://localhost:9999/callback"


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


def make_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


@dataclass
class Harness:
    running: ASGIServer
    registry: object
    oauth: object
    settings: Settings
    client: httpx2.AsyncClient

    def mcp_client_factory(self):
        """An ``McpHttpClientFactory`` reaching this harness's in-process app.

        ``ASGIServer.http_client`` (``fastmcp.utilities.tests``) already
        matches that protocol's signature, so no wrapper is needed.
        """
        return self.running.http_client


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


async def refresh_access_token(
    client: httpx2.AsyncClient,
    client_id: str,
    refresh_token: str,
    resource: str,
) -> dict:
    """Exchange a refresh token at /token."""
    r = await client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "resource": resource,
        },
    )
    return {
        "status": r.status_code,
        "body": r.json() if r.content else {},
        "client_id": client_id,
    }


async def register_client(client: httpx2.AsyncClient, client_name: str | None = None) -> str:
    payload: dict[str, object] = {
        "redirect_uris": [REDIRECT_URI],
        "token_endpoint_auth_method": "none",
    }
    if client_name is not None:
        payload["client_name"] = client_name
    r = await client.post("/register", json=payload)
    assert r.status_code in (200, 201), r.text
    return r.json()["client_id"]


async def authorize_to_login(
    client: httpx2.AsyncClient, client_id: str, challenge: str, resource: str
) -> str:
    """Run /authorize and return the login transaction id from the redirect."""
    r = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "test-state",
            "resource": resource,
        },
    )
    assert r.status_code in (302, 307), r.text
    return parse_qs(urlparse(r.headers["location"]).query)["txn"][0]


async def obtain_access_token(
    client: httpx2.AsyncClient,
    resource: str,
    api_token: str = VALID_TOKEN,
    email: str = "user@example.com",
) -> dict:
    """Full happy-path OAuth flow; returns the parsed /token JSON response."""
    client_id = await register_client(client)
    verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, resource)
    r = await client.post("/login", data={"txn": txn, "api_token": api_token, "email": email})
    assert r.status_code == 302, r.text
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    r = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": resource,
        },
    )
    return {
        "status": r.status_code,
        "body": r.json() if r.content else {},
        "client_id": client_id,
    }


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
