"""Shared fixtures + a helper that drives the full OAuth flow like a client.

The helper emulates exactly what Claude Desktop's OAuth connector does:
discovery (PRM -> ASM) -> dynamic client registration -> /authorize with PKCE
S256 + resource indicator -> login -> code exchange at /token.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import httpx2
import pytest
import pytest_asyncio
from fastmcp.utilities.tests import ASGIServer, asgi_server

from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server

VALID_TOKEN = "valid-test-token"
BASE_URL = "http://localhost:8080"
REDIRECT_URI = "http://localhost:9999/callback"


@pytest.fixture(autouse=True)
def _allow_insecure_upstream_http_for_tests(monkeypatch):
    """Most tests use cleartext docker-style upstream URLs in JSON env."""
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP", "true")
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE", "true")


@pytest.fixture(autouse=True)
def _default_deployment_profile_to_local(monkeypatch):
    """Most tests rely on RBAC_MODE=off and DEV tokens, which `production` refuses.

    ``KEYSTONE_MCP_DEPLOYMENT_PROFILE`` defaults to ``production`` (A04); without
    this, almost every test in the suite would need to set it explicitly. A test
    of the `production` profile itself sets the variable directly, which
    overrides this fixture's `monkeypatch.setenv` for that one test.
    """
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")


@pytest.fixture(autouse=True)
def _isolated_users_db(monkeypatch, tmp_path):
    """Point the built-in users directory at a per-test SQLite file.

    Without this, any test that builds a server (``users_backend`` now
    defaults to ``local``) would migrate and write to ``./keystone-users.db``
    in the repository root instead of an isolated temporary database.
    """
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{tmp_path}/keystone-users.db")


@pytest.fixture(autouse=True)
def _disable_dotenv_loading_for_tests(monkeypatch):
    """Isolate the suite from a developer's own .env in the repo root.

    ``cli.main`` (called with an explicit ``argv`` by several tests) now loads
    an env file as its first step (see keystone_mcp.env_file.load_env_file).
    Without this, a real ``.env`` sitting in the working directory the suite
    runs from would leak into every test. Tests of the loader itself remove
    this with ``monkeypatch.delenv`` to exercise the real default-file lookup.
    """
    monkeypatch.setenv("KEYSTONE_MCP_ENV_FILE", "")


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
    idp = StaticIdentityProvider({VALID_TOKEN})
    store = InMemoryOAuthStore()
    mcp, registry, oauth, _upstreams, _policy_manager, _observability, _reconciler = build_server(
        identity_provider=idp, settings=settings, oauth_store=store
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
