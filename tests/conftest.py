"""Shared fixtures + a helper that drives the full OAuth flow like a client.

The helper emulates exactly what Claude Desktop's OAuth connector does:
discovery (PRM -> ASM) -> dynamic client registration -> /authorize with PKCE
S256 + resource indicator -> login -> code exchange at /token.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from fastmcp import Client

from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server

VALID_TOKEN = "valid-test-token"
BASE_URL = "http://localhost:8080"
REDIRECT_URI = "http://localhost:9999/callback"

# Streamable-HTTP MCP e2e tests flake when they run late in a long session (httpx
# ASGITransport + accumulated asyncio state). Run them first while keeping the
# rest of the suite order stable.
_EARLY_MCP_HTTP_E2E_TESTS = frozenset(
    {
        "test_identity_header_reaches_an_http_upstream_end_to_end",
        "test_tool_call_over_oauth_bearer",
        "test_viewer_lists_only_allowed_tools",
        "test_viewer_call_to_forbidden_tool_is_denied",
        "test_viewer_call_to_allowed_tool_succeeds",
        "test_blocked_user_is_denied_with_live_token",
        "test_fresh_server_admin_adds_member_who_cannot_see_users_tools",
        "test_nested_object_and_required_are_published_as_is",
        "test_output_schema_published_only_in_transparent_mode",
        "test_upstream_annotations_and_title_are_published",
        "test_proxy_tool_call_round_trip_with_raw_schema",
    }
)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    early: list[pytest.Item] = []
    rest: list[pytest.Item] = []
    for item in items:
        if item.name in _EARLY_MCP_HTTP_E2E_TESTS:
            early.append(item)
        else:
            rest.append(item)
    items[:] = early + rest


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


def _transient_mcp_client_error(exc: BaseException) -> bool:
    """True when a FastMCP client session open looks like a brief transport flake."""
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, RuntimeError):
        msg = str(exc).lower()
        return any(
            token in msg
            for token in (
                "connect",
                "connection",
                "session",
                "closed",
                "timeout",
                "handshake",
            )
        )
    if isinstance(exc, BaseExceptionGroup):
        return any(_transient_mcp_client_error(sub) for sub in exc.exceptions)
    return False


async def retry_transient_mcp_errors(
    fn: Callable[[], Awaitable[Any]],
    *,
    attempts: int = 8,
) -> Any:
    """Run an MCP client operation; retry brief ASGI/HTTP transport flakes."""
    last_error: BaseException | None = None
    for attempt in range(attempts):
        try:
            return await fn()
        except BaseExceptionGroup as exc:
            last_error = exc
            if attempt + 1 >= attempts or not _transient_mcp_client_error(exc):
                raise
        except Exception as exc:
            last_error = exc
            if attempt + 1 >= attempts or not _transient_mcp_client_error(exc):
                raise
        await asyncio.sleep(0.25 * (attempt + 1))
    if last_error is not None:
        raise last_error
    raise RuntimeError("retry_transient_mcp_errors exhausted without result")


@asynccontextmanager
async def mcp_client_session(
    transport=None,
    *,
    transport_factory: Callable[[], Any] | None = None,
    attempts: int = 8,
):
    """Enter a FastMCP client session; retry brief connect flakes on CI runners."""
    if transport is None and transport_factory is None:
        raise TypeError("transport or transport_factory is required")
    last_error: BaseException | None = None
    for attempt in range(attempts):
        active_transport = transport_factory() if transport_factory is not None else transport
        try:
            async with Client(active_transport) as client:
                yield client
                return
        except BaseExceptionGroup as exc:
            last_error = exc
            if attempt + 1 >= attempts or not _transient_mcp_client_error(exc):
                raise
        except Exception as exc:
            last_error = exc
            if attempt + 1 >= attempts or not _transient_mcp_client_error(exc):
                raise
        await asyncio.sleep(0.25 * (attempt + 1))
    if last_error is not None:
        raise last_error


def make_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


@dataclass
class Harness:
    app: object
    registry: object
    oauth: object
    settings: Settings
    client: httpx.AsyncClient

    def mcp_client_factory(self):
        app = self.app

        def factory(headers=None, timeout=None, auth=None, **_kw):
            return httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url=BASE_URL,
                headers=headers,
                timeout=timeout or httpx.Timeout(30.0),
                auth=auth,
                follow_redirects=True,
            )

        return factory


@pytest_asyncio.fixture
async def harness():
    settings = Settings(base_url=BASE_URL, refresh_interval_seconds=0)
    idp = StaticIdentityProvider({VALID_TOKEN})
    store = InMemoryOAuthStore()
    mcp, registry, oauth, _upstreams, _policy_manager, _observability, _reconciler = build_server(
        identity_provider=idp, settings=settings, oauth_store=store
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            yield Harness(app=app, registry=registry, oauth=oauth, settings=settings, client=client)


async def refresh_access_token(
    client: httpx.AsyncClient,
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


async def register_client(client: httpx.AsyncClient, client_name: str | None = None) -> str:
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
    client: httpx.AsyncClient, client_id: str, challenge: str, resource: str
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
    client: httpx.AsyncClient,
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
