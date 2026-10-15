"""Anti-framing and CSP headers on the login page's HTML responses.

These responses carry the api_token and, once the consent screen ships, a consent screen —
blocking embedding in a hidden iframe (clickjacking) matters here even though
the page has no cookies yet.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from support.login import dev_token_login
from support.oauth_harness import BASE_URL, REDIRECT_URI, VALID_TOKEN, authorize_to_login, make_pkce

PROVIDER_PATH = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "keystone_mcp"
    / "auth"
    / "keystone_oauth_provider.py"
)


def _build_app(**settings_overrides):
    settings = Settings(base_url=BASE_URL, refresh_interval_seconds=0, **settings_overrides)
    _login = dev_token_login({VALID_TOKEN})
    store = InMemoryOAuthStore()
    mcp, *_rest = build_server(
        login_providers=[_login],
        settings=settings,
        oauth_store=store,
        register_builtin_catalog=False,
    )
    return mcp.http_app(path=settings.http_path)


def _assert_security_headers(response: httpx.Response) -> None:
    assert response.headers.get("x-frame-options") == "DENY"
    csp = response.headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'none'" in csp
    assert response.headers.get("referrer-policy") == "no-referrer"
    assert "no-store" in response.headers.get("cache-control", "")


@pytest.mark.asyncio
async def test_get_login_with_live_txn_has_security_headers():
    app = _build_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
            )
            client_id = r.json()["client_id"]
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, BASE_URL)

            resp = await client.get("/login", params={"txn": txn})
            assert resp.status_code == 200
            _assert_security_headers(resp)


@pytest.mark.asyncio
async def test_get_login_with_bad_txn_has_security_headers():
    app = _build_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            resp = await client.get("/login", params={"txn": "bad"})
            assert resp.status_code == 400
            _assert_security_headers(resp)


@pytest.mark.asyncio
async def test_post_login_with_invalid_token_has_security_headers():
    app = _build_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
            )
            client_id = r.json()["client_id"]
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, BASE_URL)

            resp = await client.post(
                "/login",
                data={"txn": txn, "api_token": "wrong-token", "email": "user@example.com"},
            )
            assert resp.status_code == 401
            _assert_security_headers(resp)


@pytest.mark.asyncio
async def test_get_login_google_disabled_has_security_headers():
    """With Google disabled, no ``/login/google`` route is registered at all.

    Keystone only registers a route per *configured* redirect login
    provider, so this is now a bare Starlette 404 rather than a Keystone
    error page — it carries no security headers of Keystone's own, since
    no Keystone handler ever runs for it.
    """
    app = _build_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            resp = await client.get("/login/google", params={"txn": "x"})
            assert resp.status_code == 404


@pytest.mark.asyncio
async def test_successful_login_redirect_has_no_csp():
    app = _build_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
            )
            client_id = r.json()["client_id"]
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, BASE_URL)

            resp = await client.post(
                "/login",
                data={"txn": txn, "api_token": VALID_TOKEN, "email": "user@example.com"},
            )
            assert resp.status_code == 302
            assert "content-security-policy" not in resp.headers
            assert "x-frame-options" not in resp.headers


def test_provider_has_no_raw_html_responses():
    """``HTMLResponse(`` must only appear inside ``_html_response`` itself."""
    source = PROVIDER_PATH.read_text(encoding="utf-8")
    assert len(re.findall(r"HTMLResponse\(", source)) == 1
