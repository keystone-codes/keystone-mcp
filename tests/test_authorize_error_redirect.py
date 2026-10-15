"""Authorize error responses must not redirect to foreign redirect_uri hosts."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
from asgi_lifespan import LifespanManager
from mcp.shared.auth import OAuthClientInformationFull

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from support.login import dev_token_login
from support.oauth_harness import BASE_URL, REDIRECT_URI, VALID_TOKEN, make_pkce, register_client


def _build_app(*, oauth_store=None, **settings_overrides):
    settings = Settings(base_url=BASE_URL, refresh_interval_seconds=0, **settings_overrides)
    _login = dev_token_login({VALID_TOKEN})
    store = oauth_store if oauth_store is not None else InMemoryOAuthStore()
    mcp, *_rest = build_server(
        login_providers=[_login],
        settings=settings,
        oauth_store=store,
        register_builtin_catalog=False,
    )
    return mcp.http_app(path=settings.http_path), store


async def _register_evil_client(store: InMemoryOAuthStore) -> str:
    client = OAuthClientInformationFull(
        client_id="evil-client",
        redirect_uris=["https://evil.example/cb"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    await store.put_client(client)
    return client.client_id


async def test_authorize_error_to_foreign_host_shows_page() -> None:
    app, store = _build_app()
    client_id = await _register_evil_client(store)
    _verifier, challenge = make_pkce()
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "https://evil.example/cb",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "s",
        "scope": "zzz",
        "resource": BASE_URL,
    }
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.get("/authorize", params=params)
            assert r.status_code == 400
            assert "text/html" in r.headers.get("content-type", "")
            assert "location" not in {k.lower() for k in r.headers}
            assert "evil.example" not in r.text


async def test_authorize_missing_pkce_to_foreign_host_shows_page() -> None:
    app, store = _build_app()
    client_id = await _register_evil_client(store)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "https://evil.example/cb",
        "state": "s",
        "scope": "openid",
        "resource": BASE_URL,
    }
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.get("/authorize", params=params)
            assert r.status_code == 400
            assert "text/html" in r.headers.get("content-type", "")
            assert "evil.example" not in r.text


async def test_authorize_error_to_loopback_redirects() -> None:
    for redirect_uri in ("http://127.0.0.1:33418/cb", "http://[::1]:33418/cb"):
        app, store = _build_app()
        client = OAuthClientInformationFull(
            client_id=f"loopback-{redirect_uri}",
            redirect_uris=[redirect_uri],  # type: ignore[list-item]
            token_endpoint_auth_method="none",
        )
        await store.put_client(client)
        _verifier, challenge = make_pkce()
        params = {
            "response_type": "code",
            "client_id": client.client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "s",
            "scope": "zzz",
            "resource": BASE_URL,
        }
        async with LifespanManager(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url=BASE_URL
            ) as http:
                r = await http.get("/authorize", params=params)
                assert r.status_code in (302, 307), r.text
                location = r.headers["location"]
                assert urlparse(location).netloc == urlparse(redirect_uri).netloc
                assert parse_qs(urlparse(location).query).get("error") == ["invalid_scope"]


async def test_authorize_error_to_allowlisted_host_redirects() -> None:
    redirect_uri = "https://claude.ai/api/mcp/auth_callback"
    app, store = _build_app(oauth_allowed_redirect_hosts=("claude.ai",))
    client = OAuthClientInformationFull(
        client_id="claude-client",
        redirect_uris=[redirect_uri],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    await store.put_client(client)
    _verifier, challenge = make_pkce()
    params = {
        "response_type": "code",
        "client_id": client.client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "s",
        "scope": "zzz",
        "resource": BASE_URL,
    }
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as http:
            r = await http.get("/authorize", params=params)
            assert r.status_code in (302, 307), r.text
            assert "error=" in r.headers["location"]


async def test_authorize_success_unchanged() -> None:
    app, _store = _build_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            r = await client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": REDIRECT_URI,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "s",
                    "resource": BASE_URL,
                },
            )
            assert r.status_code in (302, 307), r.text
            assert "/login?txn=" in r.headers["location"]
