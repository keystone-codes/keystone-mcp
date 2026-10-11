"""OAuth 2.1 flow tests emulating Claude Desktop's connector.

Covers the official discovery/registration/authorization/token sequence plus the
security invariants: 401 advertises resource metadata, PKCE S256, Resource
Indicators (RFC 8707), invalid api_token issues no code, and tokens minted for a
foreign audience are rejected.
"""

from __future__ import annotations

import contextlib
from urllib.parse import parse_qs, urlparse

import httpx
from asgi_lifespan import LifespanManager

from conftest import (
    BASE_URL,
    REDIRECT_URI,
    VALID_TOKEN,
    authorize_to_login,
    make_pkce,
    obtain_access_token,
    register_client,
)
from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.keystone_oauth_provider import TRANSLATIONS
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings, resources_equivalent
from keystone_mcp.server import build_server


@contextlib.asynccontextmanager
async def login_page_client(**setting_overrides):
    """A client against a server built with the given Settings overrides."""
    settings = Settings(base_url=BASE_URL, **setting_overrides)
    mcp, *_rest = build_server(
        identity_provider=StaticIdentityProvider({VALID_TOKEN}),
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client.keystone_settings = settings  # type: ignore[attr-defined]
            yield client


async def open_login_page(
    client: httpx.AsyncClient,
    *,
    accept_language: str | None = None,
    lang: str | None = None,
) -> httpx.Response:
    """Drive /authorize then GET /login, so the page renders for a live txn."""
    settings = client.keystone_settings  # type: ignore[attr-defined]
    client_id = await register_client(client)
    _verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    params = {"txn": txn}
    if lang is not None:
        params["lang"] = lang
    headers = {"Accept-Language": accept_language} if accept_language else None
    return await client.get("/login", params=params, headers=headers)


async def test_unauthenticated_mcp_call_advertises_resource_metadata(harness):
    r = await harness.client.post(
        harness.settings.transport_url,
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={"Accept": "application/json, text/event-stream"},
        follow_redirects=True,
    )
    assert r.status_code == 401
    www = r.headers.get("WWW-Authenticate", "")
    assert "Bearer" in www
    assert "resource_metadata=" in www
    assert "/.well-known/oauth-protected-resource" in www


async def test_protected_resource_metadata(harness):
    r = await harness.client.get(harness.settings.protected_resource_metadata_path)
    assert r.status_code == 200
    body = r.json()
    assert resources_equivalent(body["resource"], harness.settings.resource_url)
    assert body["authorization_servers"]


async def test_authorization_server_metadata(harness):
    r = await harness.client.get("/.well-known/oauth-authorization-server")
    assert r.status_code == 200
    body = r.json()
    for ep in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
        assert ep in body
    assert "S256" in body.get("code_challenge_methods_supported", [])


async def test_dynamic_client_registration(harness):
    client_id = await register_client(harness.client)
    assert client_id
    # The AS must remember the registered client.
    assert await harness.oauth.get_client(client_id) is not None


async def test_full_pkce_flow_issues_token(harness):
    res = await obtain_access_token(harness.client, harness.settings.resource_url)
    assert res["status"] == 200
    assert res["body"].get("access_token")
    assert res["body"].get("token_type") == "Bearer"
    assert res["body"].get("refresh_token")


async def test_invalid_api_token_issues_no_code(harness):
    """An invalid api_token at login must not mint an authorization code."""
    client_id = await register_client(harness.client)
    _verifier, challenge = make_pkce()
    txn = await authorize_to_login(
        harness.client, client_id, challenge, harness.settings.resource_url
    )
    r = await harness.client.post(
        "/login", data={"txn": txn, "api_token": "WRONG", "email": "user@example.com"}
    )
    assert r.status_code == 401
    assert "location" not in r.headers  # no redirect, hence no code


async def test_failed_login_preserves_txn_for_successful_retry(harness):
    """Wrong api_key must not consume txn; a later valid login succeeds."""
    client_id = await register_client(harness.client)
    verifier, challenge = make_pkce()
    txn = await authorize_to_login(
        harness.client, client_id, challenge, harness.settings.resource_url
    )
    failed = await harness.client.post(
        "/login",
        data={"txn": txn, "api_token": "WRONG", "email": "user@example.com"},
    )
    assert failed.status_code == 401
    assert await harness.oauth._get_pending_txn(txn) is not None

    success = await harness.client.post(
        "/login",
        data={"txn": txn, "api_token": VALID_TOKEN, "email": "retry@example.com"},
    )
    assert success.status_code == 302
    assert await harness.oauth._get_pending_txn(txn) is None

    code = parse_qs(urlparse(success.headers["location"]).query)["code"][0]
    token = await harness.client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": harness.settings.resource_url,
        },
    )
    assert token.status_code == 200
    verified = await harness.oauth.verify_token(token.json()["access_token"])
    assert verified is not None
    assert verified.subject == "retry@example.com"


async def test_token_carries_verified_email_claim(harness):
    res = await obtain_access_token(
        harness.client, harness.settings.resource_url, email="alice@example.com"
    )
    access_token = res["body"]["access_token"]
    verified = await harness.oauth.verify_token(access_token)
    assert verified is not None
    assert verified.subject == "alice@example.com"
    assert verified.claims["email"] == "alice@example.com"
    assert verified.resource == harness.settings.resource_url


async def test_token_for_foreign_audience_is_rejected(harness):
    """A token bound to a different resource must fail verify_token (RFC 8707)."""
    res = await obtain_access_token(harness.client, resource="http://evil.example.com/mcp")
    access_token = res["body"]["access_token"]
    # load (raw) succeeds but verify (audience-checked) rejects it.
    assert await harness.oauth.load_access_token(access_token) is not None
    assert await harness.oauth.verify_token(access_token) is None


async def test_authorization_code_is_single_use(harness):
    client_id = await register_client(harness.client)
    verifier, challenge = make_pkce()
    txn = await authorize_to_login(
        harness.client, client_id, challenge, harness.settings.resource_url
    )
    r = await harness.client.post(
        "/login", data={"txn": txn, "api_token": VALID_TOKEN, "email": "u@example.com"}
    )
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    token_req = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
        "code_verifier": verifier,
        "resource": harness.settings.resource_url,
    }
    first = await harness.client.post("/token", data=token_req)
    assert first.status_code == 200
    second = await harness.client.post("/token", data=token_req)
    assert second.status_code != 200


async def test_pkce_wrong_verifier_is_rejected(harness):
    client_id = await register_client(harness.client)
    _verifier, challenge = make_pkce()
    txn = await authorize_to_login(
        harness.client, client_id, challenge, harness.settings.resource_url
    )
    r = await harness.client.post(
        "/login", data={"txn": txn, "api_token": VALID_TOKEN, "email": "u@example.com"}
    )
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    other_verifier, _ = make_pkce()
    r = await harness.client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": other_verifier,
            "resource": harness.settings.resource_url,
        },
    )
    assert r.status_code != 200


async def test_login_page_uses_configured_default_language():
    """With no Accept-Language match, the page renders in login_default_lang."""
    for lang in ("en", "he", "ru"):
        async with login_page_client(login_default_lang=lang) as client:
            page = await open_login_page(client, accept_language="fr-FR")
            assert page.status_code == 200
            assert TRANSLATIONS[lang]["submit"] in page.text


async def test_accept_language_beats_the_configured_default():
    async with login_page_client(login_default_lang="en") as client:
        page = await open_login_page(client, accept_language="he")
        assert TRANSLATIONS["he"]["submit"] in page.text


async def test_explicit_lang_override_beats_the_configured_default():
    async with login_page_client(login_default_lang="en") as client:
        page = await open_login_page(client, lang="ru")
        assert TRANSLATIONS["ru"]["submit"] in page.text
