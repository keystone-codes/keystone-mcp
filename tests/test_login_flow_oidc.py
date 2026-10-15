"""End-to-end OIDC login through ``build_server`` and ``FakeOidcIssuer``."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.login.oidc import OidcLoginProvider
from keystone_mcp.server import build_server
from keystone_mcp.user_directory.factory import build_in_memory_user_directory_resolver
from support.login import dev_token_login
from support.oauth_harness import (
    BASE_URL,
    REDIRECT_URI,
    VALID_TOKEN,
    authorize_to_login,
    make_pkce,
    register_client,
)

pytestmark = pytest.mark.asyncio

_CSRF_FIELD_RE = re.compile(r'name="csrf" value="([^"]*)"')


def _settings(**overrides) -> Settings:
    base = {
        "base_url": BASE_URL,
        "enabled_login_methods": frozenset({"api_key"}),
        "users_service_url": "http://users.example",
        "users_service_token": "users-token",
    }
    base.update(overrides)
    return Settings(**base)


@pytest_asyncio.fixture
async def okta_harness() -> AsyncIterator[dict]:
    fake = FakeOidcIssuer(client_id="okta-cid", client_secret="okta-secret")
    provider = OidcLoginProvider(
        fake.config(name="okta", title="Okta"),
        http_client_factory=fake.http_client,
    )
    settings = _settings()
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))
    _login = dev_token_login({VALID_TOKEN})
    mcp, _reg, oauth, *_ = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
        login_providers=[provider, _login],
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            yield {
                "client": client,
                "oauth": oauth,
                "fake": fake,
                "backend": backend,
                "settings": settings,
            }


async def _start_okta(client, txn: str) -> str:
    page = await client.get(f"/login?txn={txn}")
    assert "Sign in with Okta" in page.text
    assert 'action="/login/okta"' in page.text
    csrf = _CSRF_FIELD_RE.search(page.text).group(1)
    response = await client.post("/login/okta", data={"txn": txn, "csrf": csrf})
    assert response.status_code == 302
    return response.headers["location"]


async def test_full_oidc_login_flow_and_auth_method(okta_harness):
    client = okta_harness["client"]
    oauth = okta_harness["oauth"]
    fake = okta_harness["fake"]
    settings = okta_harness["settings"]
    client_id = await register_client(client)
    verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    redirect_url = await _start_okta(client, txn)
    fake.user.email = "alice@example.com"
    callback = await fake.authorize(redirect_url)
    response = await client.get("/login/okta/callback", params=callback)
    assert response.status_code == 302
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    token_response = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": settings.resource_url,
        },
    )
    assert token_response.status_code == 200
    verified = await oauth.verify_token(token_response.json()["access_token"])
    assert verified.claims["auth_method"] == "okta"


async def test_unknown_user_gets_user_denied(okta_harness):
    client = okta_harness["client"]
    fake = okta_harness["fake"]
    settings = okta_harness["settings"]
    client_id = await register_client(client)
    _, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    redirect_url = await _start_okta(client, txn)
    fake.user.email = "stranger@example.com"
    callback = await fake.authorize(redirect_url)
    response = await client.get("/login/okta/callback", params=callback)
    assert response.status_code == 403


async def test_unverified_email_refused(okta_harness):
    client = okta_harness["client"]
    fake = okta_harness["fake"]
    settings = okta_harness["settings"]
    client_id = await register_client(client)
    _, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    redirect_url = await _start_okta(client, txn)
    fake.user.email_verified = False
    callback = await fake.authorize(redirect_url)
    response = await client.get("/login/okta/callback", params=callback)
    assert response.status_code == 403


async def test_token_endpoint_unavailable_shows_identity_error(okta_harness):
    client = okta_harness["client"]
    fake = okta_harness["fake"]
    settings = okta_harness["settings"]
    client_id = await register_client(client)
    _, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    redirect_url = await _start_okta(client, txn)
    fake.tamper.token_endpoint_status = 503
    callback = await fake.authorize(redirect_url)
    response = await client.get("/login/okta/callback", params=callback)
    assert response.status_code == 400


async def test_discovery_unavailable_returns_503(okta_harness):
    client = okta_harness["client"]
    fake = okta_harness["fake"]
    settings = okta_harness["settings"]
    fake.tamper.discovery_status = 503
    client_id = await register_client(client)
    _, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    page = await client.get(f"/login?txn={txn}")
    csrf = _CSRF_FIELD_RE.search(page.text).group(1)
    response = await client.post("/login/okta", data={"txn": txn, "csrf": csrf})
    assert response.status_code == 503
