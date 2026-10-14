"""SEC-03 / SEC-04 / SEC-06: CSRF, state, and forged OIDC tokens."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from tests.security.conftest import BASE_URL, DEV_TOKEN, REDIRECT_URI
from tests.security.helpers import _csrf_from_page, pkce_pair

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.login.oidc import OidcLoginProvider
from keystone_mcp.server import build_server
from keystone_mcp.user_directory.factory import build_in_memory_user_directory_resolver
from support.login import dev_token_login

pytestmark = pytest.mark.security


@pytest_asyncio.fixture
async def oidc_attacker_stack():
    fake = FakeOidcIssuer(client_id="sec-oidc", client_secret="sec-secret")
    provider = OidcLoginProvider(
        fake.config(name="fakeoidc", title="Fake"),
        http_client_factory=fake.http_client,
    )
    settings = Settings(
        base_url=BASE_URL,
        enabled_login_methods=frozenset({"api_key"}),
        users_service_url="http://users.example",
        users_service_token="users-token",
    )
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed("alice@sec.test", roles=("member",))
    mcp, *_ = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
        login_providers=[provider, dev_token_login({DEV_TOKEN})],
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL, follow_redirects=False
        ) as client:
            yield {"client": client, "fake": fake}


async def _authorize_txn(client) -> str:
    reg = await client.post(
        "/register",
        json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
    )
    client_id = reg.json()["client_id"]
    _verifier, challenge = pkce_pair()
    auth = await client.get(
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
    return parse_qs(urlparse(auth.headers["location"]).query)["txn"][0]


async def test_login_redirect_post_without_csrf_cookie_rejected(attacker_stand) -> None:
    async with attacker_stand.raw_client() as client:
        txn = await _authorize_txn(client)
        r = await client.post("/login/fakeoidc", data={"txn": txn})
        assert r.status_code in (400, 403)


async def test_login_redirect_post_with_wrong_origin_rejected(attacker_stand) -> None:
    async with attacker_stand.raw_client() as client:
        txn = await _authorize_txn(client)
        page = await client.get(f"/login?txn={txn}")
        csrf = _csrf_from_page(page.text)
        assert csrf is not None
        r = await client.post(
            "/login/fakeoidc",
            data={"txn": txn, "csrf": csrf},
            headers={"Origin": "https://attacker.example"},
        )
        assert r.status_code in (400, 403, 302)
        if r.status_code == 302:
            assert "idp.test" not in r.headers.get("location", "")


async def test_oidc_callback_wrong_state_rejected(oidc_attacker_stack) -> None:
    client = oidc_attacker_stack["client"]
    fake = oidc_attacker_stack["fake"]
    txn = await _authorize_txn(client)
    page = await client.get(f"/login?txn={txn}")
    csrf = _csrf_from_page(page.text)
    assert csrf
    start = await client.post("/login/fakeoidc", data={"txn": txn, "csrf": csrf})
    assert start.status_code == 302
    params = await fake.authorize(start.headers["location"])
    params["state"] = "wrong-state"
    cb = await client.get("/login/fakeoidc/callback", params=params)
    assert cb.status_code == 400


async def test_oidc_tampered_id_token_rejected(oidc_attacker_stack) -> None:
    client = oidc_attacker_stack["client"]
    fake = oidc_attacker_stack["fake"]
    txn = await _authorize_txn(client)
    page = await client.get(f"/login?txn={txn}")
    csrf = _csrf_from_page(page.text)
    assert csrf
    start = await client.post("/login/fakeoidc", data={"txn": txn, "csrf": csrf})
    fake.tamper.alg_hs256 = True
    params = await fake.authorize(start.headers["location"])
    cb = await client.get("/login/fakeoidc/callback", params=params)
    assert cb.status_code == 400
