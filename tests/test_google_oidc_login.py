"""Google OIDC login flow tests."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

import pytest

from conftest import (
    BASE_URL,
    REDIRECT_URI,
    VALID_TOKEN,
    authorize_to_login,
    make_pkce,
    register_client,
)
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.login.factory import build_login_providers
from keystone_mcp.login.oidc import OidcLoginProvider
from keystone_mcp.server import build_server
from keystone_mcp.user_directory.factory import build_in_memory_user_directory_resolver
from support.google_oidc_fixtures import build_mock_google_oidc
from support.login import dev_token_login


def _google_settings(**overrides) -> Settings:
    base = {
        "base_url": BASE_URL,
        "primary_login_method": "google",
        "enabled_login_methods": frozenset({"google", "api_key"}),
        "google_client_id": "test-google-client",
        "google_client_secret": "test-google-secret",
        "users_service_url": "http://users.example",
        "users_service_token": "users-token",
    }
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
async def google_harness():
    import httpx
    from asgi_lifespan import LifespanManager

    settings = _google_settings()
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))
    backend.seed("blocked@example.com", roles=("operator",), is_blocked=True)

    mock_google = build_mock_google_oidc(settings.google_redirect_uri)
    _login = dev_token_login({VALID_TOKEN})
    store = InMemoryOAuthStore()
    mcp, registry, oauth, _upstreams, _policy, _observability, _reconciler = build_server(
        settings=settings,
        oauth_store=store,
        user_resolver=resolver,
        login_providers=[mock_google.provider, _login],
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            yield {
                "client": client,
                "oauth": oauth,
                "settings": settings,
                "backend": backend,
                "mock_google": mock_google,
                "resolver": resolver,
            }


_CSRF_FIELD_RE = re.compile(r'name="csrf" value="([^"]*)"')


async def _start_google_redirect(client, txn: str) -> str:
    """Walk the consent screen's Google button like a browser would.

    The screen must be shown first: ``GET /login?txn`` returns the consent
    page carrying a hidden ``csrf`` field and setting the matching
    ``km_login_csrf`` cookie (held by ``httpx.AsyncClient`` across requests).
    Only the form's own ``POST /login/google`` actually redirects to Google.
    """
    page = await client.get(f"/login?txn={txn}")
    assert page.status_code == 200, page.text
    match = _CSRF_FIELD_RE.search(page.text)
    assert match is not None, page.text
    csrf = match.group(1)
    response = await client.post("/login/google", data={"txn": txn, "csrf": csrf})
    assert response.status_code == 302, response.text
    return response.headers["location"]


async def _complete_google_callback(
    client,
    oauth,
    mock_google,
    txn: str,
    *,
    email: str = "alice@example.com",
    google_code: str = "google-auth-code",
    state: str | None = None,
    nonce: str | None = None,
    hd: str | None = None,
) -> tuple[str, str]:
    redirect_url = await _start_google_redirect(client, txn)
    parsed = urlparse(redirect_url)
    google_state = parse_qs(parsed.query)["state"][0]
    if nonce is None:
        nonce = parse_qs(parsed.query).get("nonce", [None])[0]
    if nonce is None:
        nonce = mock_google.client.new_nonce()
    mock_google.set_pending_identity(email=email, nonce=nonce or "nonce", hd=hd)
    if google_code == "google-auth-code":
        callback_params = await mock_google.fake.authorize(redirect_url)
    else:
        callback_params = {"state": state or google_state, "code": google_code}
    response = await client.get("/login/google/callback", params=callback_params)
    return response, google_state


async def test_google_login_redirect_includes_state_nonce_pkce(google_harness):
    client = google_harness["client"]
    client_id = await register_client(client)
    verifier, challenge = make_pkce()
    txn = await authorize_to_login(
        client, client_id, challenge, google_harness["settings"].resource_url
    )
    redirect_url = await _start_google_redirect(client, txn)
    parsed = urlparse(redirect_url)
    assert parsed.netloc == "accounts.google.com"
    query = parse_qs(parsed.query)
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"]
    assert query["code_challenge"]
    assert query["scope"] == ["openid email"]
    assert query["client_id"] == ["test-google-client"]
    assert query["redirect_uri"] == [google_harness["settings"].google_redirect_uri]

 # The pending-attempt namespace is now "login_attempt" (shared by any
    # redirect provider), not the Google-only "google" it used to be.
    raw = await google_harness["oauth"]._pending_store.get("login_attempt", query["state"][0])
    assert raw is not None


async def test_google_login_with_googleapis_discovery_endpoints(google_harness):
    client = google_harness["client"]
    oauth = google_harness["oauth"]
    mock_google = google_harness["mock_google"]
    settings = google_harness["settings"]
    mock_google.fake.tamper.discovery_token_endpoint = "https://oauth2.googleapis.com/token"
    mock_google.fake.tamper.discovery_jwks_uri = "https://www.googleapis.com/jwks"

    client_id = await register_client(client)
    verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

    response, _state = await _complete_google_callback(
        client, oauth, mock_google, txn, email="alice@example.com"
    )
    assert response.status_code == 302
    location = response.headers["location"]
    code = parse_qs(urlparse(location).query)["code"][0]

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


async def test_google_callback_success_issues_authorization_code(google_harness):
    client = google_harness["client"]
    oauth = google_harness["oauth"]
    mock_google = google_harness["mock_google"]
    settings = google_harness["settings"]

    client_id = await register_client(client)
    verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

    response, _state = await _complete_google_callback(
        client, oauth, mock_google, txn, email="alice@example.com"
    )
    assert response.status_code == 302
    location = response.headers["location"]
    code = parse_qs(urlparse(location).query)["code"][0]

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
    assert verified is not None
    assert verified.subject == "alice@example.com"


async def test_google_callback_invalid_id_token_signature(google_harness):
    client = google_harness["client"]
    mock_google = google_harness["mock_google"]
    settings = google_harness["settings"]

    client_id = await register_client(client)
    _, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

    redirect_url = await _start_google_redirect(client, txn)
    nonce = parse_qs(urlparse(redirect_url).query)["nonce"][0]
    mock_google.set_pending_identity(email="alice@example.com", nonce=nonce)
    mock_google.fake.tamper.bad_signature = True
    callback_params = await mock_google.fake.authorize(redirect_url)
    response = await client.get("/login/google/callback", params=callback_params)
    assert response.status_code == 400


async def test_google_callback_rejects_bad_iss_aud_exp_nonce(google_harness):
    client = google_harness["client"]
    mock_google = google_harness["mock_google"]
    settings = google_harness["settings"]

    client_id = await register_client(client)
    _, challenge = make_pkce()

    cases = [
        {"iss": "https://evil.example.com"},
        {"wrong_aud": True},
        {"expired": True},
        {"wrong_nonce": "other-nonce"},
        {"email_verified": False},
    ]
    for kwargs in cases:
        txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
        redirect_url = await _start_google_redirect(client, txn)
        nonce = parse_qs(urlparse(redirect_url).query)["nonce"][0]
        mock_google.set_pending_identity(email="alice@example.com", nonce=nonce, **kwargs)
        callback_params = await mock_google.fake.authorize(redirect_url)
        response = await client.get("/login/google/callback", params=callback_params)
        expected = 403 if kwargs.get("email_verified") is False else 400
        assert response.status_code == expected


async def test_google_state_mismatch_and_single_use(google_harness):
    client = google_harness["client"]
    mock_google = google_harness["mock_google"]
    settings = google_harness["settings"]

    client_id = await register_client(client)
    _, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    redirect_url = await _start_google_redirect(client, txn)

    mismatch = await client.get(
        "/login/google/callback",
        params={"state": "wrong-state", "code": "code"},
    )
    assert mismatch.status_code == 400

    nonce = parse_qs(urlparse(redirect_url).query)["nonce"][0]
    mock_google.set_pending_identity(email="alice@example.com", nonce=nonce)
    first_params = await mock_google.fake.authorize(redirect_url)
    first = await client.get("/login/google/callback", params=first_params)
    assert first.status_code == 302

    mock_google.set_pending_identity(email="alice@example.com", nonce=nonce)
    reuse = await client.get("/login/google/callback", params=first_params)
    assert reuse.status_code == 400


async def test_google_domain_restriction(google_harness):
    settings = _google_settings(google_allowed_domain="example.com")
    import httpx
    from asgi_lifespan import LifespanManager

    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))
    mock_google = build_mock_google_oidc(settings.google_redirect_uri, allowed_domain="example.com")
    mcp, _, oauth, _, _, _, _ = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
        login_providers=[mock_google.provider, dev_token_login({VALID_TOKEN})],
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            redirect = await _start_google_redirect(client, txn)
            assert "hd=example.com" in redirect

            response, _ = await _complete_google_callback(
                client,
                oauth,
                mock_google,
                txn,
                email="alice@other.com",
                hd="example.com",
            )
            assert response.status_code == 403

            txn_no_hd = await authorize_to_login(
                client, client_id, challenge, settings.resource_url
            )
            no_hd, _ = await _complete_google_callback(
                client,
                oauth,
                mock_google,
                txn_no_hd,
                email="alice@example.com",
            )
            assert no_hd.status_code == 403

            txn2 = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            ok, _ = await _complete_google_callback(
                client,
                oauth,
                mock_google,
                txn2,
                email="alice@example.com",
                hd="example.com",
            )
            assert ok.status_code == 302


def test_legacy_google_domain_from_settings(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", "secret")
    settings = Settings(
        google_client_id="g-cid",
        google_client_secret="secret",
        google_allowed_domain="corp.example",
        login_providers_path="",
        enabled_login_methods=frozenset({"google"}),
    )
    providers = build_login_providers(settings)
    google = next(p for p in providers if p.name == "google")
    assert isinstance(google, OidcLoginProvider)
    assert google.config.hosted_domain == "corp.example"
    assert google.config.allowed_domains == ("corp.example",)


async def test_legacy_google_domain_end_to_end(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", "test-google-secret")
    import httpx
    from asgi_lifespan import LifespanManager

    import keystone_mcp.server as server_module

    settings = _google_settings(
        google_allowed_domain="corp.example",
        login_providers_path="",
        enabled_login_methods=frozenset({"google", "api_key"}),
    )
    mock_google = build_mock_google_oidc(
        settings.google_redirect_uri,
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        allowed_domain="corp.example",
    )
    real_build = server_module.build_login_providers

    def _build_with_mock_google(*args, **kwargs):
        providers = real_build(*args, **kwargs)
        return [mock_google.provider if p.name == "google" else p for p in providers]

    monkeypatch.setattr(server_module, "build_login_providers", _build_with_mock_google)
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed("alice@corp.example", roles=("operator",))
    mcp, _, oauth, _, _, _, _ = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            redirect = await _start_google_redirect(client, txn)
            assert "hd=corp.example" in redirect

            response, _ = await _complete_google_callback(
                client,
                oauth,
                mock_google,
                txn,
                email="alice@corp.example",
                hd="other.example",
            )
            assert response.status_code == 403


async def test_legacy_google_without_domain_has_no_hd(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", "test-google-secret")
    import httpx
    from asgi_lifespan import LifespanManager

    import keystone_mcp.server as server_module

    settings = _google_settings(
        google_allowed_domain="",
        login_providers_path="",
        enabled_login_methods=frozenset({"google", "api_key"}),
    )
    mock_google = build_mock_google_oidc(
        settings.google_redirect_uri,
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
    )
    real_build = server_module.build_login_providers

    def _build_with_mock_google(*args, **kwargs):
        providers = real_build(*args, **kwargs)
        return [mock_google.provider if p.name == "google" else p for p in providers]

    monkeypatch.setattr(server_module, "build_login_providers", _build_with_mock_google)
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))
    mcp, _, oauth, _, _, _, _ = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            redirect = await _start_google_redirect(client, txn)
            assert "hd=" not in redirect


async def test_google_unknown_and_blocked_users_denied(google_harness):
    client = google_harness["client"]
    oauth = google_harness["oauth"]
    mock_google = google_harness["mock_google"]
    settings = google_harness["settings"]

    client_id = await register_client(client)
    _, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

    unknown = await _complete_google_callback(
        client, oauth, mock_google, txn, email="unknown@example.com"
    )
    assert unknown[0].status_code == 403

    txn2 = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    blocked = await _complete_google_callback(
        client, oauth, mock_google, txn2, email="blocked@example.com"
    )
    assert blocked[0].status_code == 403


async def test_google_disabled_hides_route(google_harness):
    import httpx
    from asgi_lifespan import LifespanManager

    settings = Settings(base_url=BASE_URL)
    mcp, _, oauth, _, _, _, _ = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            response = await client.get("/login/google?txn=fake")
            assert response.status_code == 404

            post_response = await client.post(
                "/login/google", data={"txn": "fake", "csrf": "anything"}
            )
            assert post_response.status_code == 404


async def test_api_key_flow_still_works_with_google_enabled(google_harness):
    """api_key login still works alongside Google — for a directory-known email.

    ``retry@example.com`` used to work here because /login only checked the
 token; since the directory check also the directory, this harness's seeded
    ``alice@example.com`` is used instead.
    """
    client = google_harness["client"]
    settings = google_harness["settings"]
    client_id = await register_client(client)
    verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    response = await client.post(
        "/login",
        data={"txn": txn, "api_token": VALID_TOKEN, "email": "alice@example.com"},
    )
    assert response.status_code == 302
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    token = await client.post(
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
    assert token.status_code == 200


async def test_login_page_shows_consent_when_google_primary(google_harness):
    """Even with Google as the primary method, /login shows the consent screen.

 It must not redirect straight to Google: the screen itself carries
    the Google button as a form.
    """
    client = google_harness["client"]
    settings = google_harness["settings"]
    client_id = await register_client(client)
    _, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    page = await client.get(f"/login?txn={txn}", follow_redirects=False)
    assert page.status_code == 200
    assert 'action="/login/google"' in page.text
    assert 'method="post"' in page.text


# ── 1: the Google state is bound to the browser that started it ───
#
# Attack this closes: attacker registers a client with their own redirect_uri,
# runs /authorize + the consent screen + POST /login/google themselves (so
# they hold a valid km_login_csrf cookie and a state tied to it), then sends
# the victim the resulting Google authorization URL. If the victim is already
# signed in to Google, Google redirects the victim's browser straight to
# /login/google/callback — a browser that never visited /login and so never
# carries the attacker's cookie. Before this fix the callback only checked
# `state` (an opaque, single-use nonce, but not browser-bound), so it minted a
# code for the attacker's redirect_uri using the victim's identity.


async def test_google_callback_without_csrf_cookie_is_refused(google_harness):
    client = google_harness["client"]
    mock_google = google_harness["mock_google"]
    settings = google_harness["settings"]

    client_id = await register_client(client)
    _, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    redirect_url = await _start_google_redirect(client, txn)
    parsed = urlparse(redirect_url)
    google_state = parse_qs(parsed.query)["state"][0]
    nonce = parse_qs(parsed.query)["nonce"][0]
    mock_google.set_pending_identity(email="alice@example.com", nonce=nonce)

    # The victim's browser: never visited /login or POSTed /login/google, so
    # it never received the km_login_csrf cookie at all.
    #
    # Saved/restored via `httpx.Cookies` (not a plain `dict`): a plain dict
    # round trip drops the cookie's domain/path, so restoring it re-adds a
    # second, differently-scoped jar entry instead of replacing the one a
    # later `Set-Cookie` updates — harmless under the old "reuse the incoming
    # cookie" behaviour (both entries held the same value), but a real
    # mismatch now that every consent-screen render mints a fresh cookie
 # (second review): the jar would hold both the stale restored
    # value and the fresh one, and which one the request actually sends
    # becomes ambiguous.
    import httpx

    saved_cookies = httpx.Cookies(client.cookies)
    client.cookies.clear()
    try:
        response = await client.get(
            "/login/google/callback",
            params={"state": google_state, "code": "google-auth-code"},
        )
    finally:
        client.cookies = httpx.Cookies(saved_cookies)

    assert response.status_code == 400, response.text
    assert "location" not in response.headers

    # The underlying /authorize transaction is not spent: a fresh, correct
    # Google round trip against the same txn still succeeds.
    redirect_url_2 = await _start_google_redirect(client, txn)
    nonce_2 = parse_qs(urlparse(redirect_url_2).query)["nonce"][0]
    mock_google.set_pending_identity(email="alice@example.com", nonce=nonce_2)
    retry_params = await mock_google.fake.authorize(redirect_url_2)
    retry = await client.get("/login/google/callback", params=retry_params)
    assert retry.status_code == 302, retry.text
    assert "code=" in retry.headers["location"]


async def test_google_callback_with_mismatched_csrf_cookie_is_refused(google_harness):
    client = google_harness["client"]
    mock_google = google_harness["mock_google"]
    settings = google_harness["settings"]

    client_id = await register_client(client)
    _, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    redirect_url = await _start_google_redirect(client, txn)
    parsed = urlparse(redirect_url)
    google_state = parse_qs(parsed.query)["state"][0]
    nonce = parse_qs(parsed.query)["nonce"][0]
    mock_google.set_pending_identity(email="alice@example.com", nonce=nonce)

    # A browser holding some other, unrelated km_login_csrf cookie value
    # (e.g. from its own, separate /login visit) — not empty, just wrong.
    client.cookies.set("km_login_csrf", "a" * 32, path="/login")
    response = await client.get(
        "/login/google/callback",
        params={"state": google_state, "code": "google-auth-code"},
    )
    assert response.status_code == 400, response.text
    assert "location" not in response.headers


async def test_google_callback_with_matching_csrf_cookie_succeeds(google_harness):
    """Regression guard: the normal flow (same browser throughout) is unaffected."""
    client = google_harness["client"]
    oauth = google_harness["oauth"]
    mock_google = google_harness["mock_google"]
    settings = google_harness["settings"]

    client_id = await register_client(client)
    _, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    response, _state = await _complete_google_callback(
        client, oauth, mock_google, txn, email="alice@example.com"
    )
    assert response.status_code == 302, response.text
    assert "code=" in response.headers["location"]


# ── 7: identity.email is normalized in the Google branch too ──────
#
# google_oidc.verify_id_token already lowercases the email claim (the directory-check own
# note on the Google branch), so this cannot be reproduced end-to-end through
# the real verification path. This test instead patches verify_id_token to
# return a non-normalized identity — simulating that upstream guarantee ever
# being relaxed or bypassed — and checks handle_google_callback's own
# normalize_email(...) call (matching handle_login) still produces a
# lower-case, trimmed subject and `email` claim.
async def test_google_identity_email_is_normalized_defensively(google_harness):
    client = google_harness["client"]
    oauth = google_harness["oauth"]
    mock_google = google_harness["mock_google"]
    settings = google_harness["settings"]

    client_id = await register_client(client)
    verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    redirect_url = await _start_google_redirect(client, txn)
    nonce = parse_qs(urlparse(redirect_url).query)["nonce"][0]
    mock_google.fake.user.email = " Alice@Example.COM "
    mock_google.set_pending_identity(email=" Alice@Example.COM ", nonce=nonce)
    callback_params = await mock_google.fake.authorize(redirect_url)
    response = await client.get("/login/google/callback", params=callback_params)
    assert response.status_code == 302, response.text
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
    assert verified is not None
    assert verified.subject == "alice@example.com"
    assert verified.claims["email"] == "alice@example.com"


async def test_login_page_shows_form_when_api_key_primary():
    import httpx
    from asgi_lifespan import LifespanManager

    from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
    from keystone_mcp.server import build_server
    from keystone_mcp.user_directory.factory import build_in_memory_user_directory_resolver

    settings = _google_settings(primary_login_method="api_key")
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))
    mock_google = build_mock_google_oidc(settings.google_redirect_uri)
    oauth_store = InMemoryOAuthStore()
    mcp, *_rest = build_server(
        settings=settings,
        login_providers=[mock_google.provider, dev_token_login({VALID_TOKEN})],
        oauth_store=oauth_store,
        user_resolver=resolver,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            page = await client.get(f"/login?txn={txn}")
            assert "api_token" in page.text
            assert "Sign in with Google" in page.text or "Google" in page.text
