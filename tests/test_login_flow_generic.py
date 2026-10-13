"""The generic login flow, driven entirely through fake ``LoginProvider``s (X03).

These tests never touch Google or the api_key form: they prove that
``KeystoneOAuthProvider``'s machinery — the consent screen, the
``state``-keyed pending attempt, the browser/CSRF binding, and the
error-page mapping — works for *any* conforming provider, not only the two
built-in ones.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from asgi_lifespan import LifespanManager

from conftest import BASE_URL, REDIRECT_URI, authorize_to_login, make_pkce, register_client
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import bootstrap_platform, build_server
from keystone_mcp.user_directory.factory import build_in_memory_user_directory_resolver
from support.fake_login import FakeFormProvider, FakeRedirectProvider
from support.google_oidc_fixtures import build_mock_google_oidc
from support.login import dev_token_login

pytestmark = pytest.mark.asyncio

_CSRF_FIELD_RE = re.compile(r'name="csrf" value="([^"]*)"')


def _settings(**overrides) -> Settings:
    base: dict[str, object] = {"base_url": BASE_URL, "refresh_interval_seconds": 0}
    base.update(overrides)
    return Settings(**base)


def _build_app(login_providers, *, user_resolver=None):
    settings = _settings()
    mcp, _registry, oauth, *_rest = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        login_providers=login_providers,
        user_resolver=user_resolver,
        register_builtin_catalog=False,
    )
    return mcp.http_app(path=settings.http_path), settings, oauth


async def _start_redirect(
    client: httpx.AsyncClient, txn: str, provider_name: str
) -> httpx.Response:
    """Walk the consent screen's provider button like a browser would."""
    page = await client.get("/login", params={"txn": txn})
    assert page.status_code == 200, page.text
    match = _CSRF_FIELD_RE.search(page.text)
    assert match is not None, page.text
    csrf = match.group(1)
    return await client.post(f"/login/{provider_name}", data={"txn": txn, "csrf": csrf})


async def test_redirect_provider_full_flow():
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))
    provider = FakeRedirectProvider("acme")
    app, settings, oauth = _build_app([provider], user_resolver=resolver)

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            page = await client.get("/login", params={"txn": txn})
            assert page.status_code == 200
            assert 'action="/login/acme"' in page.text

            redirect_response = await _start_redirect(client, txn, "acme")
            assert redirect_response.status_code == 302
            state = parse_qs(urlparse(redirect_response.headers["location"]).query)["state"][0]

            callback = await client.get(
                "/login/acme/callback",
                params={"state": state, "code": "x", "email": "alice@example.com"},
            )
            assert callback.status_code == 302, callback.text
            code = parse_qs(urlparse(callback.headers["location"]).query)["code"][0]

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
            assert token_response.status_code == 200, token_response.text
            access_token = token_response.json()["access_token"]
            verified = await oauth.verify_token(access_token)
            assert verified is not None
            assert verified.subject == "alice@example.com"
            assert verified.claims["auth_method"] == "acme"


async def test_callback_state_is_single_use():
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))
    provider = FakeRedirectProvider("acme")
    app, settings, _oauth = _build_app([provider], user_resolver=resolver)

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            redirect_response = await _start_redirect(client, txn, "acme")
            state = parse_qs(urlparse(redirect_response.headers["location"]).query)["state"][0]

            first = await client.get(
                "/login/acme/callback",
                params={"state": state, "code": "x", "email": "alice@example.com"},
            )
            assert first.status_code == 302, first.text

            second = await client.get(
                "/login/acme/callback",
                params={"state": state, "code": "x", "email": "alice@example.com"},
            )
            assert second.status_code == 400


async def test_callback_for_other_provider_is_refused():
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))
    acme = FakeRedirectProvider("acme")
    other = FakeRedirectProvider("other")
    app, settings, _oauth = _build_app([acme, other], user_resolver=resolver)

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            redirect_response = await _start_redirect(client, txn, "acme")
            state = parse_qs(urlparse(redirect_response.headers["location"]).query)["state"][0]

            response = await client.get(
                "/login/other/callback",
                params={"state": state, "code": "x", "email": "alice@example.com"},
            )
            assert response.status_code == 400
            # The acme attempt itself was consumed by the mismatched lookup
            # (state is single-use), so completing it under "acme" now also
            # fails rather than silently succeeding under the wrong name.
            assert len(other.complete_calls) == 0
            retry = await client.get(
                "/login/acme/callback",
                params={"state": state, "code": "x", "email": "alice@example.com"},
            )
            assert retry.status_code == 400
            assert len(acme.complete_calls) == 0


async def test_unexpected_provider_error_is_identity_page(caplog):
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))
    provider = FakeRedirectProvider("acme", raises=RuntimeError("boom - should never be shown"))
    app, settings, _oauth = _build_app([provider], user_resolver=resolver)

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            redirect_response = await _start_redirect(client, txn, "acme")
            state = parse_qs(urlparse(redirect_response.headers["location"]).query)["state"][0]

            with caplog.at_level(logging.ERROR, logger="keystone_mcp.auth.keystone_oauth_provider"):
                response = await client.get(
                    "/login/acme/callback",
                    params={"state": state, "code": "x", "email": "alice@example.com"},
                )

    assert response.status_code == 503
    assert "boom - should never be shown" not in response.text
    assert any(
        record.exc_info is not None and "acme" in record.getMessage() for record in caplog.records
    )


async def test_unknown_provider_route_is_404():
    app, _settings_obj, _oauth = _build_app([FakeRedirectProvider("acme")])

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            response = await client.post("/login/nope", data={"txn": "x", "csrf": "y"})
            assert response.status_code == 404


async def test_warm_up_failure_does_not_stop_start(caplog):
    class _FailingWarmUp(FakeRedirectProvider):
        async def warm_up(self) -> None:
            raise OSError("provider unreachable at startup")

    provider = _FailingWarmUp("acme")
    settings = _settings()
    mcp, registry, _oauth, upstreams, policy_manager, _observability, _reconciler = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        login_providers=[provider],
        register_builtin_catalog=False,
    )
    del mcp

    with caplog.at_level(logging.WARNING, logger="keystone_mcp.server"):
        await bootstrap_platform(
            upstreams, registry, settings, policy_manager, login_providers=[provider]
        )

    assert any(
        "acme" in record.getMessage() and "not ready" in record.getMessage()
        for record in caplog.records
    )


async def test_consent_page_html_unchanged_for_builtin_providers():
    """With Google and api_key both enabled, the consent page still looks like 0.4.0's.

    This is the one place the generic rendering path (``_login_form_html``)
    is checked against the two *built-in* providers together, pinning the
    exact fragments a fork or a client integration may have come to rely on.
    """
    settings = _settings(
        enabled_login_methods=frozenset({"google", "api_key"}),
        google_client_id="test-google-client",
        google_client_secret="test-google-secret",
        users_service_url="http://users.example",
        users_service_token="users-token",
    )
    mock_google = build_mock_google_oidc(settings.google_redirect_uri)
    _login = dev_token_login({"irrelevant-token"})
    mcp, *_rest = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        login_providers=[mock_google.provider, _login],
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            page = await client.get("/login", params={"txn": txn})

    assert page.status_code == 200
    assert 'action="/login/google"' in page.text
    assert 'name="csrf"' in page.text
    assert "Sign in with Google" in page.text
    assert 'action="/login"' in page.text
    assert 'name="api_token"' in page.text
    assert 'name="email"' in page.text


# ── a provider must not be able to claim another provider's identity ───────
#
# auth_method (the issued token's claim, and the value RBAC's interactive-
# human gate checks against "google") must come from *which route the
# sign-in came back on*, never from the provider's own self-reported
# LoginIdentity.provider -- otherwise a third-party redirect or form
# provider, configured under any name, could report provider="google" and
# pick up the interactive-human trust that name carries.


async def test_redirect_provider_claiming_another_name_is_refused(caplog):
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))
    provider = FakeRedirectProvider("acme", reported_provider="google")
    app, settings, _oauth = _build_app([provider], user_resolver=resolver)

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            redirect_response = await _start_redirect(client, txn, "acme")
            state = parse_qs(urlparse(redirect_response.headers["location"]).query)["state"][0]

            with caplog.at_level(
                logging.WARNING, logger="keystone_mcp.auth.keystone_oauth_provider"
            ):
                response = await client.get(
                    "/login/acme/callback",
                    params={"state": state, "code": "x", "email": "alice@example.com"},
                )

    assert response.status_code == 400
    assert any(
        "acme" in record.getMessage() and "google" in record.getMessage()
        for record in caplog.records
    )


async def test_form_provider_claiming_another_name_is_refused():
    provider = FakeFormProvider("acme_form", reported_provider="google")
    app, settings, _oauth = _build_app([provider])

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            response = await client.post("/login", data={"txn": txn, "email": "alice@example.com"})

    assert response.status_code == 401


# ── begin() is no longer trusted to never raise (finding #2) ───────────────


async def test_begin_rejected_provider_unavailable_is_503():
    provider = FakeRedirectProvider("acme", begin_rejects="provider_unavailable")
    app, settings, _oauth = _build_app([provider])

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            response = await _start_redirect(client, txn, "acme")

    assert response.status_code == 503
    assert "location" not in response.headers


async def test_begin_unexpected_error_is_503(caplog):
    provider = FakeRedirectProvider("acme", begin_raises=RuntimeError("boom - should not show"))
    app, settings, _oauth = _build_app([provider])

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            with caplog.at_level(logging.ERROR, logger="keystone_mcp.auth.keystone_oauth_provider"):
                response = await _start_redirect(client, txn, "acme")

    assert response.status_code == 503
    assert "boom - should not show" not in response.text
    assert any(
        record.exc_info is not None and "acme" in record.getMessage() for record in caplog.records
    )


# ── the callback is bound to the browser that started it, for any provider ─
# (mirrors test_google_oidc_login.py::test_google_callback_without_csrf_cookie_is_refused)


async def test_acme_callback_without_csrf_cookie_is_refused():
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))
    provider = FakeRedirectProvider("acme")
    app, settings, _oauth = _build_app([provider], user_resolver=resolver)

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            redirect_response = await _start_redirect(client, txn, "acme")
            state = parse_qs(urlparse(redirect_response.headers["location"]).query)["state"][0]

            # The victim's browser: never visited /login or POSTed
            # /login/acme, so it never received the km_login_csrf cookie.
            saved_cookies = httpx.Cookies(client.cookies)
            client.cookies.clear()
            try:
                response = await client.get(
                    "/login/acme/callback",
                    params={"state": state, "code": "x", "email": "alice@example.com"},
                )
            finally:
                client.cookies = httpx.Cookies(saved_cookies)

    assert response.status_code == 400
    assert "location" not in response.headers


# ── finding #3: a resolver is built whenever any provider other than the
#    built-in api_key form alone is configured, not only for Google ────────


async def test_custom_provider_alone_gets_an_auto_built_resolver(tmp_path):
    """``build_server(login_providers=[a custom provider])`` with no injected resolver.

    Before this fix, the resolver gate keyed off ``settings.google_login_enabled``
    specifically, so a deployment configuring only a custom provider got no
    resolver at all: the directory check silently never ran for a form
    provider, and a custom redirect provider's callback hard-503'd on every
    sign-in. Here nobody seeds the directory with "alice@example.com", so a
    correct resolver must refuse her.

    ``users_store`` is a migrated local SQLite store (as in
    ``test_login_directory_check.py``'s dev-token-directory regression test),
    so this exercises ``build_server``'s own automatic resolver construction
    rather than Redis plumbing unrelated to this finding.
    """
    from support.users_store import make_users_store

    store, _revision = await make_users_store(tmp_path)
    provider = FakeFormProvider("acme_form")
    settings = _settings()
    mcp, *_rest = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        login_providers=[provider],
        register_builtin_catalog=False,
        users_store=store,
    )
    app = mcp.http_app(path=settings.http_path)

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            response = await client.post("/login", data={"txn": txn, "email": "nobody@example.com"})

    assert response.status_code == 403
