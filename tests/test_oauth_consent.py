"""Consent screen tests.

Before any authorization code is issued, ``GET /login`` must show which
application is asking for access and where the result will be sent, and the
user must click through it explicitly. For the Google button specifically,
the click has to happen on this screen and nowhere else: a bare
``GET /login/google`` link (which used to jump straight to Google) now only
bounces back to the consent screen, and the actual redirect to Google is a
CSRF-checked ``POST`` the screen's own form submits.
"""

from __future__ import annotations

import re

import httpx
import pytest
from asgi_lifespan import LifespanManager

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from keystone_mcp.user_directory.factory import build_in_memory_user_directory_resolver
from support.google_oidc_fixtures import build_mock_google_oidc
from support.login import dev_token_login
from support.oauth_harness import (
    BASE_URL,
    VALID_TOKEN,
    authorize_to_login,
    make_pkce,
    register_client,
)

pytestmark = pytest.mark.asyncio

_CSRF_FIELD_RE = re.compile(r'name="csrf" value="([^"]*)"')


def _api_key_settings(**overrides) -> Settings:
    base: dict[str, object] = {"base_url": BASE_URL, "refresh_interval_seconds": 0}
    base.update(overrides)
    return Settings(**base)


def _google_settings(**overrides) -> Settings:
    base: dict[str, object] = {
        "base_url": BASE_URL,
        "refresh_interval_seconds": 0,
        "enabled_login_methods": frozenset({"google", "api_key"}),
        "google_client_id": "test-google-client",
        "google_client_secret": "test-google-secret",
        "users_service_url": "http://users.example",
        "users_service_token": "users-token",
    }
    base.update(overrides)
    return Settings(**base)


class _Harness:
    def __init__(self, client: httpx.AsyncClient, settings: Settings) -> None:
        self.client = client
        self.settings = settings


@pytest.fixture
async def api_key_client():
    settings = _api_key_settings()
    _login = dev_token_login({VALID_TOKEN})
    mcp, *_rest = build_server(
        login_providers=[_login], settings=settings, oauth_store=InMemoryOAuthStore()
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            yield _Harness(client, settings)


def _google_harness(settings: Settings):
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))
    mock_google = build_mock_google_oidc(settings.google_redirect_uri)
    _login = dev_token_login({VALID_TOKEN})

    mcp, *_rest = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
        login_providers=[mock_google.provider, _login],
    )
    return mcp.http_app(path=settings.http_path)


async def test_login_page_shows_client_name_and_redirect_host(api_key_client):
    h = api_key_client
    client_id = await register_client(h.client, client_name="Test App")
    _, challenge = make_pkce()
    txn = await authorize_to_login(h.client, client_id, challenge, h.settings.resource_url)

    page = await h.client.get("/login", params={"txn": txn})

    assert page.status_code == 200
    assert "Test App" in page.text
    assert "localhost:9999" in page.text


async def test_unnamed_client_shows_placeholder(api_key_client):
    h = api_key_client
    client_id = await register_client(h.client)
    _, challenge = make_pkce()
    txn = await authorize_to_login(h.client, client_id, challenge, h.settings.resource_url)

    page = await h.client.get("/login", params={"txn": txn})

    assert page.status_code == 200
    assert "Unnamed application" in page.text


async def test_client_name_is_escaped(api_key_client):
    h = api_key_client
    client_id = await register_client(h.client, client_name="<script>x</script>")
    _, challenge = make_pkce()
    txn = await authorize_to_login(h.client, client_id, challenge, h.settings.resource_url)

    page = await h.client.get("/login", params={"txn": txn})

    assert page.status_code == 200
    assert "<script>x</script>" not in page.text
    assert "&lt;script&gt;x&lt;/script&gt;" in page.text


async def test_google_primary_shows_consent_instead_of_redirect():
    settings = _google_settings(primary_login_method="google")
    app = _google_harness(settings)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client, client_name="Test App")
            _, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            page = await client.get("/login", params={"txn": txn})

            assert page.status_code == 200
            assert 'action="/login/google"' in page.text
            assert 'method="post"' in page.text
            set_cookie = page.headers.get("set-cookie", "")
            assert "km_login_csrf=" in set_cookie
            assert "HttpOnly" in set_cookie
            assert "samesite=lax" in set_cookie.lower()
            # Plain http (this suite's BASE_URL): the unprefixed name, scoped
 # to /login as before (second review).
            assert not set_cookie.lower().startswith("__host-")
            assert "path=/login" in set_cookie.lower()


async def test_post_login_google_requires_matching_csrf():
    settings = _google_settings()
    app = _google_harness(settings)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            # No cookie has been set on this client yet.
            no_cookie = await client.post("/login/google", data={"txn": txn, "csrf": "anything"})
            assert no_cookie.status_code == 400

            page = await client.get("/login", params={"txn": txn})
            match = _CSRF_FIELD_RE.search(page.text)
            assert match is not None
            csrf = match.group(1)
            assert csrf

            # Cookie now present, but the submitted field does not match it.
            mismatch = await client.post("/login/google", data={"txn": txn, "csrf": "wrong-value"})
            assert mismatch.status_code == 400

            # Matching cookie and field: the real redirect to Google.
            ok = await client.post("/login/google", data={"txn": txn, "csrf": csrf})
            assert ok.status_code == 302
            assert "state=" in ok.headers["location"]


async def test_get_login_google_redirects_to_consent():
    settings = _google_settings()
    app = _google_harness(settings)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            response = await client.get("/login/google", params={"txn": "X"})
            assert response.status_code == 303
            assert response.headers["location"] == "/login?txn=X"


async def test_uppercase_https_base_url_sets_secure_host_cookies():
    settings = _google_settings(base_url="HTTPS://mcp.example.com")
    app = _google_harness(settings)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            page = await client.get("/login", params={"txn": txn, "lang": "en"})
            cookies = page.headers.get_list("set-cookie")
            csrf = next(c for c in cookies if c.startswith("__Host-km_login_csrf="))
            lang = next(c for c in cookies if c.startswith("__Host-km_lang="))
            for header in (csrf, lang):
                assert "Secure" in header
                assert "path=/" in header.lower() or header.lower().endswith("path=/")


async def test_cookie_secure_flag_follows_base_url():
    https_settings = _google_settings(base_url="https://mcp.example.com")
    https_app = _google_harness(https_settings)
    async with LifespanManager(https_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=https_app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _, challenge = make_pkce()
            txn = await authorize_to_login(
                client, client_id, challenge, https_settings.resource_url
            )
            page = await client.get("/login", params={"txn": txn})
            set_cookie = page.headers.get("set-cookie", "")
            assert "Secure" in set_cookie
 # second review: the `__Host-` prefix over https,
            # which requires `Path=/` — a browser refuses to store the
            # cookie at all otherwise, so the stronger name and the broader
            # path must travel together.
            assert set_cookie.startswith("__Host-km_login_csrf=")
            assert "path=/;" in set_cookie.lower() or set_cookie.lower().endswith("path=/")

    http_settings = _google_settings(base_url="http://localhost:8080")
    http_app = _google_harness(http_settings)
    async with LifespanManager(http_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=http_app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, http_settings.resource_url)
            page = await client.get("/login", params={"txn": txn})
            set_cookie = page.headers.get("set-cookie", "")
            assert "Secure" not in set_cookie
            assert set_cookie.startswith("km_login_csrf=")
            assert "path=/login" in set_cookie.lower()


async def test_csrf_cookie_is_never_echoed_back_from_the_request():
    """second review: a pre-existing cookie value is never reused.

    Before this fix, any incoming `km_login_csrf` cookie at least 32
    characters long was reused verbatim — including one the browser carried
    in because an attacker planted it (e.g. over a plain-http same-host
    endpoint, or a sibling subdomain able to set a cookie without the
    `__Host-` prefix). Reusing it would hand the attacker a CSRF token they
    already know, defeating the whole point of a server-issued secret.
    """
    settings = _google_settings()
    app = _google_harness(settings)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client, client_name="Test App")
            _, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            planted = "a" * 40  # attacker-known, well over the old reuse threshold
            page = await client.get(
                "/login",
                params={"txn": txn},
                headers={"Cookie": f"km_login_csrf={planted}"},
            )

            assert page.status_code == 200
            match = _CSRF_FIELD_RE.search(page.text)
            assert match is not None
            assert match.group(1) != planted
            set_cookie = page.headers.get("set-cookie", "")
            assert f"km_login_csrf={planted}" not in set_cookie


async def test_rerendering_consent_screen_rotates_the_csrf_cookie():
    """A second render mints a new pair; a first (now stale) tab's field 400s.

    This is the trade-off `_render_consent_page`'s docstring describes:
    always minting a fresh cookie (rather than reusing one long enough)
    means a page already open in another tab for the same `txn` stops
    matching the browser's cookie once a second render happens. The user can
    simply reload; this test documents (and pins) that behaviour rather than
    treating it as a regression.
    """
    settings = _google_settings()
    app = _google_harness(settings)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client, client_name="Test App")
            _, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

            first = await client.get("/login", params={"txn": txn})
            first_csrf = _CSRF_FIELD_RE.search(first.text).group(1)

            second = await client.get("/login", params={"txn": txn})
            second_csrf = _CSRF_FIELD_RE.search(second.text).group(1)

            assert first_csrf != second_csrf

            stale = await client.post("/login/google", data={"txn": txn, "csrf": first_csrf})
            assert stale.status_code == 400

            fresh = await client.post("/login/google", data={"txn": txn, "csrf": second_csrf})
            assert fresh.status_code == 302


async def test_api_key_flow_unchanged(api_key_client):
    """Posting the credential form directly (no GET /login, no cookie) still works."""
    h = api_key_client
    client_id = await register_client(h.client)
    _, challenge = make_pkce()
    txn = await authorize_to_login(h.client, client_id, challenge, h.settings.resource_url)

    response = await h.client.post(
        "/login", data={"txn": txn, "api_token": VALID_TOKEN, "email": "user@example.com"}
    )
    assert response.status_code == 302
    assert "code=" in response.headers["location"]
