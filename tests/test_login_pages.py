"""HTML layout and language persistence for built-in sign-in pages."""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
from asgi_lifespan import LifespanManager

from keystone_mcp.auth.keystone_oauth_provider import TRANSLATIONS
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.login.pages import (
    _PAGE_STYLES,
    LANG_SWITCHER_ORDER,
    FieldView,
    ProviderView,
    _redirect_provider_html,
    render_consent_page,
    render_error_page,
)
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

SNAPSHOT_DIR = Path(__file__).resolve().parent / "data" / "login-pages"
_SNAPSHOT_TXN = "TXN"
_SNAPSHOT_CSRF = "CSRF"

_SAMPLE_PROVIDERS = (
    ProviderView("google", "redirect", "Google", ()),
    ProviderView(
        "api_key",
        "form",
        "API key",
        (
            FieldView("email", "email", "Email", None, "email", "email"),
            FieldView("api_token", "password", "API token", "token_help", "off", None),
        ),
    ),
)


def _normalize_html(html: str) -> str:
    return re.sub(r">\s+<", "><", html.strip())


def _write_or_compare_snapshot(name: str, html: str, snapshot_update: bool) -> None:
    path = SNAPSHOT_DIR / name
    normalized = _normalize_html(html)
    if snapshot_update:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(normalized + "\n", encoding="utf-8")
        return
    expected = _normalize_html(path.read_text(encoding="utf-8"))
    assert normalized == expected


def _consent_html(lang: str, *, error_key: str | None = None) -> str:
    t = TRANSLATIONS[lang]
    return render_consent_page(
        lang=lang,
        t=t,
        brand="Keystone-MCP",
        client_name="MCP CLI Proxy",
        redirect_uri="http://localhost:18198/oauth/callback",
        redirect_location="localhost:18198",
        providers=_SAMPLE_PROVIDERS,
        txn=_SNAPSHOT_TXN,
        csrf=_SNAPSHOT_CSRF,
        error_key=error_key,
        txn_query=f"txn={_SNAPSHOT_TXN}&",
    )


@pytest.mark.parametrize("lang", ["en", "he"])
def test_consent_page_matches_snapshot(lang: str, snapshot_update: bool) -> None:
    _write_or_compare_snapshot(f"consent-{lang}.html", _consent_html(lang), snapshot_update)


def test_consent_page_with_error_matches_snapshot(snapshot_update: bool) -> None:
    _write_or_compare_snapshot(
        "consent-en-error.html",
        _consent_html("en", error_key="error_invalid"),
        snapshot_update,
    )


def test_error_page_matches_snapshot(snapshot_update: bool) -> None:
    t = TRANSLATIONS["en"]
    html = render_error_page(
        lang="en",
        t=t,
        brand="Keystone-MCP",
        error_key="error_request",
        status_code=400,
    )
    _write_or_compare_snapshot("error-request-en.html", html, snapshot_update)


def test_rtl_pages_use_logical_properties() -> None:
    forbidden = (
        "margin-left",
        "margin-right",
        "padding-left",
        "padding-right",
        "border-left",
        "border-right",
    )
    for name in forbidden:
        assert name not in _PAGE_STYLES


def test_no_external_resources() -> None:
    html = _consent_html("en")
    assert "<script" not in html.lower()
    assert re.search(r'\b(?:src|href)=["\']https?://', html) is None


def test_lang_links_keep_txn() -> None:
    html = _consent_html("en")
    assert 'href="/login?txn=TXN&amp;lang=ru"' in html


def test_lang_switcher_lists_all_languages_in_fixed_order() -> None:
    html = _consent_html("en")
    positions = [html.find(code.upper()) for code in LANG_SWITCHER_ORDER]
    assert all(p >= 0 for p in positions)
    assert positions == sorted(positions)


def test_translations_cover_new_keys() -> None:
    required = {
        "or_api_key",
        "token_help",
        "error_hint_generic",
        "error_hint_request",
        "error_hint_redirect_host",
        "error_code_hint",
        "lang_switcher_label",
    }
    for lang, table in TRANSLATIONS.items():
        missing = required - table.keys()
        assert not missing, f"{lang} missing {missing}"


def _google_app(**settings_overrides):
    base_url = settings_overrides.pop("base_url", BASE_URL)
    settings = Settings(
        base_url=base_url,
        primary_login_method="google",
        enabled_login_methods=frozenset({"google", "api_key"}),
        google_client_id="test-google-client",
        google_client_secret="test-google-secret",
        refresh_interval_seconds=0,
        **settings_overrides,
    )
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))
    mock_google = build_mock_google_oidc(settings.google_redirect_uri)
    api_key = dev_token_login({VALID_TOKEN})
    mcp, _registry, oauth, *_rest = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
        register_builtin_catalog=False,
        login_providers=[mock_google.provider, api_key],
    )
    return mcp.http_app(path=settings.http_path), settings, oauth


@pytest.mark.asyncio
async def test_query_lang_sets_cookie_and_overrides_header() -> None:
    app, settings, _oauth = _google_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            page = await client.get(
                "/login",
                params={"txn": txn, "lang": "en"},
                headers={"Accept-Language": "ru"},
            )
            assert page.status_code == 200
            assert "Sign in to connect a client" in page.text
            set_cookie = page.headers.get_list("set-cookie")
            lang_cookie = next(c for c in set_cookie if c.startswith("km_lang="))
            assert "Path=/login" in lang_cookie
            assert "HttpOnly" in lang_cookie
            assert "SameSite=lax" in lang_cookie


@pytest.mark.asyncio
async def test_lang_cookie_persists_after_post_error() -> None:
    app, settings, _oauth = _google_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=BASE_URL,
            cookies={"km_lang": "en"},
        ) as client:
            client_id = await register_client(client)
            verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            bad = await client.post(
                "/login",
                data={"txn": txn, "email": "alice@example.com", "api_token": "wrong"},
                headers={"Accept-Language": "ru"},
            )
            assert bad.status_code == 401
            assert "Invalid api_token or email" in bad.text


@pytest.mark.asyncio
async def test_lang_cookie_used_on_callback_error_page() -> None:
    app, settings, _oauth = _google_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=BASE_URL,
            cookies={"km_lang": "he"},
        ) as client:
            response = await client.get("/login/google/callback", params={"state": "broken"})
            assert response.status_code == 400
            assert 'dir="rtl"' in response.text
            assert "בקשת הרשאה לא חוקית" in response.text


@pytest.mark.asyncio
async def test_unknown_lang_cookie_is_ignored() -> None:
    app, settings, _oauth = _google_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=BASE_URL,
            cookies={"km_lang": "xx"},
            headers={"Accept-Language": "en"},
        ) as client:
            client_id = await register_client(client)
            verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            page = await client.get("/login", params={"txn": txn})
            assert "Sign in to connect a client" in page.text
            assert not any(c.startswith("km_lang=") for c in page.headers.get_list("set-cookie"))


@pytest.mark.asyncio
async def test_no_lang_cookie_without_explicit_choice() -> None:
    app, settings, _oauth = _google_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url=BASE_URL,
            headers={"Accept-Language": "ru"},
        ) as client:
            client_id = await register_client(client)
            verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            page = await client.get("/login", params={"txn": txn})
            assert "Вход для подключения клиента" in page.text
            assert not any(c.startswith("km_lang=") for c in page.headers.get_list("set-cookie"))


def test_provider_title_is_escaped_once() -> None:
    t = TRANSLATIONS["en"]
    provider = ProviderView("att", "redirect", "AT&T", ())
    html = _redirect_provider_html(provider, t, txn="T", csrf="C")
    assert "AT&amp;T" in html
    assert "&amp;amp;" not in html


@pytest.mark.asyncio
async def test_lang_cookie_path_is_root_for_host_prefix() -> None:
    app, settings, _oauth = _google_app(base_url="https://mcp.example.com")
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.com"
        ) as client:
            client_id = await register_client(client)
            verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            page = await client.get("/login", params={"txn": txn, "lang": "he"})
            assert page.status_code == 200
            lang_cookie = next(
                c for c in page.headers.get_list("set-cookie") if c.startswith("__Host-km_lang=")
            )
            assert "Path=/;" in lang_cookie.replace(" ", "")
            assert "Secure" in lang_cookie


@pytest.mark.asyncio
async def test_lang_cookie_path_is_login_over_http() -> None:
    app, settings, _oauth = _google_app(base_url="http://localhost:8080")
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://localhost:8080"
        ) as client:
            client_id = await register_client(client)
            verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            page = await client.get("/login", params={"txn": txn, "lang": "he"})
            assert page.status_code == 200
            lang_cookie = next(
                c for c in page.headers.get_list("set-cookie") if c.startswith("km_lang=")
            )
            assert "Path=/login" in lang_cookie


def test_brand_is_escaped() -> None:
    brand = Settings(login_brand="<b>x</b>").login_brand
    t = TRANSLATIONS["en"]
    html = render_consent_page(
        lang="en",
        t=t,
        brand=brand,
        client_name="App",
        redirect_uri="http://localhost/cb",
        redirect_location="localhost",
        providers=_SAMPLE_PROVIDERS[:1],
        txn="T",
        csrf=None,
        error_key=None,
        txn_query="txn=T&",
    )
    assert "&lt;b&gt;x&lt;/b&gt;" in html
    assert "<h1><b>x</b></h1>" not in html
