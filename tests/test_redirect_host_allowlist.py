"""`KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS` (A17).

An organisation that knows its own clients (say, only Claude and Cursor) can
restrict which hosts a registered client's ``redirect_uri`` may point to.
Empty (the default) means no restriction — the 0.3.1 behaviour. When set,
both ``POST /register`` (``KeystoneOAuthProvider.register_client``) and
``GET /authorize`` (``KeystoneOAuthProvider.authorize``) refuse a
``redirect_uri`` whose host is not on the list; the host check in
``register_client`` runs before the client-count cap from A12.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from asgi_lifespan import LifespanManager
from mcp.server.auth.provider import AuthorizationCode, RefreshToken, TokenError
from mcp.shared.auth import OAuthClientInformationFull
from prometheus_client import REGISTRY

from conftest import BASE_URL, REDIRECT_URI, make_pkce, register_client
from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.keystone_oauth_provider import (
    KeystoneOAuthProvider,
    _redirect_uri_allowed,
)
from keystone_mcp.auth.login_pending_store import InMemoryLoginPendingStore
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import ConfigError, Settings
from keystone_mcp.server import build_server

VALID_TOKEN = "valid-test-token"
_REDIRECT_HOST = urlparse(REDIRECT_URI).hostname  # "localhost"


def _build_app(*, oauth_store=None, **settings_overrides):
    settings = Settings(base_url=BASE_URL, refresh_interval_seconds=0, **settings_overrides)
    idp = StaticIdentityProvider({VALID_TOKEN})
    store = oauth_store if oauth_store is not None else InMemoryOAuthStore()
    mcp, *_rest = build_server(
        identity_provider=idp,
        settings=settings,
        oauth_store=store,
        register_builtin_catalog=False,
    )
    return mcp.http_app(path=settings.http_path), store


def _registrations(outcome: str) -> float:
    return (
        REGISTRY.get_sample_value(
            "keystone_mcp_oauth_client_registrations_total",
            {"outcome": outcome},
        )
        or 0.0
    )


async def test_empty_allowlist_allows_any_redirect() -> None:
    app, _store = _build_app(oauth_allowed_redirect_hosts=())
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={
                    "redirect_uris": ["https://evil.example/cb"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert r.status_code == 201, r.text


async def test_registration_refused_for_unlisted_host() -> None:
    app, _store = _build_app(oauth_allowed_redirect_hosts=("claude.ai",))
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={
                    "redirect_uris": ["https://evil.example/cb"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert r.status_code == 400, r.text
            body = r.json()
            assert body["error"] == "invalid_redirect_uri"
            assert "evil.example" in body["error_description"]


async def test_registration_allowed_for_listed_host() -> None:
    app, _store = _build_app(oauth_allowed_redirect_hosts=(_REDIRECT_HOST,))
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={
                    "redirect_uris": [REDIRECT_URI],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert r.status_code == 201, r.text


async def test_one_bad_uri_rejects_the_whole_registration() -> None:
    app, store = _build_app(oauth_allowed_redirect_hosts=(_REDIRECT_HOST,))
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={
                    "redirect_uris": [REDIRECT_URI, "https://evil.example/cb"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert r.status_code == 400, r.text
            assert r.json()["error"] == "invalid_redirect_uri"
    assert await store.count_clients() == 0


async def test_custom_scheme_host_is_matched() -> None:
    # A custom (non-http(s)) scheme is matched only against an explicit
    # `scheme://host` allowlist entry (finding #4): a bare host entry no
    # longer implies "any scheme on this host", since that was exactly the
    # gap that let `evil-app://claude.ai/cb` or `http://claude.ai/...` through
    # under an allowlist meant for `https://claude.ai`.
    app, _store = _build_app(
        oauth_allowed_redirect_scheme_hosts=("cursor://anysphere.cursor-retrieval",)
    )
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={
                    "redirect_uris": ["cursor://anysphere.cursor-retrieval/cb"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert r.status_code == 201, r.text


async def test_custom_scheme_is_refused_without_an_explicit_scheme_host_entry() -> None:
    """The gap finding #4 closes: a bare host entry no longer allows every scheme."""
    app, _store = _build_app(oauth_allowed_redirect_hosts=("anysphere.cursor-retrieval",))
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={
                    "redirect_uris": ["cursor://anysphere.cursor-retrieval/cb"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert r.status_code == 400, r.text
            assert r.json()["error"] == "invalid_redirect_uri"


async def test_http_is_refused_for_a_non_loopback_host_even_when_listed() -> None:
    """finding #4: an allowed host does not make plain http trustworthy for it."""
    app, _store = _build_app(oauth_allowed_redirect_hosts=("claude.ai",))
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={
                    "redirect_uris": ["http://claude.ai/cb"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert r.status_code == 400, r.text
            assert r.json()["error"] == "invalid_redirect_uri"


async def test_https_is_allowed_for_a_listed_non_loopback_host() -> None:
    app, _store = _build_app(oauth_allowed_redirect_hosts=("claude.ai",))
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={
                    "redirect_uris": ["https://claude.ai/cb"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert r.status_code == 201, r.text


async def test_redirect_uris_null_is_refused_instead_of_crashing() -> None:
    """finding #5: `redirect_uris: null` must not reach `for ... in None`."""
    app, _store = _build_app(oauth_allowed_redirect_hosts=("claude.ai",))
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={"redirect_uris": None, "token_endpoint_auth_method": "none"},
            )
            assert r.status_code == 400, r.text
            assert r.json()["error"] == "invalid_redirect_uri"


async def test_authorize_refused_for_preexisting_client_on_unlisted_host() -> None:
    # The client registered before the restriction existed (or was registered
    # with allowlisting off); it is already in the store.
    store = InMemoryOAuthStore()
    preexisting = OAuthClientInformationFull(
        client_id="preexisting-client",
        redirect_uris=["https://evil.example/cb"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    await store.put_client(preexisting)

    app, _store = _build_app(oauth_store=store, oauth_allowed_redirect_hosts=("claude.ai",))
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            _verifier, challenge = make_pkce()
            r = await client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": "preexisting-client",
                    "redirect_uri": "https://evil.example/cb",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "test-state",
                    "resource": f"{BASE_URL}/",
                },
            )
            # Refusing used to redirect (302) straight to the client's own
            # (disallowed) redirect_uri with `error`/`state` query parameters —
            # itself a browser hop to the host this allowlist exists to keep
            # the browser away from, even with no code attached. Finding #3:
            # the refusal now stays on this server instead.
            assert r.status_code == 302, r.text
            location = r.headers["location"]
            assert location.startswith(BASE_URL)
            assert "evil.example" not in location
            assert "state" not in parse_qs(urlparse(location).query)

            follow = await client.get(location)
            assert follow.status_code == 400, follow.text
            assert "evil.example" not in follow.text


def test_allowlist_parsing(monkeypatch) -> None:
    # Case-insensitive, whitespace-trimmed, empty elements dropped.
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "  Claude.AI , , localhost ")
    settings = Settings(base_url=BASE_URL)
    assert settings.oauth_allowed_redirect_hosts == ("claude.ai", "localhost")

    # A scheme in an entry is refused with a startup error, not silently stripped.
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "https://claude.ai")
    with pytest.raises(ConfigError, match="OAUTH_ALLOWED_REDIRECT_HOSTS"):
        Settings(base_url=BASE_URL)

    # A port in an entry is refused the same way.
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "host:443")
    with pytest.raises(ConfigError, match="OAUTH_ALLOWED_REDIRECT_HOSTS"):
        Settings(base_url=BASE_URL)

    # A custom scheme paired with a host (finding #4) parses into its own
    # field, separate from the bare hosts.
    monkeypatch.setenv(
        "KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS",
        "claude.ai,cursor://anysphere.cursor-retrieval",
    )
    settings = Settings(base_url=BASE_URL)
    assert settings.oauth_allowed_redirect_hosts == ("claude.ai",)
    assert settings.oauth_allowed_redirect_scheme_hosts == ("cursor://anysphere.cursor-retrieval",)

    # http/https are refused in `scheme://host` form too: that form exists for
    # custom schemes only, and allowing it here would be a second way to
    # write a bare host entry that silently skips the loopback-only rule for
    # `http` (see `_redirect_uri_allowed`).
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "https://claude.ai")
    with pytest.raises(ConfigError, match="OAUTH_ALLOWED_REDIRECT_HOSTS"):
        Settings(base_url=BASE_URL)
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "http://claude.ai")
    with pytest.raises(ConfigError, match="OAUTH_ALLOWED_REDIRECT_HOSTS"):
        Settings(base_url=BASE_URL)

    # A malformed scheme-qualified entry (no host, or a path/port tacked on)
    # is refused rather than silently dropped or half-parsed.
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "cursor://")
    with pytest.raises(ConfigError, match="OAUTH_ALLOWED_REDIRECT_HOSTS"):
        Settings(base_url=BASE_URL)
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "cursor://host/path")
    with pytest.raises(ConfigError, match="OAUTH_ALLOWED_REDIRECT_HOSTS"):
        Settings(base_url=BASE_URL)


async def test_rejected_redirect_host_metric() -> None:
    app, _store = _build_app(oauth_allowed_redirect_hosts=("claude.ai",), metrics_enabled=True)
    before = _registrations("rejected_redirect_host")

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={
                    "redirect_uris": ["https://evil.example/cb"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert r.status_code == 400, r.text

    assert _registrations("rejected_redirect_host") == before + 1


# ── finding #3: the allowlist also gates /token, not just /authorize ───────
#
# register_client and authorize both check the allowlist, but neither
# retroactively evicts a client that registered before the allowlist existed
# (or before it was tightened). Without a check at token-exchange time, such
# a client could keep calling touch_client + rotating its refresh token
# forever, never going through either checked path again.


def _preexisting_client() -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id="preexisting-client",
        redirect_uris=["https://evil.example/cb"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )


async def test_refresh_exchange_refused_for_preexisting_client_on_unlisted_host() -> None:
    settings = Settings(base_url=BASE_URL, oauth_allowed_redirect_hosts=("claude.ai",))
    store = InMemoryOAuthStore()
    provider = KeystoneOAuthProvider(
        StaticIdentityProvider({VALID_TOKEN}), settings, store, InMemoryLoginPendingStore()
    )
    client = _preexisting_client()
    await store.put_client(client)
    refresh = RefreshToken(
        token="km_rt_preexisting",
        client_id="preexisting-client",
        scopes=[],
        expires_at=int(time.time()) + 600,
        subject="user@example.com",
    )
    await store.put_refresh_token(refresh)

    with pytest.raises(TokenError) as exc_info:
        await provider.exchange_refresh_token(client, refresh, [])
    assert exc_info.value.error == "unauthorized_client"

    # Refused before any rotation side effect: the old token still works
    # (i.e. nothing was consumed or replaced by the refused call).
    assert await store.get_refresh_token("km_rt_preexisting") is not None


async def test_authorization_code_exchange_refused_for_preexisting_client_on_unlisted_host() -> (
    None
):
    settings = Settings(base_url=BASE_URL, oauth_allowed_redirect_hosts=("claude.ai",))
    store = InMemoryOAuthStore()
    provider = KeystoneOAuthProvider(
        StaticIdentityProvider({VALID_TOKEN}), settings, store, InMemoryLoginPendingStore()
    )
    client = _preexisting_client()
    await store.put_client(client)
    auth_code = AuthorizationCode(
        code="km_code_preexisting",
        scopes=[],
        expires_at=time.time() + 600,
        client_id="preexisting-client",
        code_challenge="irrelevant-for-this-check",
        redirect_uri="https://evil.example/cb",  # type: ignore[arg-type]
        redirect_uri_provided_explicitly=True,
        resource=None,
        subject="user@example.com",
    )

    with pytest.raises(TokenError) as exc_info:
        await provider.exchange_authorization_code(client, auth_code)
    assert exc_info.value.error == "unauthorized_client"


# ── finding #3: the SDK must never redirect a disallowed host on its own ───
#
# `client.validate_scope` raises `InvalidScopeError` *inside* the SDK's own
# `AuthorizationHandler.handle` (mcp/server/auth/handlers/authorize.py),
# before `KeystoneOAuthProvider.authorize` is ever called — the one place the
# redirect-host allowlist was checked. The SDK's own error handler already
# has `client` and the SDK-validated `redirect_uri` by that point, and
# redirects straight there with `error`/`state` query parameters. For a
# client registered before the allowlist existed (or was tightened), that is
# a redirect to a host this allowlist exists to keep the browser away from.


async def test_authorize_refused_for_preexisting_client_with_invalid_scope() -> None:
    store = InMemoryOAuthStore()
    preexisting = OAuthClientInformationFull(
        client_id="preexisting-client",
        redirect_uris=["https://evil.example/cb"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    await store.put_client(preexisting)

    app, _store = _build_app(oauth_store=store, oauth_allowed_redirect_hosts=("claude.ai",))
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            _verifier, challenge = make_pkce()
            r = await client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": "preexisting-client",
                    "redirect_uri": "https://evil.example/cb",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "test-state",
                    # The client was never registered with any scope
                    # (`scope` defaults to None), so any non-empty requested
                    # scope is "not registered" and trips `InvalidScopeError`
                    # inside the SDK, before `provider.authorize()` runs.
                    "scope": "bogus-scope-never-registered",
                    "resource": f"{BASE_URL}/",
                },
            )
            assert r.status_code == 302, r.text
            location = r.headers["location"]
            assert location.startswith(BASE_URL)
            assert "evil.example" not in location
            assert "state" not in parse_qs(urlparse(location).query)

            follow = await client.get(location)
            assert follow.status_code == 400, follow.text
            assert "evil.example" not in follow.text


async def test_authorize_still_works_for_an_allowed_client_with_invalid_scope() -> None:
    """The guard must not interfere with a client that IS on the allowlist."""
    app, _store = _build_app(oauth_allowed_redirect_hosts=(_REDIRECT_HOST,))
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
                    "state": "test-state",
                    "scope": "bogus-scope-never-registered",
                    "resource": f"{BASE_URL}/",
                },
            )
            # Reaches the SDK's own (unchanged) invalid_scope redirect, which
            # is safe here: REDIRECT_URI's host is on the allowlist.
            assert r.status_code == 302, r.text
            location = r.headers["location"]
            assert location.startswith(REDIRECT_URI)
            assert parse_qs(urlparse(location).query)["error"] == ["invalid_scope"]


async def test_authorize_post_still_works_for_an_allowed_client() -> None:
    """POST /authorize (body consumed by the guard) must still reach the SDK."""
    app, _store = _build_app(oauth_allowed_redirect_hosts=(_REDIRECT_HOST,))
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            r = await client.post(
                "/authorize",
                data={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": REDIRECT_URI,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "test-state",
                    "resource": f"{BASE_URL}/",
                },
            )
            assert r.status_code == 302, r.text
            assert "txn=" in r.headers["location"]


async def test_authorize_post_refused_for_preexisting_client_on_unlisted_host() -> None:
    store = InMemoryOAuthStore()
    preexisting = OAuthClientInformationFull(
        client_id="preexisting-client",
        redirect_uris=["https://evil.example/cb"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    await store.put_client(preexisting)

    app, _store = _build_app(oauth_store=store, oauth_allowed_redirect_hosts=("claude.ai",))
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            _verifier, challenge = make_pkce()
            r = await client.post(
                "/authorize",
                data={
                    "response_type": "code",
                    "client_id": "preexisting-client",
                    "redirect_uri": "https://evil.example/cb",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "test-state",
                    "resource": f"{BASE_URL}/",
                },
            )
            assert r.status_code == 302, r.text
            location = r.headers["location"]
            assert location.startswith(BASE_URL)
            assert "evil.example" not in location


# ── finding #9: `[::1]` (and bare `::1`) in the redirect-host allowlist ─────
#
# `_parse_redirect_host_entries` refused any entry containing `:`, which
# accidentally caught an IPv6 literal (`::1`) along with the port/scheme
# mistakes it was meant to catch. An allowlisted deployment could not name
# IPv6 loopback at all, even though `_redirect_uri_allowed`'s own
# `http`-is-loopback-only rule already recognizes `::1`.


def test_allowlist_parsing_accepts_ipv6_loopback(monkeypatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "claude.ai,[::1]")
    settings = Settings(base_url=BASE_URL)
    assert settings.oauth_allowed_redirect_hosts == ("claude.ai", "::1")

    # The bracket-free form (as a human might type it, or copy from a URL's
    # hostname) is accepted and normalized the same way.
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "claude.ai,::1")
    settings = Settings(base_url=BASE_URL)
    assert settings.oauth_allowed_redirect_hosts == ("claude.ai", "::1")


def test_allowlist_parsing_accepts_other_ipv6_literals(monkeypatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "[2001:db8::1]")
    settings = Settings(base_url=BASE_URL)
    assert settings.oauth_allowed_redirect_hosts == ("2001:db8::1",)


def test_allowlist_parsing_still_refuses_a_bare_ipv4_port(monkeypatch) -> None:
    # A single colon that is not a valid IPv6 literal is still a port mistake.
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "127.0.0.1:443")
    with pytest.raises(ConfigError, match="OAUTH_ALLOWED_REDIRECT_HOSTS"):
        Settings(base_url=BASE_URL)


def test_allowlist_parsing_still_refuses_garbage_with_a_colon(monkeypatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "not-ipv6:thing")
    with pytest.raises(ConfigError, match="OAUTH_ALLOWED_REDIRECT_HOSTS"):
        Settings(base_url=BASE_URL)


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        ("http://[::1]:9999/cb", True),
        ("http://[::1]/cb", True),
        ("https://[::1]/cb", True),
        ("https://[::1]:9999/cb", True),
    ],
)
def test_ipv6_loopback_redirect_uri_allowed_for_http_and_https(uri: str, expected: bool) -> None:
    assert _redirect_uri_allowed(uri, ("::1",), ()) is expected


async def test_registration_allowed_for_ipv6_loopback_redirect_uri() -> None:
    app, _store = _build_app(oauth_allowed_redirect_hosts=("::1",))
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={
                    "redirect_uris": ["http://[::1]:9999/cb"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert r.status_code == 201, r.text
