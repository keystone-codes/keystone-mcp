"""OAuth session persistence: refresh without /login and survive provider restart."""

from __future__ import annotations

import asyncio
import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull

from conftest import (
    BASE_URL,
    VALID_TOKEN,
    authorize_to_login,
    make_pkce,
    obtain_access_token,
    refresh_access_token,
    register_client,
)
from keystone_mcp.auth.keystone_oauth_provider import (
    KeystoneOAuthProvider,
    RefreshMeta,
    encode_refresh_meta,
)
from keystone_mcp.auth.login_pending_store import InMemoryLoginPendingStore
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from support.fake_login import FakeRedirectProvider
from support.login import dev_token_login


@pytest_asyncio.fixture
async def persistence_client():
    """ASGI client backed by a shared InMemoryOAuthStore for restart tests."""
    settings = Settings(base_url=BASE_URL)
    _login = dev_token_login({VALID_TOKEN})
    store = InMemoryOAuthStore()
    mcp, _registry, oauth, _upstreams, _policy_manager, _observability, _reconciler = build_server(
        login_providers=[_login], settings=settings, oauth_store=store
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            yield client, oauth, store, settings


async def test_refresh_token_skips_login(harness):
    """After initial OAuth, refresh grant must not require another /login POST."""
    res = await obtain_access_token(harness.client, harness.settings.resource_url)
    assert res["status"] == 200
    refresh = res["body"]["refresh_token"]
    client_id = res["client_id"]

    refreshed = await refresh_access_token(
        harness.client, client_id, refresh, harness.settings.resource_url
    )
    assert refreshed["status"] == 200, refreshed
    assert refreshed["body"].get("access_token")
    assert refreshed["body"].get("refresh_token")


async def test_tokens_survive_provider_restart(persistence_client):
    """A new provider instance sharing the store can load clients and refresh tokens."""
    client, _oauth1, store, settings = persistence_client
    res = await obtain_access_token(client, settings.resource_url)
    assert res["status"] == 200
    refresh = res["body"]["refresh_token"]
    client_id = res["client_id"]

    _login = dev_token_login({VALID_TOKEN})
    pending_store = _oauth1._pending_store
    oauth2 = KeystoneOAuthProvider(settings, store, pending_store, login_providers=[_login])
    registered = await oauth2.get_client(client_id)
    assert registered is not None

    loaded = await oauth2.load_refresh_token(registered, refresh)
    assert loaded is not None
    assert loaded.subject == "user@example.com"

    token = await oauth2.exchange_refresh_token(registered, loaded, [])
    assert token.access_token
    assert token.refresh_token


async def test_pending_txn_survives_shared_store_restart(persistence_client):
    """Pending login txn readable by a new provider sharing the login pending store."""
    client, oauth1, store, settings = persistence_client
    pending_store = oauth1._pending_store
    client_id = await register_client(client)
    _verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

    _login = dev_token_login({VALID_TOKEN})
    oauth2 = KeystoneOAuthProvider(settings, store, pending_store, login_providers=[_login])
    assert await oauth2._get_pending_txn(txn) is not None


async def test_redis_store_roundtrip():
    """RedisOAuthStore serializes clients and tokens (skip without Redis URL)."""
    from mcp.server.auth.provider import AccessToken, RefreshToken
    from mcp.shared.auth import OAuthClientInformationFull

    from keystone_mcp.auth.oauth_store import RedisOAuthStore
    from support.test_env import redis_key_prefix, require_redis_url

    url = require_redis_url()
    store = RedisOAuthStore(url, key_prefix=redis_key_prefix("oauth"))
    try:
        client = OAuthClientInformationFull(
            client_id="test-client-id",
            redirect_uris=["http://localhost/cb"],
            token_endpoint_auth_method="none",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
        )
        await store.put_client(client)
        assert await store.get_client("test-client-id") is not None

        refresh = RefreshToken(
            token="km_rt_test",
            client_id="test-client-id",
            scopes=[],
            expires_at=None,
            subject="u@example.com",
        )
        await store.put_refresh_token(refresh)
        assert await store.get_refresh_token("km_rt_test") is not None

        access = AccessToken(
            token="km_at_test",
            client_id="test-client-id",
            scopes=[],
            expires_at=9999999999,
            subject="u@example.com",
            claims={"email": "u@example.com"},
        )
        await store.put_access_token(access)
        assert await store.get_access_token("km_at_test") is not None
    finally:
        await store.delete_refresh_token("km_rt_test")
        await store.delete_access_token("km_at_test")
        await store.aclose()


# ── Refresh-token lifetime and the auth_method marker ───────────────────────
async def test_refresh_token_carries_the_configured_lifetime(persistence_client):
    client, _oauth, store, settings = persistence_client
    before = time.time()
    res = await obtain_access_token(client, settings.resource_url)
    assert res["status"] == 200

    stored = await store.get_refresh_token(res["body"]["refresh_token"])
    assert stored is not None
    assert stored.expires_at is not None
    expected = before + settings.refresh_token_ttl_seconds
    assert abs(stored.expires_at - expected) < 30


async def test_refresh_token_default_lifetime_is_thirty_days():
    assert Settings().refresh_token_ttl_seconds == 30 * 24 * 3600


async def test_auth_method_marker_ttl_equals_the_refresh_token_lifetime():
    """The marker is keyed by refresh token, so its TTL must match that token's."""
    settings = Settings(base_url=BASE_URL, refresh_token_ttl_seconds=1234)
    pending = InMemoryLoginPendingStore()
    provider = KeystoneOAuthProvider(
        settings,
        InMemoryOAuthStore(),
        pending,
        login_providers=[
            dev_token_login(
                {VALID_TOKEN}
                if isinstance({VALID_TOKEN}, set)
                else set({VALID_TOKEN})
                if False
                else {VALID_TOKEN}
            )
        ],
    )
    recorded: list[tuple[str, str, str, int]] = []
    original_put = pending.put

    async def spying_put(namespace, key, payload, ttl_seconds):
        recorded.append((namespace, key, payload, ttl_seconds))
        await original_put(namespace, key, payload, ttl_seconds)

    pending.put = spying_put  # type: ignore[method-assign]
    marker = RefreshMeta(
        auth_method="google",
        resource=None,
        interactive=True,
        auth_time=None,
        key_id=None,
        key_id_known=False,
        key_expires_at=None,
    )
    await provider._put_refresh_meta("km_rt_marker", marker)

    assert recorded == [
        (
            "refresh_auth",
            "km_rt_marker",
            encode_refresh_meta(marker),
            1234,
        )
    ]


async def test_expired_refresh_token_is_refused_and_dropped():
    settings = Settings(base_url=BASE_URL, refresh_token_ttl_seconds=30 * 24 * 3600)
    store = InMemoryOAuthStore()
    provider = KeystoneOAuthProvider(
        settings,
        store,
        InMemoryLoginPendingStore(),
        login_providers=[
            dev_token_login(
                {VALID_TOKEN}
                if isinstance({VALID_TOKEN}, set)
                else set({VALID_TOKEN})
                if False
                else {VALID_TOKEN}
            )
        ],
    )
    registered = OAuthClientInformationFull(
        client_id="client-1",
        redirect_uris=["http://localhost:9999/callback"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    await store.put_refresh_token(
        RefreshToken(
            token="km_rt_expired",
            client_id="client-1",
            scopes=[],
            expires_at=int(time.time()) - 1,
            subject="user@example.com",
        )
    )

    assert await provider.load_refresh_token(registered, "km_rt_expired") is None
    assert await store.get_refresh_token("km_rt_expired") is None


async def test_live_refresh_token_is_accepted():
    settings = Settings(base_url=BASE_URL)
    store = InMemoryOAuthStore()
    provider = KeystoneOAuthProvider(
        settings,
        store,
        InMemoryLoginPendingStore(),
        login_providers=[
            dev_token_login(
                {VALID_TOKEN}
                if isinstance({VALID_TOKEN}, set)
                else set({VALID_TOKEN})
                if False
                else {VALID_TOKEN}
            )
        ],
    )
    registered = OAuthClientInformationFull(
        client_id="client-1",
        redirect_uris=["http://localhost:9999/callback"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    await store.put_refresh_token(
        RefreshToken(
            token="km_rt_live",
            client_id="client-1",
            scopes=[],
            expires_at=int(time.time()) + 600,
            subject="user@example.com",
        )
    )
    loaded = await provider.load_refresh_token(registered, "km_rt_live")
    assert loaded is not None
    assert loaded.token == "km_rt_live"


# ── Rotation ordering ───────────────────────────────────────────────────────
async def test_rotation_persists_the_new_token_before_deleting_the_old():
    """A crash between the two steps must not strand the session."""
    settings = Settings(base_url=BASE_URL)
    store = InMemoryOAuthStore()
    provider = KeystoneOAuthProvider(
        settings,
        store,
        InMemoryLoginPendingStore(),
        login_providers=[
            dev_token_login(
                {VALID_TOKEN}
                if isinstance({VALID_TOKEN}, set)
                else set({VALID_TOKEN})
                if False
                else {VALID_TOKEN}
            )
        ],
    )
    registered = OAuthClientInformationFull(
        client_id="client-1",
        redirect_uris=["http://localhost:9999/callback"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    old = RefreshToken(
        token="km_rt_old",
        client_id="client-1",
        scopes=[],
        expires_at=int(time.time()) + 600,
        subject="user@example.com",
    )
    await store.put_refresh_token(old)
    await provider._put_refresh_meta(
        "km_rt_old",
        RefreshMeta(
            auth_method="api_key",
            resource=None,
            interactive=False,
            auth_time=None,
            key_id=None,
            key_id_known=False,
            key_expires_at=None,
        ),
    )

    calls: list[str] = []
    original_put = store.put_refresh_token
    original_delete = store.delete_refresh_token

    async def spying_put(refresh):
        calls.append(f"put:{refresh.token}")
        await original_put(refresh)

    async def spying_delete(token):
        calls.append(f"delete:{token}")
        await original_delete(token)

    store.put_refresh_token = spying_put  # type: ignore[method-assign]
    store.delete_refresh_token = spying_delete  # type: ignore[method-assign]

    issued = await provider.exchange_refresh_token(registered, old, [])
    new_token = issued.refresh_token
    assert new_token is not None

    assert calls == [f"put:{new_token}", "delete:km_rt_old"]
    assert calls.index(f"put:{new_token}") < calls.index("delete:km_rt_old")


async def test_crash_after_minting_leaves_a_usable_refresh_token():
    """Simulate the interrupted rotation: the client's new token still works."""
    settings = Settings(base_url=BASE_URL)
    store = InMemoryOAuthStore()
    provider = KeystoneOAuthProvider(
        settings,
        store,
        InMemoryLoginPendingStore(),
        login_providers=[
            dev_token_login(
                {VALID_TOKEN}
                if isinstance({VALID_TOKEN}, set)
                else set({VALID_TOKEN})
                if False
                else {VALID_TOKEN}
            )
        ],
    )
    registered = OAuthClientInformationFull(
        client_id="client-1",
        redirect_uris=["http://localhost:9999/callback"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    old = RefreshToken(
        token="km_rt_old",
        client_id="client-1",
        scopes=[],
        expires_at=int(time.time()) + 600,
        subject="user@example.com",
    )
    await store.put_refresh_token(old)
    await provider._put_refresh_meta(
        "km_rt_old",
        RefreshMeta(
            auth_method="api_key",
            resource=None,
            interactive=False,
            auth_time=None,
            key_id=None,
            key_id_known=False,
            key_expires_at=None,
        ),
    )

    class _Crash(RuntimeError):
        pass

    async def crashing_delete(_token):
        raise _Crash("process died before retiring the old token")

    store.delete_refresh_token = crashing_delete  # type: ignore[method-assign]

    with pytest.raises(_Crash):
        await provider.exchange_refresh_token(registered, old, [])

    # Exactly one new refresh token was persisted, and the old one survives —
    # either way the client can still refresh.
    from keystone_mcp.auth.oauth_store import token_digest

    tokens = set(store._refresh_tokens)
    assert token_digest("km_rt_old") in tokens
    assert len(tokens) == 2


# ── Concurrent refresh must not downgrade the auth_method ───────────────────
async def test_concurrent_refresh_keeps_google_auth_method(persistence_client):
    """Two parallel refreshes of the same token must both keep auth_method=google.

    Reproduces the race: exchange_refresh_token used to consume (GETDEL) the
    auth_method marker as its first step, so the second of two concurrent
    requests for the same refresh token saw no marker and fell back to
    "api_key", downgrading a Google-authenticated session.
    """
    client, oauth, store, settings = persistence_client
    res = await obtain_access_token(client, settings.resource_url)
    assert res["status"] == 200
    refresh_token_str = res["body"]["refresh_token"]
    client_id = res["client_id"]

    # obtain_access_token logs in via the api_key form; overwrite the marker
    # to simulate a session that authenticated through Google. This fixture's
    # server only configures the built-in api_key provider, so "google" is
    # registered directly on the already-built provider (X05 refuses a
    # refresh naming a provider that is not currently configured) rather than
    # rebuilding the whole app with Google turned on, which would also pull
    # in a real users-directory resolver and change every other login in
    # this fixture.
    oauth._providers["google"] = oauth._providers["api_key"]
    await oauth._put_refresh_meta(
        refresh_token_str,
        RefreshMeta(
            auth_method="google",
            resource=None,
            interactive=True,
            auth_time=None,
            key_id=None,
            key_id_known=False,
            key_expires_at=None,
        ),
    )

    registered = await oauth.get_client(client_id)
    assert registered is not None
    loaded = await oauth.load_refresh_token(registered, refresh_token_str)
    assert loaded is not None

    # InMemoryOAuthStore and InMemoryLoginPendingStore never actually suspend
    # on I/O, so two gathered coroutines would otherwise run back-to-back
    # instead of interleaving. Force the same interleaving a real Redis round
    # trip produces by yielding right where the marker is read, so both
    # requests read the marker before either of them drops it.
    pending_store = oauth._pending_store
    original_get = pending_store.get

    async def delayed_get(namespace, key):
        value = await original_get(namespace, key)
        await asyncio.sleep(0)
        return value

    pending_store.get = delayed_get  # type: ignore[method-assign]

    first, second = await asyncio.gather(
        oauth.exchange_refresh_token(registered, loaded, []),
        oauth.exchange_refresh_token(registered, loaded, []),
    )
    assert first.access_token == second.access_token
    assert first.refresh_token == second.refresh_token

    for issued in (first, second):
        access = await store.get_access_token(issued.access_token)
        assert access is not None
        assert access.claims["auth_method"] == "google"


async def test_old_auth_marker_gets_short_grace_ttl_after_rotation(persistence_client):
    """After a successful rotation, the old refresh token's marker is rewritten, not deleted.

    This used to assert the marker was gone immediately after rotation. That
    is exactly what reopened the race this fix (finding #2, below) closes: a
    second request that validated the old refresh token concurrently with the
    one that won the rotation would read no marker at all once the first
    request deleted it, and silently downgrade to ("api_key", None). Instead
    the marker is rewritten with a short grace TTL, which this test checks
    directly against the in-memory store's expiry bookkeeping.
    """
    client, oauth, _store, settings = persistence_client
    res = await obtain_access_token(client, settings.resource_url)
    assert res["status"] == 200
    old_refresh = res["body"]["refresh_token"]
    client_id = res["client_id"]

    before = time.time()
    refreshed = await refresh_access_token(client, client_id, old_refresh, settings.resource_url)
    assert refreshed["status"] == 200

    # Still readable right after rotation, with the same auth_method/resource
    # a second concurrent request would need.
    raw = await oauth._pending_store.get("refresh_auth", old_refresh)
    assert raw is not None
    data = json.loads(raw)
    assert data["auth_method"] == "api_key"

    # But its TTL is the short grace window, not the full refresh-token
    # lifetime: it will not linger in Redis/memory forever.
    entry = oauth._pending_store._entries[("refresh_auth", old_refresh)]
    assert entry.expires_at <= before + settings.oauth_refresh_grace_seconds + 1


async def test_second_refresh_keeps_auth_method_after_first_fully_completes(persistence_client):
    """The residual race finding #2 closes: not two readers racing one write, but a
    reader that arrives after the writer it raced has already finished.

    Both requests for the same old refresh token validate it (the SDK's
    ``load_refresh_token``) before either one rotates it away — that part of
    the race was already closed by reading the marker without deleting it.
    What was still open: request A can rotate the token *all the way through*
    (including dropping the old marker) before request B, which validated the
    same old token earlier, calls ``exchange_refresh_token``. B's own refresh
    token is perfectly valid; it should not lose the Google-authenticated
    session just because A finished first.
    """
    client, oauth, store, settings = persistence_client
    res = await obtain_access_token(client, settings.resource_url)
    assert res["status"] == 200
    refresh_token_str = res["body"]["refresh_token"]
    client_id = res["client_id"]

    # Simulate a session that authenticated through Google (see the comment
    # in test_concurrent_refresh_keeps_google_auth_method for why "google" is
    # registered directly on the provider instead of rebuilding the app).
    oauth._providers["google"] = oauth._providers["api_key"]
    await oauth._put_refresh_meta(
        refresh_token_str,
        RefreshMeta(
            auth_method="google",
            resource=settings.resource_url,
            interactive=True,
            auth_time=None,
            key_id=None,
            key_id_known=False,
            key_expires_at=None,
        ),
    )

    registered = await oauth.get_client(client_id)
    assert registered is not None
    loaded = await oauth.load_refresh_token(registered, refresh_token_str)
    assert loaded is not None

    # Request A: rotates the old token all the way through.
    first = await oauth.exchange_refresh_token(registered, loaded, [])
    assert first.refresh_token is not None

    # Request B: had already validated `loaded` (its own load_refresh_token
    # call, concurrent with A's) before A finished, and now presents the same
    # now-retired old RefreshToken object.
    second = await oauth.exchange_refresh_token(registered, loaded, [])

    access = await store.get_access_token(second.access_token)
    assert access is not None
    assert access.claims["auth_method"] == "google"
    assert access.resource == settings.resource_url


# ── Client TTL: touched before the refresh token it owns is written ────────
async def test_client_is_touched_before_refresh_token_is_written():
    settings = Settings(base_url=BASE_URL)
    store = InMemoryOAuthStore()
    provider = KeystoneOAuthProvider(
        settings,
        store,
        InMemoryLoginPendingStore(),
        login_providers=[
            dev_token_login(
                {VALID_TOKEN}
                if isinstance({VALID_TOKEN}, set)
                else set({VALID_TOKEN})
                if False
                else {VALID_TOKEN}
            )
        ],
    )
    client = OAuthClientInformationFull(
        client_id="client-1",
        redirect_uris=["http://localhost:9999/callback"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    await store.put_client(client)

    calls: list[str] = []
    original_touch = store.touch_client
    original_put_refresh = store.put_refresh_token

    async def spying_touch(client_id):
        calls.append(f"touch:{client_id}")
        await original_touch(client_id)

    async def spying_put_refresh(refresh):
        calls.append(f"put_refresh:{refresh.token}")
        await original_put_refresh(refresh)

    store.touch_client = spying_touch  # type: ignore[method-assign]
    store.put_refresh_token = spying_put_refresh  # type: ignore[method-assign]

    auth_code = AuthorizationCode(
        code="km_code_test",
        scopes=[],
        expires_at=time.time() + 600,
        client_id="client-1",
        code_challenge="challenge",
        redirect_uri="http://localhost:9999/callback",
        redirect_uri_provided_explicitly=True,
        resource=None,
        subject="user@example.com",
    )
    await provider._put_auth_code(auth_code, auth_method="api_key", interactive=False)

    issued = await provider.exchange_authorization_code(client, auth_code)

    touch_idx = calls.index("touch:client-1")
    put_idx = next(i for i, c in enumerate(calls) if c.startswith("put_refresh:"))
    assert touch_idx < put_idx

    # Same ordering guarantee on the refresh grant.
    calls.clear()
    refresh = await store.get_refresh_token(issued.refresh_token)
    assert refresh is not None
    await provider.exchange_refresh_token(client, refresh, [])

    touch_idx = calls.index("touch:client-1")
    put_idx = next(i for i, c in enumerate(calls) if c.startswith("put_refresh:"))
    assert touch_idx < put_idx


# ── X05: the interactive claim comes from the provider, and survives refresh ──


async def test_refresh_keeps_interactive_flag():
    """A session opened through an interactive provider keeps interactive=True
    across two consecutive refreshes -- the claim is carried on the refresh
    marker (``_put_refresh_meta``), not recomputed from the provider's name.
    """
    settings = Settings(base_url=BASE_URL)
    store = InMemoryOAuthStore()
    pending = InMemoryLoginPendingStore()
    okta = FakeRedirectProvider("okta", interactive=True)
    provider = KeystoneOAuthProvider(settings, store, pending, login_providers=[okta])

    client = OAuthClientInformationFull(
        client_id="client-1",
        redirect_uris=["http://localhost:9999/callback"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    await store.put_client(client)
    params = AuthorizationParams(
        state="s",
        scopes=[],
        code_challenge="c",
        redirect_uri="http://localhost:9999/callback",
        redirect_uri_provided_explicitly=True,
        resource=None,
    )
    redirect_url = await provider.authorize(client, params)
    txn_id = parse_qs(urlparse(redirect_url).query)["txn"][0]

    identity = await okta.complete(
        params={"email": "alice@example.com"}, callback_url="unused", attempt={}
    )
    response = await provider._complete_login(
        txn_id, identity, "en", auth_method="okta", interactive=okta.interactive
    )
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    auth_code = await provider.load_authorization_code(client, code)
    assert auth_code is not None
    issued = await provider.exchange_authorization_code(client, auth_code)

    access = await store.get_access_token(issued.access_token)
    assert access is not None
    assert access.claims["interactive"] is True

    refresh = await store.get_refresh_token(issued.refresh_token)
    assert refresh is not None
    second = await provider.exchange_refresh_token(client, refresh, [])
    refresh2 = await store.get_refresh_token(second.refresh_token)
    assert refresh2 is not None
    third = await provider.exchange_refresh_token(client, refresh2, [])

    final_access = await store.get_access_token(third.access_token)
    assert final_access is not None
    assert final_access.claims["auth_method"] == "okta"
    assert final_access.claims["interactive"] is True


async def test_refresh_marker_from_0_4_is_read():
    """A 0.4.0 marker (``{"auth_method", "resource"}``, no ``interactive``) and
    the oldest bare-string marker both rebuild ``interactive`` from the sign-in
    method's name.
    """
    settings = Settings(base_url=BASE_URL)
    store = InMemoryOAuthStore()
    pending = InMemoryLoginPendingStore()
    provider = KeystoneOAuthProvider(
        settings,
        store,
        pending,
        login_providers=[
            dev_token_login(
                {VALID_TOKEN}
                if isinstance({VALID_TOKEN}, set)
                else set({VALID_TOKEN})
                if False
                else {VALID_TOKEN}
            )
        ],
    )

    await pending.put(
        "refresh_auth",
        "km_rt_04_google",
        json.dumps({"auth_method": "google", "resource": None}),
        3600,
    )
    meta = await provider._read_refresh_meta("km_rt_04_google")
    assert meta is not None
    assert (meta.auth_method, meta.resource, meta.interactive) == ("google", None, True)

    await pending.put("refresh_auth", "km_rt_oldest_api_key", "api_key", 3600)
    meta = await provider._read_refresh_meta("km_rt_oldest_api_key")
    assert meta is not None
    assert (meta.auth_method, meta.resource, meta.interactive) == ("api_key", None, False)


async def test_refresh_for_removed_provider_is_refused():
    """A refresh token opened through a provider that was since removed from
    the configuration is refused (``invalid_grant``), not silently downgraded
    to api_key sign-in -- the old X03 fallback this replaces.
    """
    settings = Settings(base_url=BASE_URL)
    store = InMemoryOAuthStore()
    pending = InMemoryLoginPendingStore()
    provider = KeystoneOAuthProvider(
        settings,
        store,
        pending,
        login_providers=[
            dev_token_login(
                {VALID_TOKEN}
                if isinstance({VALID_TOKEN}, set)
                else set({VALID_TOKEN})
                if False
                else {VALID_TOKEN}
            )
        ],
    )
    client = OAuthClientInformationFull(
        client_id="client-1",
        redirect_uris=["http://localhost:9999/callback"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    await store.put_client(client)
    old = RefreshToken(
        token="km_rt_okta_removed",
        client_id="client-1",
        scopes=[],
        expires_at=int(time.time()) + 600,
        subject="user@example.com",
    )
    await store.put_refresh_token(old)
    await provider._put_refresh_meta(
        "km_rt_okta_removed",
        RefreshMeta(
            auth_method="okta",
            resource=None,
            interactive=True,
            auth_time=None,
            key_id=None,
            key_id_known=False,
            key_expires_at=None,
        ),
    )

    with pytest.raises(TokenError) as excinfo:
        await provider.exchange_refresh_token(client, old, [])
    assert excinfo.value.error == "invalid_grant"

    assert await store.get_refresh_token("km_rt_okta_removed") is None
    assert await pending.get("refresh_auth", "km_rt_okta_removed") is None
