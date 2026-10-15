"""Login and dynamic client registration rate limits (429 + Retry-After)."""

from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest
import redis
from asgi_lifespan import LifespanManager
from redis.exceptions import RedisError

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore, build_shared_auth_stores
from keystone_mcp.auth.throttle import RedisLoginFailureLimiter
from keystone_mcp.config import ConfigError, Settings, load_settings, validate_settings
from keystone_mcp.server import build_server
from support.login import dev_token_login
from support.oauth_harness import (
    BASE_URL,
    REDIRECT_URI,
    VALID_TOKEN,
    authorize_to_login,
    make_pkce,
    register_client,
)
from support.test_env import redis_key_prefix, require_redis_url


def _build_app(**settings_overrides):
    settings = Settings(base_url=BASE_URL, refresh_interval_seconds=0, **settings_overrides)
    _login = dev_token_login({VALID_TOKEN})
    store = InMemoryOAuthStore()
    mcp, *_rest = build_server(
        login_providers=[_login],
        settings=settings,
        oauth_store=store,
        register_builtin_catalog=False,
    )
    return mcp.http_app(path=settings.http_path)


@pytest.mark.asyncio
async def test_register_returns_429_when_ip_limit_exceeded():
    app = _build_app(
        login_throttle_ip_max=2,
        login_throttle_email_max=0,
        login_throttle_window_seconds=300,
    )
    payload = {"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"}
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            assert (await client.post("/register", json=payload)).status_code in (200, 201)
            assert (await client.post("/register", json=payload)).status_code in (200, 201)
            blocked = await client.post("/register", json=payload)
            assert blocked.status_code == 429
            assert blocked.headers.get("retry-after") is not None
            assert int(blocked.headers["retry-after"]) >= 1


@pytest.mark.asyncio
async def test_login_post_returns_429_when_ip_limit_exceeded():
    app = _build_app(
        login_throttle_ip_max=2,
        login_throttle_email_max=0,
        login_throttle_window_seconds=300,
    )
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
            )
            client_id = r.json()["client_id"]
            verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, BASE_URL)
            assert (
                await client.post(
                    "/login",
                    data={"txn": txn, "api_token": "bad", "email": "a@example.com"},
                )
            ).status_code == 401
            blocked = await client.post(
                "/login",
                data={"txn": txn, "api_token": "bad", "email": "b@example.com"},
            )
            assert blocked.status_code == 429
            assert blocked.headers.get("retry-after") is not None


@pytest.mark.asyncio
async def test_failed_logins_throttled_per_email_success_does_not_count():
    app = _build_app(
        login_throttle_ip_max=0,
        login_throttle_email_max=2,
        login_throttle_window_seconds=300,
    )
    email = "victim@example.com"

    async def _login(client, *, token: str) -> httpx.Response:
        r = await client.post(
            "/register",
            json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
        )
        client_id = r.json()["client_id"]
        verifier, challenge = make_pkce()
        txn = await authorize_to_login(client, client_id, challenge, BASE_URL)
        return await client.post(
            "/login",
            data={"txn": txn, "api_token": token, "email": email},
        )

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            assert (await _login(client, token="bad")).status_code == 401
            assert (await _login(client, token=VALID_TOKEN)).status_code == 302
            assert (await _login(client, token="bad")).status_code == 401
            blocked = await _login(client, token="bad")
            assert blocked.status_code == 429


@pytest.mark.asyncio
async def test_login_throttle_disabled_when_limits_are_zero():
    app = _build_app(
        login_throttle_ip_max=0,
        login_throttle_email_max=0,
        login_throttle_window_seconds=300,
    )
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            for _ in range(5):
                r = await client.post(
                    "/register",
                    json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
                )
                assert r.status_code in (200, 201)


def test_negative_login_throttle_settings_are_refused():
    settings = Settings(
        base_url=BASE_URL,
        redis_url=require_redis_url(),
        login_throttle_ip_max=-1,
        login_throttle_email_max=10,
        login_throttle_window_seconds=300,
    )
    with pytest.raises(ConfigError, match="LOGIN_THROTTLE_IP_MAX"):
        validate_settings(settings)


def test_malformed_login_throttle_env_var_is_refused(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_THROTTLE_IP_MAX", "nope")
    with pytest.raises(ConfigError, match="LOGIN_THROTTLE_IP_MAX"):
        load_settings()


def _authorize_params(client_id: str, challenge: str) -> dict:
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": REDIRECT_URI,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": "test-state",
        "resource": BASE_URL,
    }


@pytest.mark.asyncio
async def test_authorize_returns_429_when_oauth_ip_limit_exceeded():
    app = _build_app(
        oauth_throttle_ip_max=2,
        login_throttle_ip_max=0,
        login_throttle_email_max=0,
        login_throttle_window_seconds=300,
    )
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            params = _authorize_params(client_id, challenge)
            r1 = await client.get("/authorize", params=params)
            assert r1.status_code in (302, 307)
            r2 = await client.get("/authorize", params=params)
            assert r2.status_code in (302, 307)
            blocked = await client.get("/authorize", params=params)
            assert blocked.status_code == 429
            assert blocked.headers.get("retry-after") is not None
            assert int(blocked.headers["retry-after"]) >= 1


@pytest.mark.asyncio
async def test_token_shares_the_oauth_endpoint_budget():
    app = _build_app(
        oauth_throttle_ip_max=2,
        login_throttle_ip_max=0,
        login_throttle_email_max=0,
        login_throttle_window_seconds=300,
    )
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            verifier, challenge = make_pkce()
            r1 = await client.get("/authorize", params=_authorize_params(client_id, challenge))
            assert r1.status_code in (302, 307)
            token_req = {
                "grant_type": "authorization_code",
                "code": "bogus-code",
                "redirect_uri": REDIRECT_URI,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": BASE_URL,
            }
            r2 = await client.post("/token", data=token_req)
            assert r2.status_code != 429
            blocked = await client.post("/token", data=token_req)
            assert blocked.status_code == 429
            assert blocked.headers.get("retry-after") is not None
            assert int(blocked.headers["retry-after"]) >= 1


@pytest.mark.asyncio
async def test_oauth_endpoint_limit_is_independent_from_login_limit():
    # Exhausting /authorize must not block POST /register. login_throttle_ip_max
    # is 2 here (register_client's own call, plus the probe below) so the
    # probe's outcome reflects only the /authorize exhaustion, not a
    # coincidental exhaustion of the separate /register budget.
    app_a = _build_app(
        oauth_throttle_ip_max=1,
        login_throttle_ip_max=2,
        login_throttle_email_max=0,
        login_throttle_window_seconds=300,
    )
    async with LifespanManager(app_a):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_a), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            params = _authorize_params(client_id, challenge)
            r1 = await client.get("/authorize", params=params)
            assert r1.status_code in (302, 307)
            blocked_authorize = await client.get("/authorize", params=params)
            assert blocked_authorize.status_code == 429

            still_allowed = await client.post(
                "/register",
                json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
            )
            assert still_allowed.status_code in (200, 201)

    # Exhausting POST /register must not block /authorize.
    app_b = _build_app(
        oauth_throttle_ip_max=1,
        login_throttle_ip_max=1,
        login_throttle_email_max=0,
        login_throttle_window_seconds=300,
    )
    async with LifespanManager(app_b):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_b), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            blocked_register = await client.post(
                "/register",
                json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
            )
            assert blocked_register.status_code == 429

            _verifier, challenge = make_pkce()
            still_allowed = await client.get(
                "/authorize", params=_authorize_params(client_id, challenge)
            )
            assert still_allowed.status_code in (302, 307)


@pytest.mark.asyncio
async def test_oauth_endpoint_throttle_disabled_when_zero():
    app = _build_app(
        oauth_throttle_ip_max=0,
        login_throttle_ip_max=0,
        login_throttle_email_max=0,
        login_throttle_window_seconds=300,
    )
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            for _ in range(10):
                _verifier, challenge = make_pkce()
                r = await client.get("/authorize", params=_authorize_params(client_id, challenge))
                assert r.status_code in (302, 307)


@pytest.mark.asyncio
async def test_register_ipv6_counted_per_64():
    app = _build_app(
        login_throttle_ip_max=2,
        login_throttle_email_max=0,
        login_throttle_window_seconds=300,
    )
    payload = {"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"}
    async with LifespanManager(app):
        transport_a = httpx.ASGITransport(app=app, client=("2001:db8::1", 12345))
        transport_b = httpx.ASGITransport(app=app, client=("2001:db8::2", 12345))
        transport_other = httpx.ASGITransport(app=app, client=("2001:db8:0:1::1", 12345))
        transport_v4 = httpx.ASGITransport(app=app, client=("192.0.2.1", 12345))
        transport_mapped = httpx.ASGITransport(app=app, client=("::ffff:192.0.2.1", 12345))
        async with httpx.AsyncClient(transport=transport_a, base_url=BASE_URL) as c1:
            assert (await c1.post("/register", json=payload)).status_code in (200, 201)
            assert (await c1.post("/register", json=payload)).status_code in (200, 201)
        async with httpx.AsyncClient(transport=transport_b, base_url=BASE_URL) as c2:
            blocked = await c2.post("/register", json=payload)
            assert blocked.status_code == 429
        async with httpx.AsyncClient(transport=transport_other, base_url=BASE_URL) as c3:
            assert (await c3.post("/register", json=payload)).status_code in (200, 201)
        async with httpx.AsyncClient(transport=transport_v4, base_url=BASE_URL) as c4:
            assert (await c4.post("/register", json=payload)).status_code in (200, 201)
        async with httpx.AsyncClient(transport=transport_mapped, base_url=BASE_URL) as c5:
            assert (await c5.post("/register", json=payload)).status_code in (200, 201)
            blocked = await c5.post("/register", json=payload)
            assert blocked.status_code == 429


def test_negative_oauth_throttle_setting_is_refused():
    settings = Settings(
        base_url=BASE_URL,
        redis_url=require_redis_url(),
        oauth_throttle_ip_max=-1,
    )
    with pytest.raises(ConfigError, match="OAUTH_THROTTLE_IP_MAX"):
        validate_settings(settings)


async def _failed_login(
    client: httpx.AsyncClient,
    *,
    email: str,
    token: str = "bad",
) -> httpx.Response:
    r = await client.post(
        "/register",
        json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
    )
    client_id = r.json()["client_id"]
    _verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, BASE_URL)
    return await client.post(
        "/login",
        data={"txn": txn, "api_token": token, "email": email},
    )


@pytest.mark.asyncio
async def test_failures_from_other_network_do_not_lock_person():
    app = _build_app(
        login_throttle_ip_max=0,
        login_throttle_email_max=10,
        login_throttle_window_seconds=300,
    )
    email = "alice@example.com"
    async with LifespanManager(app):
        transport_a = httpx.ASGITransport(app=app, client=("198.51.100.7", 12345))
        transport_b = httpx.ASGITransport(app=app, client=("203.0.113.9", 12345))
        async with httpx.AsyncClient(transport=transport_a, base_url=BASE_URL) as client_a:
            for _ in range(10):
                assert (await _failed_login(client_a, email=email)).status_code == 401
            blocked = await _failed_login(client_a, email=email)
            assert blocked.status_code == 429
        async with httpx.AsyncClient(transport=transport_b, base_url=BASE_URL) as client_b:
            ok = await _failed_login(client_b, email=email, token=VALID_TOKEN)
            assert ok.status_code == 302


@pytest.mark.asyncio
async def test_failures_ipv6_same_64_share_budget():
    app = _build_app(
        login_throttle_ip_max=0,
        login_throttle_email_max=2,
        login_throttle_window_seconds=300,
    )
    email = "ipv6@example.com"
    async with LifespanManager(app):
        transport_a = httpx.ASGITransport(app=app, client=("2001:db8::1", 12345))
        transport_b = httpx.ASGITransport(app=app, client=("2001:db8::2", 12345))
        async with httpx.AsyncClient(transport=transport_a, base_url=BASE_URL) as c1:
            assert (await _failed_login(c1, email=email)).status_code == 401
            assert (await _failed_login(c1, email=email)).status_code == 401
        async with httpx.AsyncClient(transport=transport_b, base_url=BASE_URL) as c2:
            blocked = await _failed_login(c2, email=email)
            assert blocked.status_code == 429


@pytest.mark.asyncio
async def test_email_failures_shared_across_replicas(redis_url: str):
    prefix = redis_key_prefix("login-fail-b07")
    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        redis_url=redis_url,
        redis_key_prefix=redis_key_prefix("oauth-b07"),
        login_pending_key_prefix=prefix,
        login_throttle_ip_max=0,
        login_throttle_email_max=10,
        login_throttle_window_seconds=300,
    )
    oauth_store, pending_store = build_shared_auth_stores(settings)
    login = dev_token_login({VALID_TOKEN})

    def _make_app():
        mcp, *_rest = build_server(
            login_providers=[login],
            settings=settings,
            oauth_store=oauth_store,
            login_pending_store=pending_store,
            register_builtin_catalog=False,
        )
        return mcp.http_app(path=settings.http_path)

    app_a = _make_app()
    app_b = _make_app()
    email = "replica@example.com"
    async with LifespanManager(app_a):
        async with LifespanManager(app_b):
            transport = httpx.ASGITransport(app=app_a, client=("198.51.100.50", 12345))
            async with httpx.AsyncClient(transport=transport, base_url=BASE_URL) as client:
                for _ in range(5):
                    assert (await _failed_login(client, email=email)).status_code == 401
            transport_b = httpx.ASGITransport(app=app_b, client=("198.51.100.50", 12345))
            async with httpx.AsyncClient(transport=transport_b, base_url=BASE_URL) as client_b:
                for _ in range(5):
                    assert (await _failed_login(client_b, email=email)).status_code == 401
                blocked = await _failed_login(client_b, email=email)
                assert blocked.status_code == 429
    await oauth_store.aclose()


@pytest.mark.asyncio
async def test_email_limiter_redis_down_allows(caplog: pytest.LogCaptureFixture):
    from keystone_mcp.auth.keystone_oauth_provider import KeystoneOAuthProvider
    from keystone_mcp.auth.login_pending_store import InMemoryLoginPendingStore

    failing_redis = AsyncMock()
    failing_redis.get.side_effect = RedisError("down")
    limiter = RedisLoginFailureLimiter(
        failing_redis,
        key_prefix="km:test:",
        max_failures=1,
        window_seconds=300,
    )
    settings = Settings(base_url=BASE_URL, login_throttle_email_max=1)
    store = InMemoryOAuthStore()
    pending = InMemoryLoginPendingStore()
    login = dev_token_login({VALID_TOKEN})
    KeystoneOAuthProvider(
        settings,
        store,
        pending,
        login_providers=[login],
        login_failure_limiter=limiter,
    )
    allowed, _retry = await limiter.check("a@example.com", "198.51.100.1")
    assert allowed
    assert sum(1 for r in caplog.records if "login failure limiter Redis error" in r.message) == 1


@pytest.mark.asyncio
async def test_email_key_has_no_plain_email(redis_url: str):
    prefix = redis_key_prefix("login-fail-keys")
    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        redis_url=redis_url,
        redis_key_prefix=redis_key_prefix("oauth-keys"),
        login_pending_key_prefix=prefix,
        login_throttle_ip_max=0,
        login_throttle_email_max=10,
        login_throttle_window_seconds=300,
    )
    oauth_store, pending_store = build_shared_auth_stores(settings)
    login = dev_token_login({VALID_TOKEN})
    mcp, *_rest = build_server(
        login_providers=[login],
        settings=settings,
        oauth_store=oauth_store,
        login_pending_store=pending_store,
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    email = "secret.person@example.com"
    async with LifespanManager(app):
        transport = httpx.ASGITransport(app=app, client=("198.51.100.88", 12345))
        async with httpx.AsyncClient(transport=transport, base_url=BASE_URL) as client:
            assert (await _failed_login(client, email=email)).status_code == 401
    sync = redis.from_url(require_redis_url(), decode_responses=True)
    try:
        keys = list(sync.scan_iter(match=f"{prefix}login_fail:*"))
        assert keys
        joined = " ".join(keys)
        assert email not in joined
        assert "secret.person" not in joined
    finally:
        sync.close()
    await oauth_store.aclose()
