"""Login and dynamic client registration rate limits (429 + Retry-After)."""

from __future__ import annotations

import httpx
import pytest
from asgi_lifespan import LifespanManager

from conftest import (
    BASE_URL,
    REDIRECT_URI,
    VALID_TOKEN,
    authorize_to_login,
    make_pkce,
    register_client,
)
from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import ConfigError, Settings, load_settings, validate_settings
from keystone_mcp.server import build_server


def _build_app(**settings_overrides):
    settings = Settings(base_url=BASE_URL, refresh_interval_seconds=0, **settings_overrides)
    idp = StaticIdentityProvider({VALID_TOKEN})
    store = InMemoryOAuthStore()
    mcp, *_rest = build_server(
        identity_provider=idp,
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


def test_negative_oauth_throttle_setting_is_refused():
    settings = Settings(
        base_url=BASE_URL,
        oauth_throttle_ip_max=-1,
    )
    with pytest.raises(ConfigError, match="OAUTH_THROTTLE_IP_MAX"):
        validate_settings(settings)
