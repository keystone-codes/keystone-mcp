"""OAuth flow integration against shared Redis stores (production wiring)."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest_asyncio
from asgi_lifespan import LifespanManager

from keystone_mcp.auth.login_pending_store import RedisLoginPendingStore
from keystone_mcp.auth.oauth_store import RedisOAuthStore, build_shared_auth_stores
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from support.login import dev_token_login
from support.oauth_harness import (
    BASE_URL,
    REDIRECT_URI,
    VALID_TOKEN,
    authorize_to_login,
    make_pkce,
    obtain_access_token,
    register_client,
)
from support.test_env import redis_key_prefix


@pytest_asyncio.fixture
async def redis_harness(redis_url: str):
    """ASGI harness wired through build_shared_auth_stores (production path)."""
    settings = Settings(
        base_url=BASE_URL,
        redis_url=redis_url,
        redis_key_prefix=redis_key_prefix("itest"),
        login_pending_key_prefix=redis_key_prefix("login"),
    )
    oauth_store, pending_store = build_shared_auth_stores(settings)
    assert isinstance(oauth_store, RedisOAuthStore)
    assert isinstance(pending_store, RedisLoginPendingStore)
    assert oauth_store.redis is pending_store.redis

    _login = dev_token_login({VALID_TOKEN})
    mcp, registry, oauth, _upstreams, _policy_manager, _observability, _reconciler = build_server(
        login_providers=[_login],
        settings=settings,
        oauth_store=oauth_store,
        login_pending_store=pending_store,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            yield client, oauth, settings, oauth_store
    await oauth_store.aclose()


async def test_build_shared_auth_stores_uses_same_redis_pool(redis_url: str):
    settings = Settings(
        redis_url=redis_url,
        redis_key_prefix=redis_key_prefix("pool"),
        login_pending_key_prefix=redis_key_prefix("login-pool"),
    )
    oauth_store, pending_store = build_shared_auth_stores(settings)
    assert isinstance(oauth_store, RedisOAuthStore)
    assert isinstance(pending_store, RedisLoginPendingStore)
    assert oauth_store.redis is pending_store.redis
    await oauth_store.aclose()


async def test_full_oauth_flow_via_shared_redis_stores(redis_harness):
    client, oauth, settings, _oauth_store = redis_harness
    res = await obtain_access_token(client, settings.resource_url)
    assert res["status"] == 200
    assert res["body"].get("access_token")
    assert res["body"].get("refresh_token")
    verified = await oauth.verify_token(res["body"]["access_token"])
    assert verified is not None
    assert verified.subject == "user@example.com"


async def test_authorization_code_single_use_via_shared_redis(redis_harness):
    client, _oauth, settings, _oauth_store = redis_harness
    client_id = await register_client(client)
    verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    login = await client.post(
        "/login",
        data={"txn": txn, "api_token": VALID_TOKEN, "email": "u@example.com"},
    )
    assert login.status_code == 302
    code = parse_qs(urlparse(login.headers["location"]).query)["code"][0]
    token_req = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
        "code_verifier": verifier,
        "resource": settings.resource_url,
    }
    first = await client.post("/token", data=token_req)
    second = await client.post("/token", data=token_req)
    assert first.status_code == 200
    assert second.status_code != 200


async def test_corrupt_pending_txn_treated_as_missing(redis_harness):
    client, oauth, settings, _oauth_store = redis_harness
    client_id = await register_client(client)
    _verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    await oauth._pending_store.put("txn", txn, "not-valid-json-envelope", 60)
    assert await oauth._get_pending_txn(txn) is None
    r = await client.get(f"/login?txn={txn}")
    assert r.status_code == 400


async def test_corrupt_auth_code_treated_as_missing(redis_harness):
    _client, oauth, _settings, _oauth_store = redis_harness
    code_str = "km_code_corrupt_test"
    await oauth._pending_store.put("code", code_str, "{bad", 60)
    assert await oauth._get_auth_code(code_str) is None
