"""DCR TTL, eviction, and cap behaviour on Redis."""

from __future__ import annotations

import os
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from mcp.shared.auth import OAuthClientInformationFull
from prometheus_client import REGISTRY

from keystone_mcp.auth.oauth_store import (
    UNUSED_CLIENT_TTL_SECONDS,
    RedisOAuthStore,
    build_shared_auth_stores,
)
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from support.login import dev_token_login
from support.oauth_harness import BASE_URL, REDIRECT_URI, VALID_TOKEN, authorize_to_login, make_pkce

_REGISTER_PAYLOAD = {"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"}


def _redis_url() -> str:
    return os.environ.get("KEYSTONE_MCP_REDIS_URL", "").strip()


@pytest.fixture
def redis_url() -> str:
    url = _redis_url()
    if not url:
        pytest.skip("KEYSTONE_MCP_REDIS_URL not set")
    return url


def _evictions() -> float:
    return REGISTRY.get_sample_value("keystone_mcp_oauth_client_evictions_total") or 0.0


@pytest_asyncio.fixture
async def redis_harness(redis_url: str):
    run_id = str(time.time_ns())
    settings = Settings(
        base_url=BASE_URL,
        redis_url=redis_url,
        redis_key_prefix=f"km:oauth:b05:{run_id}:",
        login_pending_key_prefix=f"km:login:b05:{run_id}:",
        refresh_interval_seconds=0,
    )
    oauth_store, pending_store = build_shared_auth_stores(settings)
    assert isinstance(oauth_store, RedisOAuthStore)
    mcp, *_rest = build_server(
        login_providers=[dev_token_login({VALID_TOKEN})],
        settings=settings,
        oauth_store=oauth_store,
        login_pending_store=pending_store,
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            yield client, oauth_store, settings
    await oauth_store.aclose()


async def test_unused_client_ttl_is_one_day(redis_harness) -> None:
    client, store, _settings = redis_harness
    r = await client.post("/register", json=_REGISTER_PAYLOAD)
    assert r.status_code == 201, r.text
    client_id = r.json()["client_id"]
    ttl = await store.redis.ttl(store._client_key(client_id))
    assert 0 < ttl <= UNUSED_CLIENT_TTL_SECONDS
    assert await store.redis.zscore(store._client_unused_key(), client_id) is not None

    verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, BASE_URL)
    login = await client.post(
        "/login",
        data={"txn": txn, "api_token": VALID_TOKEN, "email": "user@example.com"},
    )
    assert login.status_code == 302, login.text
    code = parse_qs(urlparse(login.headers["location"]).query)["code"][0]
    token = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": BASE_URL,
        },
    )
    assert token.status_code == 200, token.text

    ttl_after = await store.redis.ttl(store._client_key(client_id))
    assert ttl_after > UNUSED_CLIENT_TTL_SECONDS
    assert await store.redis.zscore(store._client_unused_key(), client_id) is None


async def test_cap_evicts_oldest_unused_client(redis_harness) -> None:
    _client, _store, harness_settings = redis_harness
    run_id = str(time.time_ns())
    settings = Settings(
        base_url=BASE_URL,
        redis_url=harness_settings.redis_url,
        redis_key_prefix=f"km:oauth:b05cap:{run_id}:",
        login_pending_key_prefix=f"km:login:b05cap:{run_id}:",
        refresh_interval_seconds=0,
        oauth_max_clients=3,
        metrics_enabled=True,
    )
    oauth_store, pending_store = build_shared_auth_stores(settings)
    assert isinstance(oauth_store, RedisOAuthStore)
    mcp, *_rest = build_server(
        login_providers=[dev_token_login({VALID_TOKEN})],
        settings=settings,
        oauth_store=oauth_store,
        login_pending_store=pending_store,
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    before = _evictions()
    first_id = None
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as http:
            for _ in range(3):
                r = await http.post("/register", json=_REGISTER_PAYLOAD)
                assert r.status_code == 201, r.text
                if first_id is None:
                    first_id = r.json()["client_id"]
            fourth = await http.post("/register", json=_REGISTER_PAYLOAD)
            assert fourth.status_code == 201, fourth.text
    assert first_id is not None
    assert await oauth_store.get_client(first_id) is None
    assert _evictions() == before + 1
    await oauth_store.aclose()


async def test_cap_without_unused_clients_refuses(redis_harness) -> None:
    client, store, settings = redis_harness
    run_id = str(time.time_ns())
    settings = Settings(
        base_url=BASE_URL,
        redis_url=settings.redis_url,
        redis_key_prefix=f"km:oauth:b05full:{run_id}:",
        login_pending_key_prefix=f"km:login:b05full:{run_id}:",
        refresh_interval_seconds=0,
        oauth_max_clients=3,
    )
    oauth_store, pending_store = build_shared_auth_stores(settings)
    mcp, *_rest = build_server(
        login_providers=[dev_token_login({VALID_TOKEN})],
        settings=settings,
        oauth_store=oauth_store,
        login_pending_store=pending_store,
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as http:
            client_ids: list[str] = []
            for _ in range(3):
                r = await http.post("/register", json=_REGISTER_PAYLOAD)
                assert r.status_code == 201, r.text
                client_ids.append(r.json()["client_id"])
            for cid in client_ids:
                verifier, challenge = make_pkce()
                txn = await authorize_to_login(http, cid, challenge, BASE_URL)
                login = await http.post(
                    "/login",
                    data={"txn": txn, "api_token": VALID_TOKEN, "email": "u@example.com"},
                )
                assert login.status_code == 302
                code = parse_qs(urlparse(login.headers["location"]).query)["code"][0]
                tok = await http.post(
                    "/token",
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": REDIRECT_URI,
                        "client_id": cid,
                        "code_verifier": verifier,
                        "resource": BASE_URL,
                    },
                )
                assert tok.status_code == 200
            blocked = await http.post("/register", json=_REGISTER_PAYLOAD)
            assert blocked.status_code == 400
            assert blocked.json()["error"] == "invalid_client_metadata"
            assert "limit" in blocked.json()["error_description"].lower()
    await oauth_store.aclose()


@pytest.mark.integration
async def test_ten_thousand_unused_clients_do_not_block_registration(redis_harness) -> None:
    _client, store, settings = redis_harness
    run_id = str(time.time_ns())
    settings = Settings(
        base_url=BASE_URL,
        redis_url=settings.redis_url,
        redis_key_prefix=f"km:oauth:b0510k:{run_id}:",
        login_pending_key_prefix=f"km:login:b0510k:{run_id}:",
        refresh_interval_seconds=0,
        oauth_max_clients=10000,
    )
    oauth_store, pending_store = build_shared_auth_stores(settings)
    assert isinstance(oauth_store, RedisOAuthStore)
    now = int(time.time())
    pipe = oauth_store.redis.pipeline(transaction=False)
    for i in range(10000):
        cid = f"seed-{i}"
        pipe.set(
            oauth_store._client_key(cid),
            OAuthClientInformationFull(
                client_id=cid,
                redirect_uris=[REDIRECT_URI],  # type: ignore[list-item]
                token_endpoint_auth_method="none",
            ).model_dump_json(),
            ex=UNUSED_CLIENT_TTL_SECONDS,
        )
        pipe.zadd(oauth_store._client_index_key(), {cid: now + UNUSED_CLIENT_TTL_SECONDS})
        pipe.zadd(oauth_store._client_unused_key(), {cid: now})
    await pipe.execute()

    mcp, *_rest = build_server(
        login_providers=[dev_token_login({VALID_TOKEN})],
        settings=settings,
        oauth_store=oauth_store,
        login_pending_store=pending_store,
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as http:
            r = await http.post("/register", json=_REGISTER_PAYLOAD)
            assert r.status_code == 201, r.text
    await oauth_store.aclose()
