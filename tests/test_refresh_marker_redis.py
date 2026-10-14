"""Refresh session markers on shared Redis stores."""

from __future__ import annotations

import json
import os
import time

import pytest
import pytest_asyncio
from mcp.server.auth.provider import AccessToken

from conftest import BASE_URL, refresh_access_token
from keystone_mcp.auth.keystone_oauth_provider import RefreshMeta, encode_refresh_meta
from keystone_mcp.auth.login_pending_store import RedisLoginPendingStore
from keystone_mcp.auth.oauth_store import (
    KeystoneRefreshToken,
    RedisOAuthStore,
    build_shared_auth_stores,
)
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from support.login import dev_token_login

pytestmark = pytest.mark.asyncio


def _redis_url() -> str:
    return os.environ.get("KEYSTONE_MCP_REDIS_URL", "").strip()


@pytest.fixture
def redis_url() -> str:
    url = _redis_url()
    if not url:
        pytest.skip("KEYSTONE_MCP_REDIS_URL not set")
    return url


@pytest_asyncio.fixture
async def redis_harness(redis_url: str):
    run_id = str(time.time_ns())
    settings = Settings(
        base_url=BASE_URL,
        redis_url=redis_url,
        redis_key_prefix=f"km:oauth:rm:{run_id}:",
        login_pending_key_prefix=f"km:login:rm:{run_id}:",
    )
    oauth_store, pending_store = build_shared_auth_stores(settings)
    assert isinstance(oauth_store, RedisOAuthStore)
    assert isinstance(pending_store, RedisLoginPendingStore)
    _login = dev_token_login({"valid-test-token"})
    mcp, _registry, oauth, *_rest = build_server(
        login_providers=[_login],
        settings=settings,
        oauth_store=oauth_store,
        login_pending_store=pending_store,
    )
    app = mcp.http_app(path=settings.http_path)
    import httpx
    from asgi_lifespan import LifespanManager

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            yield client, oauth, settings, oauth_store, pending_store
    await oauth_store.aclose()


async def test_marker_written_in_same_transaction(redis_url: str):
    run_id = str(time.time_ns())
    settings = Settings(
        redis_url=redis_url,
        redis_key_prefix=f"km:oauth:tx:{run_id}:",
        login_pending_key_prefix=f"km:login:tx:{run_id}:",
    )
    oauth_store, _pending = build_shared_auth_stores(settings)
    assert oauth_store.writes_refresh_meta

    tracked: list[str] = []
    original_put_refresh = oauth_store._pipe_put_refresh
    original_put_meta = oauth_store._pipe_put_refresh_meta

    def tracking_put_refresh(pipe, refresh):
        tracked.append(f"rt:{refresh.token}")
        original_put_refresh(pipe, refresh)

    def tracking_put_meta(pipe, token, payload, ttl):
        tracked.append(f"meta:{token}")
        original_put_meta(pipe, token, payload, ttl)

    oauth_store._pipe_put_refresh = tracking_put_refresh  # type: ignore[method-assign]
    oauth_store._pipe_put_refresh_meta = tracking_put_meta  # type: ignore[method-assign]

    now = int(time.time())
    refresh = KeystoneRefreshToken(
        token="km_rt_tx_test",
        client_id="c1",
        scopes=[],
        expires_at=now + 3600,
        subject="user@example.com",
        iat=now,
    )
    access = AccessToken(
        token="km_at_tx_test",
        client_id="c1",
        scopes=[],
        expires_at=now + 600,
        subject="user@example.com",
        claims={"email": "user@example.com", "subject_type": "human", "iat": now},
    )
    meta = encode_refresh_meta(
        RefreshMeta(
            auth_method="api_key",
            resource=None,
            interactive=False,
            auth_time=now,
            key_id=None,
            key_id_known=True,
            key_expires_at=None,
        )
    )
    await oauth_store.commit_token_pair(
        subject="user@example.com",
        consumed_iat=None,
        access=access,
        refresh=refresh,
        refresh_meta=meta,
    )
    assert f"rt:{refresh.token}" in tracked
    assert f"meta:{refresh.token}" in tracked
    await oauth_store.aclose()


@pytest.mark.parametrize(
    ("marker_payload", "auth_method"),
    [
        (
            '{"auth_method":"google","resource":"https://ks.example/mcp","interactive":true}',
            "google",
        ),
        ('{"auth_method":"google","resource":null}', "google"),
        ("api_key", "api_key"),
    ],
)
async def test_session_from_legacy_markers_refresh(
    redis_harness, marker_payload: str, auth_method: str
):
    client, oauth, settings, oauth_store, pending_store = redis_harness
    if auth_method == "google":
        oauth._providers["google"] = oauth._providers["api_key"]

    from mcp.shared.auth import OAuthClientInformationFull

    client_id = "legacy-client"
    client_record = OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=["http://localhost:9999/callback"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    await oauth_store.put_client(client_record)

    refresh_token = "km_rt_legacy_session"
    now = int(time.time())
    refresh_record = KeystoneRefreshToken(
        token=refresh_token,
        client_id=client_id,
        scopes=[],
        expires_at=now + 3600,
        subject="user@example.com",
    )
    await oauth_store.put_refresh_token(refresh_record)

    prefix = settings.login_pending_key_prefix
    if not prefix.endswith(":"):
        prefix = f"{prefix}:"
    meta_key = f"{prefix}refresh_auth:{refresh_token}"
    await oauth_store.redis.set(meta_key, marker_payload, ex=3600)

    refreshed = await refresh_access_token(client, client_id, refresh_token, settings.resource_url)
    assert refreshed["status"] == 200, refreshed

    new_refresh = refreshed["body"]["refresh_token"]
    new_raw = await pending_store.get("refresh_auth", new_refresh)
    assert new_raw is not None
    new_data = json.loads(new_raw)
    assert new_data["auth_method"] == auth_method
    assert "auth_time" not in new_data
    assert "key_id" not in new_data


async def test_missing_marker_is_invalid_grant(redis_harness):
    client, oauth, settings, oauth_store, pending_store = redis_harness
    from conftest import obtain_access_token

    res = await obtain_access_token(client, settings.resource_url)
    assert res["status"] == 200
    refresh_token = res["body"]["refresh_token"]
    client_id = res["client_id"]

    prefix = settings.login_pending_key_prefix
    if not prefix.endswith(":"):
        prefix = f"{prefix}:"
    await oauth_store.redis.delete(f"{prefix}refresh_auth:{refresh_token}")

    refreshed = await refresh_access_token(client, client_id, refresh_token, settings.resource_url)
    assert refreshed["status"] in (400, 401)
    assert refreshed["body"].get("error") == "invalid_grant"
    assert await oauth_store.get_refresh_token(refresh_token) is None
