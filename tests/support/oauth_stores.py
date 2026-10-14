"""Parametric OAuth store backends (memory and Redis) for rotation tests."""

from __future__ import annotations

import pytest_asyncio
from redis.asyncio import Redis

from keystone_mcp.auth.login_pending_store import (
    InMemoryLoginPendingStore,
    RedisLoginPendingStore,
    normalize_login_key_prefix,
)
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore, RedisOAuthStore, client_ttl_seconds
from keystone_mcp.config import Settings
from support.test_env import redis_key_prefix, require_redis_url


@pytest_asyncio.fixture(params=["memory", "redis"])
async def oauth_store_backend(request):
    settings = Settings()
    if request.param == "memory":
        store = InMemoryOAuthStore(
            client_ttl_seconds=client_ttl_seconds(settings),
            refresh_ttl_seconds=settings.refresh_token_ttl_seconds,
            access_ttl_seconds=settings.token_cache_ttl_seconds,
        )
        pending = InMemoryLoginPendingStore()
        yield store, pending, settings, request.param
        return

    url = require_redis_url()
    oauth_prefix = redis_key_prefix("oauth")
    login_prefix = redis_key_prefix("login")
    redis = Redis.from_url(url, decode_responses=True)
    store = RedisOAuthStore(
        url,
        key_prefix=oauth_prefix,
        redis=redis,
        owns_redis=False,
        client_ttl_seconds=client_ttl_seconds(settings),
        refresh_ttl_seconds=settings.refresh_token_ttl_seconds,
        access_ttl_seconds=settings.token_cache_ttl_seconds,
        refresh_meta_key_prefix=f"{normalize_login_key_prefix(login_prefix)}refresh_auth:",
    )
    pending = RedisLoginPendingStore(redis, key_prefix=login_prefix, owns_redis=False)
    yield store, pending, settings, request.param
    for prefix in (oauth_prefix, login_prefix):
        keys = [k async for k in redis.scan_iter(match=f"{prefix}*")]
        if keys:
            await redis.delete(*keys)
    await redis.aclose()
