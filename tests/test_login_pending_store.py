"""Login pending store: TTL, atomic single-use consume, Redis integration."""

from __future__ import annotations

import asyncio
import logging
import os
import time

import pytest

from keystone_mcp.auth.login_pending_store import (
    InMemoryLoginPendingStore,
    RedisLoginPendingStore,
    build_login_pending_store,
)
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore, RedisOAuthStore

logger = logging.getLogger(__name__)


@pytest.fixture
def memory_store() -> InMemoryLoginPendingStore:
    return InMemoryLoginPendingStore()


async def test_put_get_and_consume(memory_store: InMemoryLoginPendingStore):
    await memory_store.put("txn", "key-1", "payload-a", 60)
    assert await memory_store.get("txn", "key-1") == "payload-a"
    consumed = await memory_store.consume("txn", "key-1")
    assert consumed == "payload-a"
    assert await memory_store.get("txn", "key-1") is None
    assert await memory_store.consume("txn", "key-1") is None


async def test_consume_is_single_use(memory_store: InMemoryLoginPendingStore):
    await memory_store.put("code", "c1", "secret-payload", 60)
    first = await memory_store.consume("code", "c1")
    second = await memory_store.consume("code", "c1")
    assert first == "secret-payload"
    assert second is None


async def test_ttl_expiry(memory_store: InMemoryLoginPendingStore):
    await memory_store.put("txn", "expiring", "gone", 1)
    assert await memory_store.get("txn", "expiring") == "gone"
    time.sleep(1.1)
    assert await memory_store.get("txn", "expiring") is None
    assert await memory_store.consume("txn", "expiring") is None


async def test_namespace_isolation(memory_store: InMemoryLoginPendingStore):
    await memory_store.put("txn", "shared-id", "txn-value", 60)
    await memory_store.put("code", "shared-id", "code-value", 60)
    assert await memory_store.get("txn", "shared-id") == "txn-value"
    assert await memory_store.get("code", "shared-id") == "code-value"
    assert await memory_store.consume("txn", "shared-id") == "txn-value"
    assert await memory_store.get("code", "shared-id") == "code-value"


async def test_build_without_redis_is_refused():
    """Silently falling back to memory broke logins behind more than one replica.

    A pending authorization code minted on one replica could be redeemed on
    another, and a restart dropped every login in flight — with no signal that
    Redis was missing.
    """
    with pytest.raises(RuntimeError, match="KEYSTONE_MCP_REDIS_URL"):
        build_login_pending_store(object())


async def test_build_without_redis_is_refused_even_with_an_oauth_store():
    oauth = InMemoryOAuthStore()
    with pytest.raises(RuntimeError, match="KEYSTONE_MCP_REDIS_URL"):
        build_login_pending_store(object(), oauth_store=oauth)


async def test_in_memory_store_remains_available_for_tests():
    """The class stays; only the production factory refuses to choose it."""
    store = InMemoryLoginPendingStore()
    await store.put("txn", "k", "v", 60)
    assert await store.consume("txn", "k") == "v"


async def test_build_shares_the_oauth_store_redis_pool():
    class _WithRedis:
        redis = object()

    class _Settings:
        redis_url = "redis://localhost:6379/0"
        login_pending_key_prefix = "km:login:"

    store = build_login_pending_store(_Settings(), oauth_store=_WithRedis())
    assert isinstance(store, RedisLoginPendingStore)
    assert store.redis is _WithRedis.redis
    assert store._owns_redis is False


async def test_no_secrets_in_logs(memory_store: InMemoryLoginPendingStore, caplog):
    secret = "km_code_super_secret_value"
    with caplog.at_level(logging.DEBUG):
        await memory_store.put("code", "k", secret, 60)
        await memory_store.get("code", "k")
        await memory_store.consume("code", "k")
    for record in caplog.records:
        assert secret not in record.getMessage()


@pytest.fixture
async def redis_store():
    redis_url = os.environ.get("KEYSTONE_MCP_REDIS_URL", "").strip()
    if not redis_url:
        pytest.skip("KEYSTONE_MCP_REDIS_URL not set")
    prefix = "km:login:test:"
    oauth = RedisOAuthStore(redis_url, key_prefix="km:oauth:test:")
    store = RedisLoginPendingStore(oauth.redis, key_prefix=prefix, owns_redis=False)
    yield store, prefix
    await oauth.aclose()


async def test_redis_atomic_consume_single_winner(redis_store):
    store, prefix = redis_store
    key = f"race-{time.time()}"
    await store.put("code", key, "winner-payload", 30)

    results = await asyncio.gather(
        store.consume("code", key),
        store.consume("code", key),
        store.consume("code", key),
    )
    winners = [r for r in results if r is not None]
    assert len(winners) == 1
    assert winners[0] == "winner-payload"


async def test_redis_ttl_expiry(redis_store):
    store, _prefix = redis_store
    key = f"ttl-{time.time()}"
    await store.put("txn", key, "ttl-payload", 1)
    assert await store.get("txn", key) == "ttl-payload"
    time.sleep(1.1)
    assert await store.get("txn", key) is None


async def test_redis_roundtrip(redis_store):
    store, _prefix = redis_store
    key = f"rt-{time.time()}"
    await store.put("txn", key, '{"client":"abc"}', 30)
    assert await store.get("txn", key) == '{"client":"abc"}'
    assert await store.consume("txn", key) == '{"client":"abc"}'
