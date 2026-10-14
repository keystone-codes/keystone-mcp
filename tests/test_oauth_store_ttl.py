"""RedisOAuthStore TTL behaviour against real Redis.

Skipped when KEYSTONE_MCP_REDIS_URL is not set, matching
tests/test_oauth_redis_integration.py. Each test uses a unique key prefix and
cleans up its own keys in a finally block.
"""

from __future__ import annotations

import time

import pytest_asyncio
from mcp.server.auth.provider import RefreshToken
from mcp.shared.auth import OAuthClientInformationFull
from redis.exceptions import RedisError

from keystone_mcp.auth.oauth_store import RedisOAuthStore, token_digest
from support.test_env import redis_key_prefix


@pytest_asyncio.fixture
async def store(redis_url: str):
    prefix = redis_key_prefix("ttltest")
    instance = RedisOAuthStore(
        redis_url,
        key_prefix=prefix,
        client_ttl_seconds=5000,
        refresh_ttl_seconds=3000,
    )
    try:
        yield instance
    finally:
        keys = [key async for key in instance.redis.scan_iter(match=f"{prefix}*")]
        if keys:
            await instance.redis.delete(*keys)
        await instance.aclose()


def _client(client_id: str) -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=["http://localhost:9999/callback"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )


async def test_put_client_sets_ttl(store: RedisOAuthStore):
    await store.put_client(_client("c1"))
    ttl = await store.redis.ttl(store._client_key("c1"))
    assert abs(ttl - 5000) < 10


async def test_touch_client_renews_ttl(store: RedisOAuthStore):
    await store.put_client(_client("c2"))
    key = store._client_key("c2")
    await store.redis.expire(key, 10)

    await store.touch_client("c2")

    ttl = await store.redis.ttl(key)
    assert ttl > 100


async def test_touch_client_on_missing_client_is_a_noop(store: RedisOAuthStore):
    # Must not raise and must not create the key.
    await store.touch_client("does-not-exist")
    assert await store.redis.exists(store._client_key("does-not-exist")) == 0


async def test_put_refresh_token_ttl_follows_expires_at(store: RedisOAuthStore):
    expires_at = int(time.time()) + 1000
    refresh = RefreshToken(
        token="rt1",
        client_id="c1",
        scopes=[],
        expires_at=expires_at,
        subject="u@example.com",
    )
    await store.put_refresh_token(refresh)
    ttl = await store.redis.ttl(store._refresh_key(token_digest("rt1")))
    assert abs(ttl - 1000) < 10


async def test_legacy_client_without_ttl_gets_ttl_on_read(store: RedisOAuthStore):
    client = _client("c3")
    key = store._client_key("c3")
    await store.redis.set(key, client.model_dump_json())  # legacy write: no EX
    assert await store.redis.ttl(key) == -1

    loaded = await store.get_client("c3")

    assert loaded is not None
    assert await store.redis.ttl(key) > 0


async def test_legacy_refresh_token_without_ttl_gets_expireat_on_read(store: RedisOAuthStore):
    expires_at = int(time.time()) + 500
    refresh = RefreshToken(
        token="rt2",
        client_id="c1",
        scopes=[],
        expires_at=expires_at,
        subject="u@example.com",
    )
    key = store._refresh_key("rt2")
    await store.redis.set(key, refresh.model_dump_json())  # legacy write: no EX
    assert await store.redis.ttl(key) == -1

    loaded = await store.get_refresh_token("rt2")

    assert loaded is not None
    migrated_key = store._refresh_key(token_digest("rt2"))
    ttl = await store.redis.ttl(migrated_key)
    assert 0 < ttl <= 500


async def test_legacy_refresh_token_past_expiry_is_deleted_on_read(store: RedisOAuthStore):
    expires_at = int(time.time()) - 10
    refresh = RefreshToken(
        token="rt3",
        client_id="c1",
        scopes=[],
        expires_at=expires_at,
        subject="u@example.com",
    )
    key = store._refresh_key("rt3")
    await store.redis.set(key, refresh.model_dump_json())  # legacy write: no EX

    loaded = await store.get_refresh_token("rt3")

    assert loaded is None
    assert await store.redis.exists(key) == 0
    assert await store.redis.exists(store._refresh_key(token_digest("rt3"))) == 0


async def test_legacy_refresh_token_without_expires_at_gets_default_ttl(store: RedisOAuthStore):
    refresh = RefreshToken(
        token="rt4",
        client_id="c1",
        scopes=[],
        expires_at=None,
        subject="u@example.com",
    )
    key = store._refresh_key("rt4")
    await store.redis.set(key, refresh.model_dump_json())  # legacy write: no EX

    loaded = await store.get_refresh_token("rt4")

    assert loaded is not None
    migrated_key = store._refresh_key(token_digest("rt4"))
    ttl = await store.redis.ttl(migrated_key)
    assert abs(ttl - 3000) < 10


async def test_client_index_tracks_put_and_touch(store: RedisOAuthStore):
    index_key = store._client_index_key()
    await store.put_client(_client("c5"))

    assert await store.redis.zscore(index_key, "c5") is not None
    assert await store.count_clients() == 1

    # touch_client renews the index entry (and the client's own TTL) together.
    original_score = await store.redis.zscore(index_key, "c5")
    await store.touch_client("c5")
    renewed_score = await store.redis.zscore(index_key, "c5")
    assert renewed_score >= original_score


async def test_count_clients_drops_expired_entries(store: RedisOAuthStore):
    index_key = store._client_index_key()
    await store.put_client(_client("c6"))
    # Simulate an entry whose expiry has already passed, without waiting out
    # a real TTL: rewrite its index score into the past. The client key
    # itself is left alone; count_clients() must rely on the index, not on
    # re-reading every client record.
    await store.redis.zadd(index_key, {"c6": time.time() - 10})

    assert await store.count_clients() == 0
    assert await store.redis.zscore(index_key, "c6") is None


async def test_legacy_clients_are_counted_after_backfill(store: RedisOAuthStore):
    for legacy_id in ("leg-a", "leg-b", "leg-c"):
        key = store._client_key(legacy_id)
        await store.redis.set(key, _client(legacy_id).model_dump_json())
    await store.put_client(_client("new-d"))

    assert await store.count_clients() == 4
    for legacy_id in ("leg-a", "leg-b", "leg-c"):
        assert await store.redis.ttl(store._client_key(legacy_id)) > 0

    original_index = store.index_legacy_clients
    calls = 0

    async def counting_index() -> int:
        nonlocal calls
        calls += 1
        return await original_index()

    store.index_legacy_clients = counting_index  # type: ignore[method-assign]
    assert await store.count_clients() == 4
    assert calls == 0


async def test_legacy_backfill_does_not_mark_clients_unused(store: RedisOAuthStore):
    legacy_id = "leg-unused"
    await store.redis.set(store._client_key(legacy_id), _client(legacy_id).model_dump_json())
    await store.count_clients()
    assert await store.redis.zscore(store._client_unused_key(), legacy_id) is None


async def test_backfill_failure_does_not_break_counting(store: RedisOAuthStore, caplog):
    await store.put_client(_client("indexed-only"))
    assert await store.count_clients() == 1

    async def failing_index() -> int:
        raise RedisError("scan failed")

    store.index_legacy_clients = failing_index  # type: ignore[method-assign]
    store._legacy_clients_indexed = False

    with caplog.at_level("WARNING"):
        assert await store.count_clients() == 1
    assert any("backfill" in r.message.lower() for r in caplog.records)

    calls = 0

    async def succeed_index() -> int:
        nonlocal calls
        calls += 1
        return 0

    store.index_legacy_clients = succeed_index  # type: ignore[method-assign]
    store._legacy_clients_indexed = False
    await store.count_clients()
    assert calls == 1


async def test_legacy_client_is_added_to_index_on_read(store: RedisOAuthStore):
    client = _client("c7")
    key = store._client_key("c7")
    await store.redis.set(key, client.model_dump_json())  # legacy write: no EX, no index entry
    index_key = store._client_index_key()
    assert await store.redis.zscore(index_key, "c7") is None

    loaded = await store.get_client("c7")

    assert loaded is not None
    assert await store.redis.zscore(index_key, "c7") is not None
    assert await store.count_clients() == 1
