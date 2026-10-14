"""Redis-backed RBAC policy revision store."""

from __future__ import annotations

from uuid import uuid4

import pytest
from redis.asyncio import Redis

from keystone_mcp.rbac.policy_revision import RedisPolicyRevisionStore
from keystone_mcp.redis_client import redis_from_url
from support.test_env import require_redis_url


@pytest.fixture
async def redis_client():
    client = redis_from_url(require_redis_url())
    yield client
    await client.aclose()


@pytest.fixture
def revision_key() -> str:
    return f"km:test:policy-rev:{uuid4().hex}"


@pytest.mark.asyncio
async def test_redis_revision_store_roundtrip(
    redis_client: Redis,
    revision_key: str,
) -> None:
    store = RedisPolicyRevisionStore(redis_client, key=revision_key)
    first = await store.publish("hash-one")
    second = await store.publish("hash-two")
    assert first.revision == 1
    assert second.revision == 2
    assert second.content_hash == "hash-two"
    read_back = await store.read()
    assert read_back == second


@pytest.mark.asyncio
async def test_redis_publish_is_atomic(
    redis_client: Redis,
    revision_key: str,
) -> None:
    store = RedisPolicyRevisionStore(redis_client, key=revision_key)
    published = await store.publish("hash-atomic")
    raw = await redis_client.hgetall(revision_key)
    decoded = {
        (k.decode() if isinstance(k, bytes) else str(k)): (
            v.decode() if isinstance(v, bytes) else str(v)
        )
        for k, v in raw.items()
    }
    assert decoded.get("revision") == str(published.revision)
    assert decoded.get("content_hash") == "hash-atomic"
    assert decoded.get("updated_at")
