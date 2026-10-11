"""InMemoryOAuthStore TTL semantics, mirroring RedisOAuthStore (no Redis needed)."""

from __future__ import annotations

import time

from mcp.server.auth.provider import RefreshToken
from mcp.shared.auth import OAuthClientInformationFull

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore


def _client(client_id: str) -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=["http://localhost:9999/callback"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )


async def test_client_expires_after_ttl(monkeypatch):
    store = InMemoryOAuthStore(client_ttl_seconds=100, refresh_ttl_seconds=100)
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    await store.put_client(_client("c1"))
    assert await store.get_client("c1") is not None

    monkeypatch.setattr(time, "time", lambda: now + 101)
    assert await store.get_client("c1") is None


async def test_touch_client_renews_ttl(monkeypatch):
    store = InMemoryOAuthStore(client_ttl_seconds=100, refresh_ttl_seconds=100)
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    await store.put_client(_client("c1"))

    monkeypatch.setattr(time, "time", lambda: now + 90)
    await store.touch_client("c1")

    monkeypatch.setattr(time, "time", lambda: now + 150)
    assert await store.get_client("c1") is not None


async def test_touch_client_on_missing_client_is_a_noop():
    store = InMemoryOAuthStore()
    await store.touch_client("does-not-exist")  # must not raise
    assert await store.get_client("does-not-exist") is None


async def test_refresh_token_ttl_follows_expires_at(monkeypatch):
    store = InMemoryOAuthStore()
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    refresh = RefreshToken(
        token="rt1",
        client_id="c1",
        scopes=[],
        expires_at=int(now) + 50,
        subject="u@example.com",
    )
    await store.put_refresh_token(refresh)
    assert await store.get_refresh_token("rt1") is not None

    monkeypatch.setattr(time, "time", lambda: now + 51)
    assert await store.get_refresh_token("rt1") is None


async def test_refresh_token_without_expires_at_gets_default_ttl(monkeypatch):
    store = InMemoryOAuthStore(refresh_ttl_seconds=100)
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    refresh = RefreshToken(
        token="rt2",
        client_id="c1",
        scopes=[],
        expires_at=None,
        subject="u@example.com",
    )
    await store.put_refresh_token(refresh)
    assert await store.get_refresh_token("rt2") is not None

    monkeypatch.setattr(time, "time", lambda: now + 101)
    assert await store.get_refresh_token("rt2") is None
