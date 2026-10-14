"""RedisOAuthStore revocation and commit_token_pair paths (Redis only)."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from mcp.server.auth.provider import AccessToken, RefreshToken
from redis.exceptions import WatchError

from keystone_mcp.auth.oauth_store import (
    CredentialRevokedError,
    KeystoneRefreshToken,
    RedisOAuthStore,
    _subject_key,
)
from support.test_env import redis_key_prefix, require_redis_url


@pytest_asyncio.fixture
async def redis_oauth_store():
    prefix = redis_key_prefix("revoke")
    url = require_redis_url()
    store = RedisOAuthStore(
        url,
        key_prefix=prefix,
        client_ttl_seconds=3600,
        refresh_ttl_seconds=3600,
        access_ttl_seconds=600,
    )
    try:
        yield store
    finally:
        keys = [key async for key in store.redis.scan_iter(match=f"{prefix}*")]
        if keys:
            await store.redis.delete(*keys)
        await store.aclose()


def _access(
    token: str,
    client_id: str,
    subject: str,
    *,
    iat: int | None = None,
) -> AccessToken:
    now = int(time.time())
    iat_val = iat if iat is not None else now
    return AccessToken(
        token=token,
        client_id=client_id,
        scopes=[],
        expires_at=now + 3600,
        subject=subject,
        claims={"email": subject, "iat": iat_val},
    )


def _refresh(token: str, client_id: str, subject: str, *, iat: int | None = None) -> RefreshToken:
    now = int(time.time())
    return KeystoneRefreshToken(
        token=token,
        client_id=client_id,
        scopes=[],
        expires_at=now + 3600,
        subject=subject,
        iat=iat if iat is not None else now,
    )


async def test_revoke_client_tokens_removes_access_tokens_of_that_client(redis_oauth_store):
    store = redis_oauth_store
    subject = "user@example.com"
    await store.put_access_token(_access("at_a1", "client_a", subject))
    await store.put_access_token(_access("at_a2", "client_a", subject))
    await store.put_access_token(_access("at_b1", "client_b", subject))

    removed = await store.revoke_client_tokens(subject, "client_a")
    assert removed == 2
    assert await store.get_access_token("at_a1") is None
    assert await store.get_access_token("at_a2") is None
    assert await store.get_access_token("at_b1") is not None


async def test_revoke_refresh_grant_marks_and_deletes(redis_oauth_store):
    store = redis_oauth_store
    subject = "user@example.com"
    refresh_tok = "km_rt_revoke_me"
    await store.put_access_token(_access("at_same", "c1", subject))
    await store.put_access_token(_access("at_other", "c2", subject))
    await store.put_refresh_token(_refresh(refresh_tok, "c1", subject))

    await store.revoke_refresh_grant(subject, "c1", refresh_tok)

    assert await store.get_refresh_token(refresh_tok) is None
    assert await store.get_access_token("at_same") is None
    assert await store.get_access_token("at_other") is not None
    revoked_key = store._refresh_revoked_key(refresh_tok)
    assert await store.redis.exists(revoked_key) == 1


async def test_commit_token_pair_refuses_revoked_refresh(redis_oauth_store):
    store = redis_oauth_store
    subject = "user@example.com"
    old_rt = "km_rt_old"
    await store.put_refresh_token(_refresh(old_rt, "c1", subject))
    await store.redis.set(store._refresh_revoked_key(old_rt), "1", ex=3600)

    new_access = _access("at_new", "c1", subject)
    new_refresh = _refresh("km_rt_new", "c1", subject)
    with pytest.raises(CredentialRevokedError):
        await store.commit_token_pair(
            subject=subject,
            consumed_iat=int(time.time()),
            access=new_access,
            refresh=new_refresh,
            replace_refresh_token=old_rt,
        )


async def test_commit_token_pair_refuses_before_subject_nbf(redis_oauth_store):
    store = redis_oauth_store
    subject = "user@example.com"
    old_rt = "km_rt_nbf"
    now = int(time.time())
    await store.put_refresh_token(_refresh(old_rt, "c1", subject, iat=now))
    nbf_key = store._subject_nbf_key(_subject_key(subject))
    await store.redis.set(nbf_key, str(now + 100))

    new_access = _access("at_nbf", "c1", subject, iat=now)
    new_refresh = _refresh("km_rt_nbf_new", "c1", subject, iat=now)
    with pytest.raises(CredentialRevokedError):
        await store.commit_token_pair(
            subject=subject,
            consumed_iat=now,
            access=new_access,
            refresh=new_refresh,
            replace_refresh_token=old_rt,
        )


async def test_commit_token_pair_deletes_replaced_refresh(redis_oauth_store):
    store = redis_oauth_store
    subject = "user@example.com"
    old_rt = "km_rt_replace"
    now = int(time.time())
    await store.put_refresh_token(_refresh(old_rt, "c1", subject, iat=now))

    new_access = _access("at_rot", "c1", subject, iat=now)
    new_refresh = _refresh("km_rt_rotated", "c1", subject, iat=now)
    await store.commit_token_pair(
        subject=subject,
        consumed_iat=now,
        access=new_access,
        refresh=new_refresh,
        replace_refresh_token=old_rt,
    )
    assert await store.get_refresh_token(old_rt) is None
    assert await store.get_refresh_token("km_rt_rotated") is not None


async def test_commit_token_pair_gives_up_after_watch_retries(redis_oauth_store, monkeypatch):
    store = redis_oauth_store
    subject = "user@example.com"
    old_rt = "km_rt_watch"
    now = int(time.time())
    await store.put_refresh_token(_refresh(old_rt, "c1", subject, iat=now))

    class ContentionPipe:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def watch(self, *_keys):
            return None

        async def unwatch(self):
            return None

        def multi(self):
            return None

        def set(self, *_args, **_kwargs):
            return None

        def delete(self, *_args):
            return None

        def srem(self, *_args):
            return None

        def sadd(self, *_args):
            return None

        def expire(self, *_args):
            return None

        async def execute(self):
            raise WatchError("simulated contention")

    monkeypatch.setattr(store._redis, "pipeline", lambda *_a, **_k: ContentionPipe())
    monkeypatch.setattr(store._redis, "exists", AsyncMock(return_value=True))
    monkeypatch.setattr(store._redis, "get", AsyncMock(return_value=None))

    with pytest.raises(CredentialRevokedError):
        await store.commit_token_pair(
            subject=subject,
            consumed_iat=now,
            access=_access("at_w", "c1", subject, iat=now),
            refresh=_refresh("km_rt_w", "c1", subject, iat=now),
            replace_refresh_token=old_rt,
        )
