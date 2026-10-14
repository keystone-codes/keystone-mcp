"""OAuth subject index and not-before revocation (Redis + in-memory)."""

from __future__ import annotations

import time
import uuid

import pytest
import pytest_asyncio
from mcp.server.auth.provider import AccessToken, RefreshToken

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore, RedisOAuthStore
from support.test_env import redis_key_prefix, require_redis_url


@pytest_asyncio.fixture(params=["memory", "redis"])
async def oauth_store(request):
    if request.param == "memory":
        store = InMemoryOAuthStore(
            client_ttl_seconds=5000,
            refresh_ttl_seconds=3000,
            access_ttl_seconds=3600,
        )
        yield store
        return
    url = require_redis_url()
    prefix = redis_key_prefix("subj")
    store = RedisOAuthStore(
        url,
        key_prefix=prefix,
        client_ttl_seconds=5000,
        refresh_ttl_seconds=3000,
        access_ttl_seconds=3600,
    )
    try:
        yield store
    finally:
        keys = [key async for key in store.redis.scan_iter(match=f"{prefix}*")]
        if keys:
            await store.redis.delete(*keys)
        await store.aclose()


async def _put_pair(store, *, email: str = "user@example.com") -> tuple[str, str]:
    now = int(time.time())
    at = f"km_at_{uuid.uuid4().hex}"
    rt = f"km_rt_{uuid.uuid4().hex}"
    await store.put_access_token(
        AccessToken(
            token=at,
            client_id="c1",
            scopes=[],
            expires_at=now + 3600,
            subject=email,
            claims={"email": email, "iat": now},
        )
    )
    await store.put_refresh_token(
        RefreshToken(
            token=rt,
            client_id="c1",
            scopes=[],
            expires_at=now + 3000,
            subject=email,
        )
    )
    return at, rt


async def test_put_tokens_adds_to_subject_index(oauth_store):
    at, rt = await _put_pair(oauth_store)
    if isinstance(oauth_store, RedisOAuthStore):
        members = await oauth_store.redis.smembers(
            oauth_store._subject_index_key("user@example.com")
        )
        ttl = await oauth_store.redis.ttl(oauth_store._subject_index_key("user@example.com"))
        assert f"at:{at}" in members
        assert f"rt:{rt}" in members
        assert abs(ttl - 5000) < 15
    else:
        members = oauth_store._subject_index.get("user@example.com", set())
        assert f"at:{at}" in members
        assert f"rt:{rt}" in members


async def test_delete_token_removes_from_index(oauth_store):
    at, rt = await _put_pair(oauth_store)
    await oauth_store.delete_access_token(at)
    if isinstance(oauth_store, RedisOAuthStore):
        members = await oauth_store.redis.smembers(
            oauth_store._subject_index_key("user@example.com")
        )
        assert f"at:{at}" not in members
        assert f"rt:{rt}" in members
    else:
        members = oauth_store._subject_index.get("user@example.com", set())
        assert f"at:{at}" not in members


async def test_revoke_subject_deletes_all_tokens_and_index(oauth_store):
    at, rt = await _put_pair(oauth_store)
    now = int(time.time())
    revoked = await oauth_store.revoke_subject("user@example.com", now=now)
    assert revoked.access == 1
    assert rt in revoked.refresh_tokens
    assert await oauth_store.get_access_token(at) is None
    assert await oauth_store.get_refresh_token(rt) is None
    if isinstance(oauth_store, RedisOAuthStore):
        assert (
            await oauth_store.redis.exists(oauth_store._subject_index_key("user@example.com")) == 0
        )


async def test_token_issued_before_not_before_is_rejected(oauth_store):
    now = int(time.time())
    at = f"km_at_{uuid.uuid4().hex}"
    await oauth_store.put_access_token(
        AccessToken(
            token=at,
            client_id="c1",
            scopes=[],
            expires_at=now + 3600,
            subject="user@example.com",
            claims={"email": "user@example.com", "iat": now - 100},
        )
    )
    await oauth_store.revoke_subject("user@example.com", now=now)
    assert await oauth_store.get_access_token(at) is None
    if isinstance(oauth_store, RedisOAuthStore):
        assert await oauth_store.redis.exists(oauth_store._access_key(at)) == 0


async def test_token_issued_after_revocation_is_accepted(oauth_store):
    now = int(time.time())
    await oauth_store.revoke_subject("user@example.com", now=now)
    at = f"km_at_{uuid.uuid4().hex}"
    await oauth_store.put_access_token(
        AccessToken(
            token=at,
            client_id="c1",
            scopes=[],
            expires_at=now + 3600,
            subject="user@example.com",
            claims={"email": "user@example.com", "iat": now + 1},
        )
    )
    loaded = await oauth_store.get_access_token(at)
    assert loaded is not None
    assert loaded.token == at


async def test_legacy_access_token_is_indexed_on_read(oauth_store):
    now = int(time.time())
    at = f"km_at_{uuid.uuid4().hex}"
    access = AccessToken(
        token=at,
        client_id="c1",
        scopes=[],
        expires_at=now + 3600,
        subject="user@example.com",
        claims={"email": "user@example.com"},
    )
    if isinstance(oauth_store, RedisOAuthStore):
        key = oauth_store._access_key(at)
        await oauth_store.redis.set(key, access.model_dump_json(), ex=3600)
        ttl_before = await oauth_store.redis.ttl(key)
    else:
        oauth_store._access_tokens[at] = access
        ttl_before = None

    loaded = await oauth_store.get_access_token(at)
    assert loaded is not None
    assert loaded.claims is not None
    assert "iat" in loaded.claims

    if isinstance(oauth_store, RedisOAuthStore):
        members = await oauth_store.redis.smembers(
            oauth_store._subject_index_key("user@example.com")
        )
        assert f"at:{at}" in members
        ttl_after = await oauth_store.redis.ttl(oauth_store._access_key(at))
        assert abs(ttl_after - ttl_before) < 5


async def test_legacy_token_unread_is_still_revoked_by_not_before(oauth_store):
    now = int(time.time())
    at = f"km_at_{uuid.uuid4().hex}"
    # Short remaining TTL so inferred iat (expires_at - access_ttl) is before revoke nbf.
    access = AccessToken(
        token=at,
        client_id="c1",
        scopes=[],
        expires_at=now + 600,
        subject="user@example.com",
        claims={"email": "user@example.com"},
    )
    if isinstance(oauth_store, RedisOAuthStore):
        await oauth_store.redis.set(oauth_store._access_key(at), access.model_dump_json(), ex=3600)
    else:
        oauth_store._access_tokens[at] = access

    await oauth_store.revoke_subject("user@example.com", now=now)
    assert await oauth_store.get_access_token(at) is None


@pytest.mark.asyncio
async def test_index_prunes_dead_members_over_256():
    url = require_redis_url()
    prefix = redis_key_prefix("prune")
    store = RedisOAuthStore(
        url,
        key_prefix=prefix,
        client_ttl_seconds=5000,
        refresh_ttl_seconds=3000,
        access_ttl_seconds=3600,
    )
    sub = "prune@example.com"
    idx = store._subject_index_key(sub)
    try:
        now = int(time.time())
        for i in range(260):
            tok = f"dead_at_{i}"
            await store.redis.sadd(idx, f"at:{tok}")
        at_live = f"km_at_live_{uuid.uuid4().hex}"
        await store.put_access_token(
            AccessToken(
                token=at_live,
                client_id="c1",
                scopes=[],
                expires_at=now + 3600,
                subject=sub,
                claims={"email": sub, "iat": now},
            )
        )
        assert await store.redis.scard(idx) <= 256
        members = await store.redis.smembers(idx)
        assert f"at:{at_live}" in members
    finally:
        keys = [key async for key in store.redis.scan_iter(match=f"{prefix}*")]
        if keys:
            await store.redis.delete(*keys)
        await store.aclose()


@pytest.mark.asyncio
async def test_refresh_exchange_after_revoke_subject_refuses_new_tokens():
    from mcp.server.auth.provider import TokenError
    from mcp.shared.auth import OAuthClientInformationFull

    from conftest import BASE_URL, VALID_TOKEN
    from keystone_mcp.auth.keystone_oauth_provider import KeystoneOAuthProvider
    from keystone_mcp.auth.login_pending_store import InMemoryLoginPendingStore
    from keystone_mcp.config import Settings
    from support.login import dev_token_login

    settings = Settings(base_url=BASE_URL)
    store = InMemoryOAuthStore(
        client_ttl_seconds=5000,
        refresh_ttl_seconds=3000,
        access_ttl_seconds=3600,
    )
    pending = InMemoryLoginPendingStore()
    provider = KeystoneOAuthProvider(
        settings,
        store,
        pending,
        login_providers=[dev_token_login({VALID_TOKEN})],
    )
    oauth_client = OAuthClientInformationFull(
        client_id="c1",
        redirect_uris=["http://localhost:9999/callback"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    now = int(time.time())
    old_rt = "km_rt_pre_revoke"
    refresh = RefreshToken(
        token=old_rt,
        client_id="c1",
        scopes=[],
        expires_at=now + 3000,
        subject="user@example.com",
    )
    await store.put_refresh_token(refresh)
    await pending.put(
        "refresh_auth",
        old_rt,
        '{"auth_method":"api_key","resource":null,"interactive":false}',
        3000,
    )
    loaded = await provider.load_refresh_token(oauth_client, old_rt)
    assert loaded is not None

    await store.revoke_subject("user@example.com", now=now)

    with pytest.raises(TokenError) as excinfo:
        await provider.exchange_refresh_token(oauth_client, loaded, [])
    assert excinfo.value.error == "invalid_grant"
    assert await store.get_refresh_token(old_rt) is None


@pytest.mark.asyncio
async def test_auth_code_exchange_succeeds_when_code_issued_after_nbf():
    from mcp.server.auth.provider import AuthorizationCode
    from mcp.shared.auth import OAuthClientInformationFull

    from conftest import BASE_URL, VALID_TOKEN
    from keystone_mcp.auth.keystone_oauth_provider import KeystoneOAuthProvider
    from keystone_mcp.auth.login_pending_store import InMemoryLoginPendingStore
    from keystone_mcp.config import Settings
    from support.login import dev_token_login

    settings = Settings(base_url=BASE_URL)
    store = InMemoryOAuthStore(
        client_ttl_seconds=5000,
        refresh_ttl_seconds=3000,
        access_ttl_seconds=3600,
    )
    pending = InMemoryLoginPendingStore()
    provider = KeystoneOAuthProvider(
        settings,
        store,
        pending,
        login_providers=[dev_token_login({VALID_TOKEN})],
    )
    oauth_client = OAuthClientInformationFull(
        client_id="c1",
        redirect_uris=["http://localhost:9999/callback"],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    revoke_at = int(time.time())
    await store.revoke_subject("user@example.com", now=revoke_at)

    code_str = "km_code_after_nbf"
    issued_at = revoke_at + 2
    auth_code = AuthorizationCode(
        code=code_str,
        scopes=[],
        expires_at=issued_at + settings.auth_code_ttl_seconds,
        client_id="c1",
        code_challenge="challenge",
        redirect_uri="http://localhost:9999/callback",
        redirect_uri_provided_explicitly=True,
        resource=settings.resource_url,
        subject="user@example.com",
    )
    await provider._put_auth_code(auth_code, auth_method="api_key", interactive=False)

    token = await provider.exchange_authorization_code(oauth_client, auth_code)
    assert token.access_token
    assert await store.get_access_token(token.access_token) is not None
