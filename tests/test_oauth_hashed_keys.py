"""OAuth tokens in Redis are stored under SHA-256 key references."""

from __future__ import annotations

import asyncio
import time
import uuid
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from fastmcp import Client
from httpx import ASGITransport, AsyncClient
from mcp.server.auth.provider import AccessToken
from mcp.shared.auth import OAuthClientInformationFull
from prometheus_client import REGISTRY

from keystone_mcp.auth.keystone_oauth_provider import RefreshMeta, encode_refresh_meta
from keystone_mcp.auth.oauth_store import (
    KeystoneRefreshToken,
    RedisOAuthStore,
    token_digest,
)
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.server import bootstrap_platform, build_server
from support.fastmcp_transport import streamable_http_transport_to_app
from support.login import dev_token_login
from support.oauth_harness import BASE_URL, VALID_TOKEN, obtain_access_token, refresh_access_token
from support.test_env import redis_key_prefix, require_redis_url

pytest_plugins = ("support.oauth_stores",)

pytestmark = pytest.mark.asyncio

ADMIN = VerifiedIdentity(email="admin@example.com")
VICTIM = "legacy-victim@example.com"

POLICY_YAML = """\
version: "b06-hashed"
default_deny: true
roles:
  administrator:
    allow: ["*"]
requires_human_identity: []
critical_tools: []
"""


def _counter_snapshot(metric_basename: str) -> dict[frozenset[tuple[str, str]], float]:
    values: dict[frozenset[tuple[str, str]], float] = {}
    for family in REGISTRY.collect():
        if family.name != metric_basename:
            continue
        for sample in family.samples:
            if sample.name != f"{metric_basename}_total":
                continue
            key = frozenset(sample.labels.items())
            values[key] = values.get(key, 0.0) + float(sample.value)
    return values


async def _scan_assert_no_plain_tokens(
    redis,
    prefixes: tuple[str, ...],
    *,
    access_token: str,
    refresh_token: str,
) -> None:
    needles = (access_token, refresh_token)
    for prefix in prefixes:
        async for key in redis.scan_iter(match=f"{prefix}*"):
            key_str = key if isinstance(key, str) else key.decode()
            for needle in needles:
                assert needle not in key_str
            key_type = await redis.type(key)
            if key_type == "string":
                val = await redis.get(key)
                if val:
                    for needle in needles:
                        assert needle not in val
            elif key_type == "set":
                for member in await redis.smembers(key):
                    m = member if isinstance(member, str) else member.decode()
                    for needle in needles:
                        assert needle not in m


async def _mcp_initialize(client: httpx.AsyncClient, settings: Settings, token: str) -> int:
    r = await client.post(
        settings.transport_url,
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        },
        follow_redirects=True,
    )
    return r.status_code


async def _rotation_harness(store_bundle):
    store, pending, settings, backend = store_bundle
    login = dev_token_login({VALID_TOKEN})
    mcp, _registry, oauth, *_rest = build_server(
        login_providers=[login],
        settings=settings,
        oauth_store=store,
        login_pending_store=pending,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            yield client, oauth, store, pending, settings, backend


@pytest_asyncio.fixture
async def redis_block_harness(tmp_path: Path):
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(POLICY_YAML, encoding="utf-8")
    run_id = str(time.time_ns())
    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        users_backend="local",
        redis_url=require_redis_url(),
        redis_key_prefix=redis_key_prefix(f"oauth-b06-{run_id}"),
        login_pending_key_prefix=redis_key_prefix(f"login-b06-{run_id}"),
        superadmin_email=ADMIN.email,
        users_db_url=f"sqlite:///{tmp_path}/keystone-users.db",
    )
    from keystone_mcp.auth.login_pending_store import RedisLoginPendingStore
    from keystone_mcp.auth.oauth_store import build_shared_auth_stores

    oauth_store, pending = build_shared_auth_stores(settings)
    assert isinstance(oauth_store, RedisOAuthStore)
    assert isinstance(pending, RedisLoginPendingStore)

    mcp, registry, _oauth, upstreams, policy_manager, observability, _recon = build_server(
        settings=settings,
        oauth_store=oauth_store,
        login_pending_store=pending,
        login_providers=[dev_token_login({VALID_TOKEN})],
    )
    import keystone_mcp.server as server_module

    await bootstrap_platform(
        upstreams,
        registry,
        settings,
        policy_manager,
        observability=observability,
        users_store=server_module._users_store_holder["store"],
    )
    app = mcp.http_app(path=settings.http_path)

    def _transport(token: str):
        return streamable_http_transport_to_app(app, settings.transport_url, token)

    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL) as http_client:
            admin_res = await obtain_access_token(
                http_client, settings.resource_url, email=ADMIN.email
            )
            admin_token = admin_res["body"]["access_token"]
            async with Client(_transport(admin_token)) as admin_client:
                await admin_client.call_tool(
                    "users_add",
                    {"email": VICTIM, "full_name": "Legacy Victim", "roles": []},
                )
            yield http_client, settings, oauth_store, pending, admin_token, _transport
    await oauth_store.aclose()


@pytest.mark.parametrize("oauth_store_backend", ["redis"], indirect=True)
async def test_no_redis_key_or_value_contains_a_token(oauth_store_backend):
    async for client, _oauth, store, _pending, settings, _backend in _rotation_harness(
        oauth_store_backend
    ):
        assert isinstance(store, RedisOAuthStore)
        res = await obtain_access_token(client, settings.resource_url)
        access = res["body"]["access_token"]
        refresh = res["body"]["refresh_token"]
        renewed = await refresh_access_token(
            client, res["client_id"], refresh, settings.resource_url
        )
        assert renewed["status"] == 200
        new_access = renewed["body"]["access_token"]
        new_refresh = renewed["body"]["refresh_token"]
        prefixes = (
            settings.redis_key_prefix.rstrip(":") + ":",
            settings.login_pending_key_prefix.rstrip(":") + ":",
        )
        await _scan_assert_no_plain_tokens(
            store.redis,
            prefixes,
            access_token=access,
            refresh_token=refresh,
        )
        await _scan_assert_no_plain_tokens(
            store.redis,
            prefixes,
            access_token=new_access,
            refresh_token=new_refresh,
        )


async def test_legacy_plain_access_token_is_accepted_and_moved(oauth_store_backend):
    store, _pending, settings, backend = oauth_store_backend
    if backend != "redis":
        pytest.skip("Redis only")
    assert isinstance(store, RedisOAuthStore)
    now = int(time.time())
    at = f"km_at_{uuid.uuid4().hex}"
    digest = token_digest(at)
    access = AccessToken(
        token=at,
        client_id="legacy-client",
        scopes=[],
        expires_at=now + 3600,
        subject="move@example.com",
        claims={"email": "move@example.com", "iat": now},
    )
    idx = store._subject_index_key("move@example.com")
    plain_key = store._access_key(at)
    await store.redis.set(plain_key, access.model_dump_json(), ex=3600)
    await store.redis.sadd(idx, f"at:{at}")
    ttl_before = await store.redis.ttl(plain_key)

    async for client, _oauth, _store, _pending, settings, _backend in _rotation_harness(
        oauth_store_backend
    ):
        assert await _mcp_initialize(client, settings, at) == 200

    assert await store.redis.exists(plain_key) == 0
    hash_key = store._access_key(digest)
    assert await store.redis.exists(hash_key) == 1
    ttl_after = await store.redis.ttl(hash_key)
    assert abs(ttl_after - ttl_before) <= 2
    members = await store.redis.smembers(idx)
    assert f"at:{at}" not in members
    assert f"at:{digest}" in members


async def test_legacy_plain_refresh_token_refreshes_and_moves(oauth_store_backend):
    store, pending, settings, backend = oauth_store_backend
    if backend != "redis":
        pytest.skip("Redis only")
    assert isinstance(store, RedisOAuthStore)
    client_id = "legacy-refresh-client"
    await store.put_client(
        OAuthClientInformationFull(
            client_id=client_id,
            redirect_uris=["http://localhost:9999/callback"],  # type: ignore[list-item]
            token_endpoint_auth_method="none",
        )
    )
    now = int(time.time())
    refresh_token = f"km_rt_{uuid.uuid4().hex}"
    digest = token_digest(refresh_token)
    refresh_record = KeystoneRefreshToken(
        token=refresh_token,
        client_id=client_id,
        scopes=[],
        expires_at=now + 3600,
        subject="refresh-move@example.com",
        iat=now,
    )
    plain_rt_key = store._refresh_key(refresh_token)
    await store.redis.set(plain_rt_key, refresh_record.model_dump_json(), ex=3600)
    idx = store._subject_index_key("refresh-move@example.com")
    await store.redis.sadd(idx, f"rt:{refresh_token}")

    login_prefix = settings.login_pending_key_prefix
    if not login_prefix.endswith(":"):
        login_prefix = f"{login_prefix}:"
    meta_key = f"{login_prefix}refresh_auth:{refresh_token}"
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
    await store.redis.set(meta_key, meta, ex=3600)

    async for client, _oauth, _store, _pending, settings, _backend in _rotation_harness(
        oauth_store_backend
    ):
        refreshed = await refresh_access_token(
            client, client_id, refresh_token, settings.resource_url
        )
        assert refreshed["status"] == 200, refreshed

    assert await store.redis.exists(plain_rt_key) == 0
    assert await store.redis.exists(store._refresh_key(digest)) == 1
    assert await store.redis.exists(meta_key) == 0
    assert await store.redis.exists(f"{login_prefix}refresh_auth:{digest}") == 1


async def test_legacy_tokens_are_revoked_by_users_block(redis_block_harness):
    http_client, settings, oauth_store, _pending, admin_token, transport = redis_block_harness
    now = int(time.time())
    at = f"km_at_{uuid.uuid4().hex}"
    access = AccessToken(
        token=at,
        client_id="c-legacy",
        scopes=[],
        expires_at=now + 3600,
        subject=VICTIM,
        claims={"email": VICTIM, "iat": now},
    )
    plain_key = oauth_store._access_key(at)
    await oauth_store.redis.set(plain_key, access.model_dump_json(), ex=3600)
    idx = oauth_store._subject_index_key(VICTIM)
    await oauth_store.redis.sadd(idx, f"at:{at}")

    assert await _mcp_initialize(http_client, settings, at) == 200

    async with Client(transport(admin_token)) as admin_client:
        blocked = await admin_client.call_tool("users_block", {"email": VICTIM})
    assert not blocked.is_error

    assert await _mcp_initialize(http_client, settings, at) == 401


async def test_migration_race_is_safe(oauth_store_backend):
    store, _pending, _settings, backend = oauth_store_backend
    if backend != "redis":
        pytest.skip("Redis only")
    assert isinstance(store, RedisOAuthStore)
    now = int(time.time())
    at = f"km_at_{uuid.uuid4().hex}"
    digest = token_digest(at)
    access = AccessToken(
        token=at,
        client_id="race-client",
        scopes=[],
        expires_at=now + 3600,
        subject="race@example.com",
        claims={"email": "race@example.com", "iat": now},
    )
    plain_key = store._access_key(at)
    await store.redis.set(plain_key, access.model_dump_json(), ex=3600)
    await store.redis.sadd(store._subject_index_key("race@example.com"), f"at:{at}")

    results = await asyncio.gather(
        store.get_access_token(at),
        store.get_access_token(at),
    )
    assert all(r is not None and r.token == at for r in results)
    assert await store.redis.exists(store._access_key(digest)) == 1
    assert await store.redis.exists(plain_key) == 0


@pytest.mark.parametrize("oauth_store_backend", ["memory", "redis"], indirect=True)
async def test_revoke_endpoint_works_with_hashed_keys(oauth_store_backend):
    async for client, _oauth, _store, _pending, settings, _backend in _rotation_harness(
        oauth_store_backend
    ):
        res = await obtain_access_token(client, settings.resource_url)
        access = res["body"]["access_token"]
        client_id = res["client_id"]

        revoke_access = await client.post(
            "/revoke",
            data={"token": access, "client_id": client_id, "client_secret": ""},
        )
        assert revoke_access.status_code == 200
        assert await _mcp_initialize(client, settings, access) == 401

        res2 = await obtain_access_token(client, settings.resource_url)
        refresh2 = res2["body"]["refresh_token"]
        revoke_refresh = await client.post(
            "/revoke",
            data={"token": refresh2, "client_id": res2["client_id"], "client_secret": ""},
        )
        assert revoke_refresh.status_code == 200
        renewed = await refresh_access_token(
            client, res2["client_id"], refresh2, settings.resource_url
        )
        assert renewed["status"] in (400, 401)
        assert renewed["body"].get("error") == "invalid_grant"


async def test_migrated_metric(oauth_store_backend):
    store, _pending, _settings, backend = oauth_store_backend
    if backend != "redis":
        pytest.skip("Redis only")
    before = _counter_snapshot("keystone_mcp_oauth_token_keys_migrated")
    now = int(time.time())
    at = f"km_at_{uuid.uuid4().hex}"
    access = AccessToken(
        token=at,
        client_id="metric-client",
        scopes=[],
        expires_at=now + 3600,
        subject="metric@example.com",
        claims={"email": "metric@example.com", "iat": now},
    )
    plain_key = store._access_key(at)
    await store.redis.set(plain_key, access.model_dump_json(), ex=3600)
    await store.redis.sadd(store._subject_index_key("metric@example.com"), f"at:{at}")

    loaded = await store.get_access_token(at)
    assert loaded is not None

    after = _counter_snapshot("keystone_mcp_oauth_token_keys_migrated")
    label = frozenset({"kind": "access", "direction": "to_hashed"}.items())
    assert after.get(label, 0) >= before.get(label, 0) + 1
