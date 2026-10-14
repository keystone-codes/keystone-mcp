"""Atomic refresh rotation, grace-window replay, and authorization-code reuse."""

from __future__ import annotations

import asyncio
import logging
import time
from unittest.mock import patch

import httpx
import pytest
from asgi_lifespan import LifespanManager

from conftest import (
    BASE_URL,
    REDIRECT_URI,
    VALID_TOKEN,
    authorize_to_login,
    make_pkce,
    obtain_access_token,
    refresh_access_token,
    register_client,
)
from keystone_mcp.auth.keystone_oauth_provider import RefreshMeta
from keystone_mcp.auth.oauth_store import RedisOAuthStore, token_digest
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from support.login import dev_token_login

pytest_plugins = ("support.oauth_stores",)

pytestmark = pytest.mark.asyncio


def _invalid_grant(res: dict) -> bool:
    return res["status"] in (400, 401) and res["body"].get("error") == "invalid_grant"


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


async def test_two_parallel_refreshes_rotate_once(oauth_store_backend, caplog):
    caplog.set_level(logging.INFO)
    async for client, oauth, store, _pending, settings, _backend in _rotation_harness(
        oauth_store_backend
    ):
        res = await obtain_access_token(client, settings.resource_url)
        refresh_str = res["body"]["refresh_token"]
        client_id = res["client_id"]
        registered = await oauth.get_client(client_id)
        assert registered is not None
        await oauth._put_refresh_meta(
            refresh_str,
            RefreshMeta(
                auth_method="api_key",
                resource=None,
                interactive=False,
                auth_time=None,
                key_id=None,
                key_id_known=False,
                key_expires_at=None,
            ),
        )
        loaded = await oauth.load_refresh_token(registered, refresh_str)
        assert loaded is not None
        r1 = await oauth.load_refresh_token(registered, refresh_str)
        r2 = await oauth.load_refresh_token(registered, refresh_str)
        first, second = await asyncio.gather(
            oauth.exchange_refresh_token(registered, r1, []),
            oauth.exchange_refresh_token(registered, r2, []),
        )
        assert first.access_token == second.access_token
        assert first.refresh_token == second.refresh_token
        if isinstance(store, RedisOAuthStore):
            prefix = store._prefix
            keys = [k async for k in store.redis.scan_iter(match=f"{prefix}rt:km_rt_*")]
            new_tokens = {k.split(":rt:", 1)[-1] for k in keys}
        else:
            new_tokens = {t for t in store._refresh_tokens if t != refresh_str}
        assert len(new_tokens) == 1
        grace_events = [
            r
            for r in caplog.records
            if getattr(r, "stream", None) == "audit" and "grace_reissue" in r.message
        ]
        assert len(grace_events) == 1
        break


async def test_second_refresh_after_first_completes_gets_same_response(oauth_store_backend):
    async for client, _oauth, _store, _pending, settings, _backend in _rotation_harness(
        oauth_store_backend
    ):
        res = await obtain_access_token(client, settings.resource_url)
        old_refresh = res["body"]["refresh_token"]
        client_id = res["client_id"]
        first = await refresh_access_token(client, client_id, old_refresh, settings.resource_url)
        assert first["status"] == 200
        second = await refresh_access_token(client, client_id, old_refresh, settings.resource_url)
        assert second["status"] == 200
        assert second["body"]["access_token"] == first["body"]["access_token"]
        assert second["body"]["refresh_token"] == first["body"]["refresh_token"]
        break


async def test_replay_after_grace_revokes_branch(oauth_store_backend, monkeypatch):
    store, pending, base_settings, _backend = oauth_store_backend
    settings = Settings(
        base_url=BASE_URL,
        oauth_refresh_grace_seconds=1,
        redis_url=base_settings.redis_url,
        redis_key_prefix=getattr(base_settings, "redis_key_prefix", "km:oauth:"),
        login_pending_key_prefix=getattr(base_settings, "login_pending_key_prefix", "km:login:"),
    )
    bundle = (store, pending, settings, _backend)
    async for client, oauth, store, _pending, settings, _backend in _rotation_harness(bundle):
        email = "replay@example.com"
        res = await obtain_access_token(client, settings.resource_url, email=email)
        old_refresh = res["body"]["refresh_token"]
        client_id = res["client_id"]
        new_res = await refresh_access_token(client, client_id, old_refresh, settings.resource_url)
        assert new_res["status"] == 200
        new_refresh = new_res["body"]["refresh_token"]
        await asyncio.sleep(1.2)
        replay = await refresh_access_token(client, client_id, old_refresh, settings.resource_url)
        assert _invalid_grant(replay)
        blocked = await refresh_access_token(client, client_id, new_refresh, settings.resource_url)
        assert _invalid_grant(blocked)
        other = await obtain_access_token(client, settings.resource_url, email=email)
        assert other["client_id"] != client_id
        assert (
            await client.post(
                settings.transport_url,
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                headers={
                    "Authorization": f"Bearer {other['body']['access_token']}",
                    "Accept": "application/json, text/event-stream",
                },
            )
        ).status_code == 200
        break


async def test_grace_zero_means_immediate_replay(oauth_store_backend):
    store, pending, base_settings, backend = oauth_store_backend
    settings = Settings(
        base_url=BASE_URL,
        oauth_refresh_grace_seconds=0,
        redis_url=base_settings.redis_url,
        redis_key_prefix=getattr(base_settings, "redis_key_prefix", "km:oauth:"),
        login_pending_key_prefix=getattr(base_settings, "login_pending_key_prefix", "km:login:"),
    )
    async for client, _oauth, _store, _pending, settings, _backend in _rotation_harness(
        (store, pending, settings, backend)
    ):
        res = await obtain_access_token(client, settings.resource_url)
        old_refresh = res["body"]["refresh_token"]
        client_id = res["client_id"]
        first = await refresh_access_token(client, client_id, old_refresh, settings.resource_url)
        assert first["status"] == 200
        second = await refresh_access_token(client, client_id, old_refresh, settings.resource_url)
        assert _invalid_grant(second)
        break


async def test_grace_response_not_returned_after_block(oauth_store_backend):
    async for client, oauth, store, _pending, settings, _backend in _rotation_harness(
        oauth_store_backend
    ):
        res = await obtain_access_token(client, settings.resource_url)
        old_refresh = res["body"]["refresh_token"]
        client_id = res["client_id"]
        rotated = await refresh_access_token(client, client_id, old_refresh, settings.resource_url)
        assert rotated["status"] == 200
        email = res.get("email") or "user@example.com"
        await store.revoke_subject(email, now=int(time.time()))
        replay = await refresh_access_token(client, client_id, old_refresh, settings.resource_url)
        assert _invalid_grant(replay)
        break


@pytest.mark.parametrize("oauth_store_backend", ["redis"], indirect=True)
async def test_grace_blob_has_no_plaintext_tokens(oauth_store_backend):
    store, pending, settings, _backend = oauth_store_backend
    assert isinstance(store, RedisOAuthStore)
    async for client, _oauth, store, _pending, settings, _backend in _rotation_harness(
        oauth_store_backend
    ):
        res = await obtain_access_token(client, settings.resource_url)
        old_refresh = res["body"]["refresh_token"]
        client_id = res["client_id"]
        out = await refresh_access_token(client, client_id, old_refresh, settings.resource_url)
        assert out["status"] == 200
        access = out["body"]["access_token"]
        new_refresh = out["body"]["refresh_token"]
        digest = token_digest(old_refresh)
        grace_key = f"{store._prefix}rt_grace:{digest}"
        used_key = f"{store._prefix}rt_used:{digest}"
        blob = await store.redis.get(grace_key)
        assert blob is not None
        assert access not in blob
        assert new_refresh not in blob
        assert old_refresh not in (await store.redis.get(used_key) or "")
        assert old_refresh not in blob
        break


async def test_rotation_by_old_replica_is_plain_invalid_grant(oauth_store_backend):
    async for client, _oauth, store, _pending, settings, _backend in _rotation_harness(
        oauth_store_backend
    ):
        res = await obtain_access_token(client, settings.resource_url)
        old_refresh = res["body"]["refresh_token"]
        client_id = res["client_id"]
        if isinstance(store, RedisOAuthStore):
            await store.redis.delete(store._refresh_key(old_refresh))
        else:
            store._refresh_tokens.pop(old_refresh, None)
        replay = await refresh_access_token(client, client_id, old_refresh, settings.resource_url)
        assert _invalid_grant(replay)
        break


async def test_code_replay_is_invalid_grant_and_revokes(oauth_store_backend):
    from urllib.parse import parse_qs, urlparse

    async for client, _oauth, _store, _pending, settings, _backend in _rotation_harness(
        oauth_store_backend
    ):
        client_id = await register_client(client)
        verifier, challenge = make_pkce()
        txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
        login = await client.post(
            "/login",
            data={"txn": txn, "api_token": VALID_TOKEN, "email": "code-replay@example.com"},
        )
        assert login.status_code == 302
        code = parse_qs(urlparse(login.headers["location"]).query)["code"][0]
        token_req = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": settings.resource_url,
        }
        first = await client.post("/token", data=token_req)
        assert first.status_code == 200
        access = first.json()["access_token"]
        second = await client.post("/token", data=token_req)
        assert second.status_code in (400, 401)
        assert second.json().get("error") == "invalid_grant"
        init = await client.post(
            settings.transport_url,
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            headers={
                "Authorization": f"Bearer {access}",
                "Accept": "application/json, text/event-stream",
            },
        )
        assert init.status_code == 401
        break


async def test_code_race_loser_gets_invalid_grant(oauth_store_backend):
    from urllib.parse import parse_qs, urlparse

    async for client, oauth, _store, _pending, settings, _backend in _rotation_harness(
        oauth_store_backend
    ):
        client_id = await register_client(client)
        verifier, challenge = make_pkce()
        txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
        login = await client.post(
            "/login",
            data={"txn": txn, "api_token": VALID_TOKEN, "email": "code-race@example.com"},
        )
        assert login.status_code == 302
        code = parse_qs(urlparse(login.headers["location"]).query)["code"][0]
        real_consume = oauth._consume_auth_code

        async def lose_consume(code_str: str):
            if code_str == code:
                return None
            return await real_consume(code_str)

        with patch.object(oauth, "_consume_auth_code", side_effect=lose_consume):
            token_req = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": settings.resource_url,
            }
            r = await client.post("/token", data=token_req)
            assert r.status_code in (400, 401)
            assert r.json().get("error") == "invalid_grant"
        break
