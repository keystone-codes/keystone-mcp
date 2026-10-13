"""POST /revoke (RFC 7009) and OAuth endpoint throttling."""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import httpx
import pytest
from asgi_lifespan import LifespanManager

from conftest import (
    BASE_URL,
    REDIRECT_URI,
    VALID_TOKEN,
    make_pkce,
    obtain_access_token,
    refresh_access_token,
    register_client,
)
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from support.login import dev_token_login


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


async def test_metadata_advertises_revocation_endpoint(harness):
    r = await harness.client.get("/.well-known/oauth-authorization-server")
    assert r.status_code == 200
    body = r.json()
    assert body.get("revocation_endpoint", "").endswith("/revoke")


async def test_revoke_access_token(harness):
    res = await obtain_access_token(harness.client, harness.settings.resource_url)
    access = res["body"]["access_token"]
    refresh = res["body"]["refresh_token"]
    client_id = res["client_id"]

    revoke = await harness.client.post(
        "/revoke",
        data={"token": access, "client_id": client_id, "client_secret": ""},
    )
    assert revoke.status_code == 200
    assert await _mcp_initialize(harness.client, harness.settings, access) == 401

    renewed = await refresh_access_token(
        harness.client, client_id, refresh, harness.settings.resource_url
    )
    assert renewed["status"] == 200
    assert renewed["body"].get("access_token")


async def test_revoke_refresh_token_also_revokes_access_tokens_of_that_client(harness):
    email = "multi@example.com"

    res_a = await obtain_access_token(harness.client, harness.settings.resource_url, email=email)
    client_a = res_a["client_id"]
    access_a = res_a["body"]["access_token"]
    refresh_a = res_a["body"]["refresh_token"]

    res_b = await obtain_access_token(harness.client, harness.settings.resource_url, email=email)
    assert res_b["client_id"] != client_a
    access_b = res_b["body"]["access_token"]

    revoke = await harness.client.post(
        "/revoke",
        data={"token": refresh_a, "client_id": client_a, "client_secret": ""},
    )
    assert revoke.status_code == 200
    assert await _mcp_initialize(harness.client, harness.settings, access_a) == 401
    assert await _mcp_initialize(harness.client, harness.settings, access_b) == 200


async def test_revoke_foreign_client_token_is_ignored(harness):
    other = await register_client(harness.client, "other")
    res = await obtain_access_token(harness.client, harness.settings.resource_url)
    access = res["body"]["access_token"]

    revoke = await harness.client.post(
        "/revoke",
        data={"token": access, "client_id": other, "client_secret": ""},
    )
    assert revoke.status_code == 200
    assert await _mcp_initialize(harness.client, harness.settings, access) == 200


async def test_revoke_unknown_token_is_200(harness):
    client_id = await register_client(harness.client)
    r = await harness.client.post(
        "/revoke",
        data={"token": "km_at_not_a_real_token", "client_id": client_id, "client_secret": ""},
    )
    assert r.status_code == 200


def _build_throttled_app(**overrides):
    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        oauth_throttle_ip_max=2,
        login_throttle_ip_max=0,
        login_throttle_email_max=0,
        login_throttle_window_seconds=300,
        **overrides,
    )
    mcp, *_rest = build_server(
        login_providers=[dev_token_login({VALID_TOKEN})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    return mcp.http_app(path=settings.http_path)


@pytest.mark.asyncio
async def test_revoke_is_throttled():
    app = _build_throttled_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "test-state",
                "resource": BASE_URL,
            }
            assert (await client.get("/authorize", params=params)).status_code in (302, 307)
            token_req = {
                "grant_type": "authorization_code",
                "code": "bogus",
                "redirect_uri": REDIRECT_URI,
                "client_id": client_id,
                "code_verifier": _verifier,
                "resource": BASE_URL,
            }
            assert (await client.post("/token", data=token_req)).status_code != 429
            assert (await client.post("/token", data=token_req)).status_code == 429
            blocked = await client.post(
                "/revoke",
                data={"token": "km_at_x", "client_id": client_id, "client_secret": ""},
            )
            assert blocked.status_code == 429


@pytest.mark.asyncio
async def test_refresh_commit_after_revoke_is_refused(harness):
    """A refresh already validated must not commit after POST /revoke returns 200."""
    res = await obtain_access_token(harness.client, harness.settings.resource_url)
    client_id = res["client_id"]
    refresh = res["body"]["refresh_token"]
    access = res["body"]["access_token"]
    store = harness.oauth._store
    commit_gate = asyncio.Event()
    real_commit = store.commit_token_pair

    async def gated_commit(**kwargs):
        if kwargs.get("replace_refresh_token"):
            await commit_gate.wait()
        return await real_commit(**kwargs)

    with patch.object(store, "commit_token_pair", side_effect=gated_commit):
        refresh_task = asyncio.create_task(
            harness.client.post(
                "/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh,
                    "client_id": client_id,
                    "resource": harness.settings.resource_url,
                },
            )
        )
        await asyncio.sleep(0.05)
        revoke = await harness.client.post(
            "/revoke",
            data={"token": refresh, "client_id": client_id, "client_secret": ""},
        )
        assert revoke.status_code == 200
        commit_gate.set()
        token_resp = await refresh_task

    assert token_resp.status_code in (400, 401)
    assert token_resp.json().get("error") == "invalid_grant"
    assert await _mcp_initialize(harness.client, harness.settings, access) == 401
    retry = await refresh_access_token(
        harness.client, client_id, refresh, harness.settings.resource_url
    )
    assert retry["status"] in (400, 401)
    assert retry["body"].get("error") == "invalid_grant"


@pytest.mark.asyncio
async def test_revoke_refresh_retries_when_delete_refresh_fails(harness):
    """If refresh deletion fails after access tokens are gone, a retry still finishes."""
    res = await obtain_access_token(harness.client, harness.settings.resource_url)
    client_id = res["client_id"]
    refresh = res["body"]["refresh_token"]
    access = res["body"]["access_token"]
    store = harness.oauth._store
    real_delete = store.delete_refresh_token
    fail_once = True

    async def flaky_delete(token: str) -> None:
        nonlocal fail_once
        if fail_once and token == refresh:
            fail_once = False
            raise RuntimeError("simulated store failure")
        await real_delete(token)

    email = "user@example.com"
    with patch.object(store, "delete_refresh_token", side_effect=flaky_delete):
        with pytest.raises(RuntimeError, match="simulated store failure"):
            await store.revoke_refresh_grant(email, client_id, refresh)

    assert await store.get_refresh_token(refresh) is not None
    assert await _mcp_initialize(harness.client, harness.settings, access) == 401

    second = await harness.client.post(
        "/revoke",
        data={"token": refresh, "client_id": client_id, "client_secret": ""},
    )
    assert second.status_code == 200
    assert await store.get_refresh_token(refresh) is None
    assert await _mcp_initialize(harness.client, harness.settings, access) == 401
