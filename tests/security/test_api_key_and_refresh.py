"""SEC-13 / SEC-14: API key and refresh-token theft scenarios."""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import pytest

from security.conftest import MEMBER_EMAIL, REDIRECT_URI
from security.helpers import _csrf_from_page, pkce_pair

pytestmark = pytest.mark.security


async def _login_with_api_key(attacker_stand, *, api_key: str, email: str) -> int:
    verifier, challenge = pkce_pair()
    async with attacker_stand.raw_client() as client:
        reg = await client.post(
            "/register",
            json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
        )
        client_id = reg.json()["client_id"]
        auth = await client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "s",
                "resource": attacker_stand.settings.resource_url,
            },
        )
        txn = parse_qs(urlparse(auth.headers["location"]).query)["txn"][0]
        page = await client.get(f"/login?txn={txn}")
        login_data = {"txn": txn, "api_token": api_key, "email": email}
        csrf = _csrf_from_page(page.text)
        if csrf:
            login_data["csrf"] = csrf
        login = await client.post("/login", data=login_data)
        return login.status_code


async def test_wrong_api_key_on_login_form_rejected(attacker_stand) -> None:
    status = await _login_with_api_key(
        attacker_stand, api_key="ksk_nope_deadbeef", email=MEMBER_EMAIL
    )
    assert status in (401, 403)


async def test_stolen_refresh_after_grace_window_revokes_branch(attacker_stand, monkeypatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS", "1")
    verifier, challenge = pkce_pair()
    async with attacker_stand.raw_client() as client:
        reg = await client.post(
            "/register",
            json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
        )
        client_id = reg.json()["client_id"]
        auth = await client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "s",
                "resource": attacker_stand.settings.resource_url,
            },
        )
        txn = parse_qs(urlparse(auth.headers["location"]).query)["txn"][0]
        page = await client.get(f"/login?txn={txn}")
        login_data = {
            "txn": txn,
            "api_token": attacker_stand.dev_token,
            "email": MEMBER_EMAIL,
        }
        csrf = _csrf_from_page(page.text)
        if csrf:
            login_data["csrf"] = csrf
        login = await client.post("/login", data=login_data)
        code = parse_qs(urlparse(login.headers["location"]).query)["code"][0]
        first = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": attacker_stand.settings.resource_url,
            },
        )
        refresh = first.json()["refresh_token"]

        async def refresh_once(token: str):
            async with attacker_stand.raw_client() as c:
                return await c.post(
                    "/token",
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": token,
                        "client_id": client_id,
                        "resource": attacker_stand.settings.resource_url,
                    },
                )

        thief = await refresh_once(refresh)
        assert thief.status_code == 200, thief.text
        time.sleep(1.2)
        victim = await refresh_once(refresh)
        assert victim.status_code != 200
        assert victim.json().get("error") == "invalid_grant"
        retry_thief = await refresh_once(refresh)
        assert retry_thief.status_code != 200
        assert retry_thief.json().get("error") == "invalid_grant"

