"""SEC-02 / SEC-05: authorization code reuse and PKCE bypass."""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlparse

import pytest

from security.conftest import REDIRECT_URI
from security.helpers import _csrf_from_page, pkce_pair

pytestmark = pytest.mark.security


async def _mint_code(attacker_stand) -> tuple[str, str, str]:
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
            "email": "member@sec.test",
        }
        csrf = _csrf_from_page(page.text)
        if csrf:
            login_data["csrf"] = csrf
        login = await client.post("/login", data=login_data)
        code = parse_qs(urlparse(login.headers["location"]).query)["code"][0]
        return client_id, code, verifier


async def test_authorization_code_second_exchange_is_invalid_grant(attacker_stand) -> None:
    client_id, code, verifier = await _mint_code(attacker_stand)
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
        "code_verifier": verifier,
        "resource": attacker_stand.settings.resource_url,
    }
    async with attacker_stand.raw_client() as client:
        first = await client.post("/token", data=payload)
        assert first.status_code == 200, first.text
        second = await client.post("/token", data=payload)
        assert second.status_code != 200
        assert second.json().get("error") == "invalid_grant"


async def test_parallel_code_exchanges_one_wins_one_invalid_grant(attacker_stand) -> None:
    client_id, code, verifier = await _mint_code(attacker_stand)
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": client_id,
        "code_verifier": verifier,
        "resource": attacker_stand.settings.resource_url,
    }

    async def exchange():
        async with attacker_stand.raw_client() as client:
            return await client.post("/token", data=payload)

    results = await asyncio.gather(exchange(), exchange())
    assert sum(r.status_code == 200 for r in results) == 1
    losers = [r for r in results if r.status_code != 200]
    assert losers and losers[0].json().get("error") == "invalid_grant"


async def test_pkce_plain_method_rejected_at_token(attacker_stand) -> None:
    async with attacker_stand.raw_client() as client:
        reg = await client.post(
            "/register",
            json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
        )
        client_id = reg.json()["client_id"]
        plain_verifier = "plain-verifier-value"
        auth = await client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT_URI,
                "code_challenge": plain_verifier,
                "code_challenge_method": "plain",
                "state": "s",
                "resource": attacker_stand.settings.resource_url,
            },
        )
        if auth.status_code == 400:
            return
        location = auth.headers.get("location", "")
        if "error=" in location:
            return
        txn = parse_qs(urlparse(location).query)["txn"][0]
        page = await client.get(f"/login?txn={txn}")
        login_data = {
            "txn": txn,
            "api_token": attacker_stand.dev_token,
            "email": "member@sec.test",
        }
        csrf = _csrf_from_page(page.text)
        if csrf:
            login_data["csrf"] = csrf
        login = await client.post("/login", data=login_data)
        code = parse_qs(urlparse(login.headers["location"]).query)["code"][0]
        tok = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": client_id,
                "code_verifier": plain_verifier,
                "resource": attacker_stand.settings.resource_url,
            },
        )
        assert tok.status_code != 200


async def test_token_exchange_without_verifier_rejected(attacker_stand) -> None:
    client_id, code, _verifier = await _mint_code(attacker_stand)
    async with attacker_stand.raw_client() as client:
        tok = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": client_id,
                "resource": attacker_stand.settings.resource_url,
            },
        )
    assert tok.status_code != 200
