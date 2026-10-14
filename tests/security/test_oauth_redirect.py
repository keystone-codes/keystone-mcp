"""SEC-01: redirect_uri substitution at /authorize and /token."""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

import pytest
from tests.security.conftest import REDIRECT_URI

pytestmark = pytest.mark.security


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


async def _register(attacker_stand, redirect_uri: str = REDIRECT_URI) -> str:
    async with attacker_stand.raw_client() as client:
        r = await client.post(
            "/register",
            json={"redirect_uris": [redirect_uri], "token_endpoint_auth_method": "none"},
        )
        assert r.status_code in (200, 201), r.text
        return r.json()["client_id"]


async def test_unregistered_redirect_uri_gets_error_page(attacker_stand) -> None:
    client_id = await _register(attacker_stand)
    _verifier, challenge = _pkce()
    async with attacker_stand.raw_client() as client:
        r = await client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://evil.example/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "s",
                "resource": attacker_stand.settings.resource_url,
            },
        )
        assert r.status_code == 400
        assert "location" not in {k.lower() for k in r.headers}


async def test_token_redirect_uri_mismatch_is_invalid_grant(attacker_stand) -> None:
    alt = "http://127.0.0.1:9998/callback"
    client_id = await _register(attacker_stand, REDIRECT_URI)
    verifier, challenge = _pkce()
    async with attacker_stand.raw_client() as client:
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
        assert auth.status_code in (302, 307), auth.text
        txn = parse_qs(urlparse(auth.headers["location"]).query)["txn"][0]
        from tests.security.helpers import _csrf_from_page

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
        assert login.status_code == 302, login.text
        code = parse_qs(urlparse(login.headers["location"]).query)["code"][0]
        tok = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": alt,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": attacker_stand.settings.resource_url,
            },
        )
        assert tok.status_code != 200
        body = tok.json()
        assert body.get("error") in ("invalid_grant", "invalid_request")

