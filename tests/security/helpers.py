"""Shared HTTP OAuth helpers for security tests (attacker-style raw requests)."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from urllib.parse import parse_qs, urlparse

from tests.security.conftest import REDIRECT_URI, AttackerStand

_CSRF_FIELD_RE = re.compile(r'name="csrf" value="([^"]*)"')


def _csrf_from_page(html: str) -> str | None:
    match = _CSRF_FIELD_RE.search(html)
    return match.group(1) if match else None


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


async def obtain_bearer_token(stand: AttackerStand, *, email: str) -> str:
    verifier, challenge = pkce_pair()
    async with stand.raw_client() as client:
        reg = await client.post(
            "/register",
            json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
        )
        assert reg.status_code in (200, 201), reg.text
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
                "resource": stand.settings.resource_url,
            },
        )
        assert auth.status_code in (302, 307), auth.text
        txn = parse_qs(urlparse(auth.headers["location"]).query)["txn"][0]
        page = await client.get(f"/login?txn={txn}")
        login_data: dict[str, str] = {
            "txn": txn,
            "api_token": stand.dev_token,
            "email": email,
        }
        csrf = _csrf_from_page(page.text)
        if csrf is not None:
            login_data["csrf"] = csrf
        login = await client.post("/login", data=login_data)
        assert login.status_code == 302, login.text
        code = parse_qs(urlparse(login.headers["location"]).query)["code"][0]
        tok = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": stand.settings.resource_url,
            },
        )
        assert tok.status_code == 200, tok.text
        return tok.json()["access_token"]
