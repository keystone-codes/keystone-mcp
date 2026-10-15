"""OAuth flow helpers shared by integration tests (importable without loading conftest)."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import httpx2
from fastmcp.utilities.tests import ASGIServer

VALID_TOKEN = "valid-test-token"
BASE_URL = "http://localhost:8080"
REDIRECT_URI = "http://localhost:9999/callback"


def make_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


@dataclass
class Harness:
    running: ASGIServer
    registry: object
    oauth: object
    settings: object
    client: httpx2.AsyncClient

    def mcp_client_factory(self):
        """An ``McpHttpClientFactory`` reaching this harness's in-process app."""
        return self.running.http_client


async def refresh_access_token(
    client: httpx2.AsyncClient,
    client_id: str,
    refresh_token: str,
    resource: str,
) -> dict:
    """Exchange a refresh token at /token."""
    r = await client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "resource": resource,
        },
    )
    return {
        "status": r.status_code,
        "body": r.json() if r.content else {},
        "client_id": client_id,
    }


async def register_client(client: httpx2.AsyncClient, client_name: str | None = None) -> str:
    payload: dict[str, object] = {
        "redirect_uris": [REDIRECT_URI],
        "token_endpoint_auth_method": "none",
    }
    if client_name is not None:
        payload["client_name"] = client_name
    r = await client.post("/register", json=payload)
    assert r.status_code in (200, 201), r.text
    return r.json()["client_id"]


async def authorize_to_login(
    client: httpx2.AsyncClient, client_id: str, challenge: str, resource: str
) -> str:
    """Run /authorize and return the login transaction id from the redirect."""
    r = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "test-state",
            "resource": resource,
        },
    )
    assert r.status_code in (302, 307), r.text
    return parse_qs(urlparse(r.headers["location"]).query)["txn"][0]


async def obtain_access_token(
    client: httpx2.AsyncClient,
    resource: str,
    api_token: str = VALID_TOKEN,
    email: str = "user@example.com",
) -> dict:
    """Full happy-path OAuth flow; returns the parsed /token JSON response."""
    client_id = await register_client(client)
    verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, resource)
    r = await client.post("/login", data={"txn": txn, "api_token": api_token, "email": email})
    assert r.status_code == 302, r.text
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    r = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": resource,
        },
    )
    return {
        "status": r.status_code,
        "body": r.json() if r.content else {},
        "client_id": client_id,
    }
