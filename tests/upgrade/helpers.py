"""HTTP helpers shared by the live upgrade stand (``run_upgrade.py``)."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

REDIRECT_URI = "http://127.0.0.1:9/callback"
DEV_TOKEN = "upgrade-dev-token"
ADMIN_EMAIL = "admin@upgrade.test"


@dataclass(frozen=True, slots=True)
class TokenPair:
    client_id: str
    access_token: str
    refresh_token: str


def make_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=30.0, http2=False)


async def discover_oauth_metadata(client: httpx.AsyncClient, base_url: str) -> dict[str, Any]:
    prm_resp = await client.get(f"{base_url}/.well-known/oauth-protected-resource")
    prm_resp.raise_for_status()
    prm = prm_resp.json()
    asm_resp = await client.get(f"{base_url}/.well-known/oauth-authorization-server")
    asm_resp.raise_for_status()
    asm = asm_resp.json()
    return {
        "resource": prm["resource"],
        "authorization_endpoint": asm["authorization_endpoint"],
        "token_endpoint": asm["token_endpoint"],
        "registration_endpoint": asm["registration_endpoint"],
    }


async def register_client(client: httpx.AsyncClient, registration_endpoint: str) -> str:
    resp = await client.post(
        registration_endpoint,
        json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
    )
    resp.raise_for_status()
    client_id = resp.json().get("client_id")
    if not client_id:
        raise RuntimeError("client registration returned no client_id")
    return client_id


async def complete_login(
    client: httpx.AsyncClient,
    base_url: str,
    txn: str,
    email: str,
    expected_state: str,
    *,
    dev_token: str = DEV_TOKEN,
) -> str:
    """POST /login; 0.4.x and 0.5.x both accept api_token + email."""
    resp = await client.post(
        f"{base_url}/login",
        data={"txn": txn, "api_token": dev_token, "email": email},
        follow_redirects=False,
    )
    if resp.status_code != 302:
        raise RuntimeError(f"/login expected 302, got {resp.status_code}: {resp.text[:200]}")
    location = resp.headers.get("location", "")
    qs = parse_qs(urlparse(location).query)
    code = qs.get("code", [None])[0]
    state = qs.get("state", [None])[0]
    if not code:
        raise RuntimeError(f"/login redirect missing code: {location}")
    if state != expected_state:
        raise RuntimeError(f"/login state mismatch: {state!r} != {expected_state!r}")
    return code


async def oauth_login_pair(
    client: httpx.AsyncClient,
    base_url: str,
    email: str,
    *,
    dev_token: str = DEV_TOKEN,
    metadata: dict[str, Any] | None = None,
) -> TokenPair:
    meta = metadata if metadata is not None else await discover_oauth_metadata(client, base_url)
    client_id = await register_client(client, meta["registration_endpoint"])
    verifier, challenge = make_pkce()
    state = secrets.token_urlsafe(16)
    auth_resp = await client.get(
        meta["authorization_endpoint"],
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "resource": meta["resource"],
        },
        follow_redirects=False,
    )
    if auth_resp.status_code not in (302, 307):
        raise RuntimeError(f"authorize failed: {auth_resp.status_code}")
    location = auth_resp.headers.get("location", "")
    txn = parse_qs(urlparse(location).query).get("txn", [None])[0]
    if not txn:
        raise RuntimeError("authorize redirect missing txn")
    code = await complete_login(client, base_url, txn, email, state, dev_token=dev_token)
    token_resp = await client.post(
        meta["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": meta["resource"],
        },
    )
    if token_resp.status_code != 200:
        raise RuntimeError(f"token exchange failed: {token_resp.status_code} {token_resp.text}")
    body = token_resp.json()
    access = body.get("access_token")
    refresh = body.get("refresh_token")
    if not access or not refresh:
        raise RuntimeError("token response missing access or refresh token")
    return TokenPair(client_id=client_id, access_token=access, refresh_token=refresh)


async def refresh_tokens(
    client: httpx.AsyncClient,
    token_endpoint: str,
    *,
    client_id: str,
    refresh_token: str,
    resource: str,
) -> TokenPair:
    resp = await client.post(
        token_endpoint,
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
            "resource": resource,
        },
    )
    if resp.status_code != 200:
        raise RuntimeError(f"refresh failed: {resp.status_code} {resp.text}")
    body = resp.json()
    access = body.get("access_token")
    refresh = body.get("refresh_token")
    if not access or not refresh:
        raise RuntimeError("refresh response missing tokens")
    return TokenPair(client_id=client_id, access_token=access, refresh_token=refresh)


async def list_tool_names(base_url: str, access_token: str) -> list[str]:
    transport = StreamableHttpTransport(
        url=f"{base_url.rstrip('/')}/",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    async with Client(transport) as session:
        tools = await session.list_tools()
    return sorted(t.name for t in tools)


async def call_tool(base_url: str, access_token: str, name: str, arguments: dict | None = None) -> Any:
    transport = StreamableHttpTransport(
        url=f"{base_url.rstrip('/')}/",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    async with Client(transport) as session:
        return await session.call_tool(name, arguments or {})


def tool_diff(
    before: list[str],
    after: list[str],
    expected: dict[str, list[dict[str, str]]],
) -> tuple[set[str], set[str]]:
    removed = set(before) - set(after)
    added = set(after) - set(before)
    exp_removed = {item["name"] for item in expected.get("removed", [])}
    exp_added = {item["name"] for item in expected.get("added", [])}
    return (removed - exp_removed) | (exp_removed - removed), (added - exp_added) | (exp_added - added)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def redis_plain_access_key(prefix: str, access_token: str) -> str:
    return f"{prefix}at:{access_token}"


def redis_hashed_access_key(prefix: str, access_token: str) -> str:
    return f"{prefix}at:{token_digest(access_token)}"


def parse_users_list_result(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, str):
        payload = json.loads(payload)
    if isinstance(payload, dict) and "users" in payload:
        return list(payload["users"])
    if isinstance(payload, list):
        return payload
    raise RuntimeError(f"unexpected users_list payload: {type(payload)}")
