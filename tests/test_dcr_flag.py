"""Tests for the `KEYSTONE_MCP_OAUTH_DCR_ENABLED` switch.

With the flag off, dynamic client registration (RFC 7591, `POST /register`)
must disappear from both the route table and the authorization server
metadata, while a client registered directly in the OAuth store can still
complete the full authorization-code flow.
"""

from __future__ import annotations

import contextlib
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from asgi_lifespan import LifespanManager
from mcp.shared.auth import OAuthClientInformationFull

from conftest import (
    BASE_URL,
    REDIRECT_URI,
    VALID_TOKEN,
    authorize_to_login,
    make_pkce,
    register_client,
)
from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server


@contextlib.asynccontextmanager
async def dcr_client(*, oauth_store=None, **setting_overrides):
    """A client against a server built with the given Settings overrides."""
    settings = Settings(base_url=BASE_URL, **setting_overrides)
    mcp, *_rest = build_server(
        identity_provider=StaticIdentityProvider({VALID_TOKEN}),
        settings=settings,
        oauth_store=oauth_store or InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client.keystone_settings = settings  # type: ignore[attr-defined]
            yield client


async def test_dcr_enabled_by_default() -> None:
    assert Settings().oauth_dcr_enabled is True

    async with dcr_client() as client:
        client_id = await register_client(client)
        assert client_id

        r = await client.get("/.well-known/oauth-authorization-server")
        assert r.status_code == 200
        assert "registration_endpoint" in r.json()


async def test_dcr_disabled_hides_register_route() -> None:
    async with dcr_client(oauth_dcr_enabled=False) as client:
        r = await client.post(
            "/register",
            json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
        )
        assert r.status_code in (404, 405)

        r = await client.get("/.well-known/oauth-authorization-server")
        assert r.status_code == 200
        assert "registration_endpoint" not in r.json()


async def test_manually_registered_client_completes_flow_with_dcr_disabled() -> None:
    store = InMemoryOAuthStore()
    manual_client = OAuthClientInformationFull(
        client_id="manually-registered-client",
        redirect_uris=[REDIRECT_URI],
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name="Manually Registered Client",
    )
    await store.put_client(manual_client)

    async with dcr_client(oauth_store=store, oauth_dcr_enabled=False) as client:
        settings: Settings = client.keystone_settings  # type: ignore[attr-defined]
        verifier, challenge = make_pkce()
        txn = await authorize_to_login(
            client, manual_client.client_id, challenge, settings.resource_url
        )
        r = await client.post(
            "/login", data={"txn": txn, "api_token": VALID_TOKEN, "email": "user@example.com"}
        )
        assert r.status_code == 302, r.text
        code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]

        r = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": manual_client.client_id,
                "code_verifier": verifier,
                "resource": settings.resource_url,
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["access_token"]


def test_dcr_env_flag_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_DCR_ENABLED", "false")
    assert Settings().oauth_dcr_enabled is False
