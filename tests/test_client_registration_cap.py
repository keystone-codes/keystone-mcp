"""`KEYSTONE_MCP_OAUTH_MAX_CLIENTS`: refuse `POST /register` past the cap.

Covers the registration-time limit (A12): a soft cap on the number of live
(non-expired) OAuth clients tracked by the store, plus the Prometheus counters
and gauge that make the cap observable. The limit is enforced in
``KeystoneOAuthProvider.register_client`` against ``OAuthStore.count_clients``;
expired clients (TTL from A02) never count against it.
"""

from __future__ import annotations

import time

import httpx
import pytest
from asgi_lifespan import LifespanManager
from mcp.shared.auth import OAuthClientInformationFull
from prometheus_client import REGISTRY

from conftest import BASE_URL, REDIRECT_URI
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import ConfigError, Settings, validate_settings
from keystone_mcp.server import build_server
from support.login import dev_token_login

VALID_TOKEN = "valid-test-token"
_REGISTER_PAYLOAD = {"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"}


def _build_app(*, oauth_store=None, **settings_overrides):
    settings = Settings(base_url=BASE_URL, refresh_interval_seconds=0, **settings_overrides)
    _login = dev_token_login({VALID_TOKEN})
    store = oauth_store if oauth_store is not None else InMemoryOAuthStore()
    mcp, *_rest = build_server(
        login_providers=[_login],
        settings=settings,
        oauth_store=store,
        register_builtin_catalog=False,
    )
    return mcp.http_app(path=settings.http_path), store


def _registrations(outcome: str) -> float:
    return (
        REGISTRY.get_sample_value(
            "keystone_mcp_oauth_client_registrations_total",
            {"outcome": outcome},
        )
        or 0.0
    )


def _clients_gauge() -> float | None:
    return REGISTRY.get_sample_value("keystone_mcp_oauth_clients")


async def test_registration_refused_when_cap_reached() -> None:
    app, _store = _build_app(oauth_max_clients=2)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r1 = await client.post("/register", json=_REGISTER_PAYLOAD)
            assert r1.status_code == 201, r1.text
            r2 = await client.post("/register", json=_REGISTER_PAYLOAD)
            assert r2.status_code == 201, r2.text

            r3 = await client.post("/register", json=_REGISTER_PAYLOAD)
            assert r3.status_code == 400, r3.text
            body = r3.json()
            assert body["error"] == "invalid_client_metadata"
            assert "limit" in body["error_description"].lower()


async def test_cap_zero_means_unlimited() -> None:
    app, _store = _build_app(oauth_max_clients=0)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            for _ in range(5):
                r = await client.post("/register", json=_REGISTER_PAYLOAD)
                assert r.status_code == 201, r.text


async def test_expired_clients_do_not_count() -> None:
    store = InMemoryOAuthStore(client_ttl_seconds=100)
    expired = OAuthClientInformationFull(
        client_id="expired-client",
        redirect_uris=[REDIRECT_URI],  # type: ignore[list-item]
        token_endpoint_auth_method="none",
    )
    await store.put_client(expired)
    # Force its entry into the past without waiting out the real TTL.
    store._client_expires_at["expired-client"] = time.time() - 1

    assert await store.count_clients() == 0

    app, _store = _build_app(oauth_store=store, oauth_max_clients=1)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post("/register", json=_REGISTER_PAYLOAD)
            assert r.status_code == 201, r.text


async def test_registration_metrics() -> None:
    app, _store = _build_app(oauth_max_clients=1, metrics_enabled=True)
    before_created = _registrations("created")
    before_rejected = _registrations("rejected_limit")

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r1 = await client.post("/register", json=_REGISTER_PAYLOAD)
            assert r1.status_code == 201, r1.text
            r2 = await client.post("/register", json=_REGISTER_PAYLOAD)
            assert r2.status_code == 400, r2.text

    assert _registrations("created") == before_created + 1
    assert _registrations("rejected_limit") == before_rejected + 1
    assert _clients_gauge() == 1


def test_negative_max_clients_refused() -> None:
    settings = Settings(base_url=BASE_URL, oauth_max_clients=-1)
    with pytest.raises(ConfigError, match="OAUTH_MAX_CLIENTS"):
        validate_settings(settings)
