"""Dynamic client registration metadata limits (POST /register)."""

from __future__ import annotations

import json

import httpx
import pytest
from asgi_lifespan import LifespanManager
from prometheus_client import REGISTRY

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from support.login import dev_token_login
from support.oauth_harness import BASE_URL, REDIRECT_URI

VALID_TOKEN = "valid-test-token"


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


@pytest.mark.asyncio
async def test_register_rejects_long_client_name() -> None:
    app, _store = _build_app(metrics_enabled=True)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            bad = await client.post(
                "/register",
                json={
                    "redirect_uris": [REDIRECT_URI],
                    "token_endpoint_auth_method": "none",
                    "client_name": "x" * 101,
                },
            )
            assert bad.status_code == 400
            assert bad.json()["error"] == "invalid_client_metadata"

            ok = await client.post(
                "/register",
                json={
                    "redirect_uris": [REDIRECT_URI],
                    "token_endpoint_auth_method": "none",
                    "client_name": "x" * 100,
                },
            )
            assert ok.status_code == 201, ok.text


@pytest.mark.asyncio
async def test_register_rejects_eleven_redirect_uris() -> None:
    app, _store = _build_app()
    uris = [f"http://127.0.0.1:{9000 + i}/cb" for i in range(11)]
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            bad = await client.post(
                "/register",
                json={"redirect_uris": uris, "token_endpoint_auth_method": "none"},
            )
            assert bad.status_code == 400
            assert bad.json()["error_description"] == "too many redirect_uris"

            ok_uris = uris[:10]
            ok = await client.post(
                "/register",
                json={"redirect_uris": ok_uris, "token_endpoint_auth_method": "none"},
            )
            assert ok.status_code == 201, ok.text


@pytest.mark.asyncio
async def test_register_rejects_long_redirect_uri() -> None:
    app, _store = _build_app()
    long_uri = "http://127.0.0.1/" + ("a" * 2040)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={"redirect_uris": [long_uri], "token_endpoint_auth_method": "none"},
            )
            assert r.status_code == 400
            assert r.json()["error"] == "invalid_client_metadata"


@pytest.mark.asyncio
async def test_register_rejects_large_body_without_reading_it_all() -> None:
    app, _store = _build_app()
    bytes_read = 0

    async def tracking_app(scope, receive, send):  # noqa: ANN001
        nonlocal bytes_read

        async def wrapped_receive():
            nonlocal bytes_read
            message = await receive()
            if message.get("type") == "http.request":
                bytes_read += len(message.get("body", b""))
            return message

        await app(scope, wrapped_receive, send)

    huge = b"x" * (3800 * 1024)
    payload = json.dumps(
        {
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
            "client_name": huge.decode("latin-1"),
        }
    ).encode("latin-1")

    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=tracking_app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                content=payload,
                headers={"Content-Type": "application/json"},
            )
            assert r.status_code == 400
            assert r.json()["error_description"] == "registration request is too large"
            assert bytes_read <= _REGISTER_GUARD_MAX_READ()


def _REGISTER_GUARD_MAX_READ() -> int:
    from keystone_mcp.auth.keystone_oauth_provider import _REGISTER_MAX_BODY_BYTES

    return _REGISTER_MAX_BODY_BYTES + 4096


@pytest.mark.asyncio
async def test_register_drops_unlisted_fields() -> None:
    app, store = _build_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={
                    "redirect_uris": [REDIRECT_URI],
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "logo_uri": "https://example.com/logo.png",
                    "jwks": {"keys": []},
                    "contacts": ["ops@example.com"],
                    "x_custom": "drop-me",
                },
            )
            assert r.status_code == 201, r.text
            body = r.json()
            assert "logo_uri" not in body
            assert "jwks" not in body
            assert "contacts" not in body
            assert "x_custom" not in body
            assert body.get("token_endpoint_auth_method") == "none"
            assert body.get("grant_types") == ["authorization_code", "refresh_token"]

            saved = await store.get_client(body["client_id"])
            assert saved is not None
            dumped = saved.model_dump()
            assert "logo_uri" not in dumped or dumped.get("logo_uri") is None
            assert saved.token_endpoint_auth_method == "none"
            assert saved.grant_types == ["authorization_code", "refresh_token"]


@pytest.mark.asyncio
async def test_rejected_metadata_metric() -> None:
    app, _store = _build_app(metrics_enabled=True)
    before = _registrations("rejected_metadata")
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            r = await client.post(
                "/register",
                json={
                    "redirect_uris": [REDIRECT_URI],
                    "token_endpoint_auth_method": "none",
                    "client_name": "y" * 101,
                },
            )
            assert r.status_code == 400
    assert _registrations("rejected_metadata") == before + 1
