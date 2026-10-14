"""Tests for ``keystone-mcp oauth register-client``."""

from __future__ import annotations

import contextlib
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from asgi_lifespan import LifespanManager
from redis.exceptions import RedisError

from conftest import BASE_URL, VALID_TOKEN, authorize_to_login, make_pkce
from keystone_mcp import cli
from keystone_mcp.auth.oauth_store import (
    UNUSED_CLIENT_TTL_SECONDS,
    RedisOAuthStore,
    build_oauth_store,
    build_shared_auth_stores,
)
from keystone_mcp.cli import main
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from support.login import dev_token_login
from support.test_env import redis_key_prefix, require_redis_url

_CLAUDE_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
_CLIENT_ID = "claude-desktop"


@pytest.fixture(autouse=True)
def _quiet_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "configure_logging", lambda settings: None)


def _register_argv(*extra: str) -> list[str]:
    return [
        "oauth",
        "register-client",
        "--client-id",
        _CLIENT_ID,
        "--redirect-uri",
        _CLAUDE_REDIRECT,
        *extra,
    ]


def test_register_client_writes_a_public_client(capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    redis_url = require_redis_url()
    prefix = redis_key_prefix("oauth-cli")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", redis_url)
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_KEY_PREFIX", prefix)

    code = main(_register_argv("--name", "Claude"))
    captured = capsys.readouterr()
    assert code == 0
    assert "registered client claude-desktop" in captured.out

    settings = Settings(redis_url=redis_url, redis_key_prefix=prefix)
    store = build_oauth_store(settings)

    async def _check() -> None:
        try:
            client = await store.get_client(_CLIENT_ID)
            assert client is not None
            assert client.token_endpoint_auth_method == "none"
            assert client.grant_types == ["authorization_code", "refresh_token"]
            assert isinstance(store, RedisOAuthStore)
            ttl = await store.redis.ttl(store._client_key(_CLIENT_ID))
            assert ttl > UNUSED_CLIENT_TTL_SECONDS
            assert await store.redis.zscore(store._client_unused_key(), _CLIENT_ID) is None
        finally:
            await store.aclose()

    import asyncio

    asyncio.run(_check())


def test_register_client_twice_reports_update(capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    redis_url = require_redis_url()
    prefix = redis_key_prefix("oauth-cli2")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", redis_url)
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_KEY_PREFIX", prefix)

    assert main(_register_argv()) == 0
    capsys.readouterr()
    code = main(_register_argv())
    captured = capsys.readouterr()
    assert code == 0
    assert "updated client claude-desktop" in captured.out


def test_register_client_refuses_redirect_outside_allowlist(
    capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    redis_url = require_redis_url()
    prefix = redis_key_prefix("oauth-cli-deny")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", redis_url)
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_KEY_PREFIX", prefix)
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "claude.ai")

    code = main(
        [
            "oauth",
            "register-client",
            "--client-id",
            "evil-client",
            "--redirect-uri",
            "https://evil.example/cb",
        ]
    )
    captured = capsys.readouterr()
    assert code == 1
    assert "redirect URI not allowed by KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS" in captured.err

    settings = Settings(redis_url=redis_url, redis_key_prefix=prefix)
    store = build_oauth_store(settings)

    async def _check() -> None:
        try:
            assert await store.get_client("evil-client") is None
        finally:
            await store.aclose()

    import asyncio

    asyncio.run(_check())


def test_register_client_requires_redis(capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KEYSTONE_MCP_REDIS_URL", raising=False)
    code = main(_register_argv())
    captured = capsys.readouterr()
    assert code == 1
    assert "KEYSTONE_MCP_REDIS_URL is not set" in captured.err


def test_register_client_reports_redis_down(capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    redis_url = require_redis_url()
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", redis_url)
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_KEY_PREFIX", redis_key_prefix("oauth-cli-down"))

    class _BrokenStore:
        async def get_client(self, client_id: str) -> None:
            return None

        async def put_client(self, client) -> None:
            raise RedisError("down")

        async def touch_client(self, client_id: str) -> None:
            raise RedisError("down")

        async def aclose(self) -> None:
            return None

    monkeypatch.setattr(
        "keystone_mcp.auth.oauth_cli.build_oauth_store",
        lambda settings: _BrokenStore(),
    )

    code = main(_register_argv())
    captured = capsys.readouterr()
    assert code == 3
    assert "Redis is unavailable (RedisError)" in captured.err
    assert "Traceback" not in captured.err


def test_register_client_rejects_bad_client_id(capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    redis_url = require_redis_url()
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", redis_url)
    code = main(
        [
            "oauth",
            "register-client",
            "--client-id",
            "a b",
            "--redirect-uri",
            _CLAUDE_REDIRECT,
        ]
    )
    assert code == 1
    assert capsys.readouterr().err


@contextlib.asynccontextmanager
async def _dcr_disabled_server(*, redis_url: str, prefix: str):
    settings = Settings(
        base_url=BASE_URL,
        redis_url=redis_url,
        redis_key_prefix=prefix,
        login_pending_key_prefix=redis_key_prefix("login"),
        oauth_dcr_enabled=False,
        refresh_interval_seconds=0,
    )
    oauth_store, pending_store = build_shared_auth_stores(settings)
    mcp, *_rest = build_server(
        login_providers=[dev_token_login({VALID_TOKEN})],
        settings=settings,
        oauth_store=oauth_store,
        login_pending_store=pending_store,
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            yield client, settings, oauth_store
    await oauth_store.aclose()


async def test_registered_client_can_sign_in(capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    redis_url = require_redis_url()
    prefix = redis_key_prefix("oauth-cli-e2e")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", redis_url)
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_KEY_PREFIX", prefix)

    assert main(_register_argv()) == 0
    capsys.readouterr()

    async with _dcr_disabled_server(redis_url=redis_url, prefix=prefix) as (
        client,
        settings,
        _store,
    ):
        verifier, challenge = make_pkce()
        txn = await authorize_to_login(client, _CLIENT_ID, challenge, settings.resource_url)
        login = await client.post(
            "/login",
            data={"txn": txn, "api_token": VALID_TOKEN, "email": "user@example.com"},
        )
        assert login.status_code == 302, login.text
        code = parse_qs(urlparse(login.headers["location"]).query)["code"][0]
        token = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _CLAUDE_REDIRECT,
                "client_id": _CLIENT_ID,
                "code_verifier": verifier,
                "resource": settings.resource_url,
            },
        )
        assert token.status_code == 200, token.text
