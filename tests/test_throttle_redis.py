"""Redis-backed shared throttles."""

from __future__ import annotations

import logging
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest
import redis
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from prometheus_client import REGISTRY
from redis.exceptions import RedisError

from keystone_mcp.auth.oauth_store import build_shared_auth_stores
from keystone_mcp.auth.rate_window import InMemorySlidingWindow, RedisSlidingWindow
from keystone_mcp.auth.throttle import LoginAttemptThrottle, ip_bucket
from keystone_mcp.config import (
    ConfigError,
    Settings,
    load_settings,
    startup_warnings,
    validate_settings,
)
from keystone_mcp.router.throttle_middleware import THROTTLE_MESSAGE
from keystone_mcp.server import build_server
from support.login import dev_token_login
from support.oauth_harness import BASE_URL, REDIRECT_URI, VALID_TOKEN
from support.test_env import redis_key_prefix, require_redis_url

SUBJECT = "throttle-redis@example.com"
ALLOW_ALL_POLICY = """\
version: "throttle-redis"
default_deny: true
roles:
  administrator:
    allow: ["*"]
"""


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "rbac-policy.yaml"
    path.write_text(ALLOW_ALL_POLICY, encoding="utf-8")
    return path


def _redis_settings(**overrides: object) -> Settings:
    base = {
        "base_url": BASE_URL,
        "refresh_interval_seconds": 0,
        "redis_url": require_redis_url(),
        "redis_key_prefix": redis_key_prefix("oauth"),
        "login_pending_key_prefix": redis_key_prefix("login"),
        "throttle_backend": "redis",
        "rbac_mode": "off",
    }
    base.update(overrides)
    return Settings(**base)


def _build_mcp(settings: Settings, policy_path: Path, monkeypatch: pytest.MonkeyPatch):
    from keystone_mcp.adapters.stub import StubAdapter
    from keystone_mcp.identity import VerifiedIdentity

    identity = VerifiedIdentity(email=SUBJECT)
    for module in (
        "keystone_mcp.identity",
        "keystone_mcp.router.rbac_middleware",
        "keystone_mcp.router.throttle_middleware",
    ):
        monkeypatch.setattr(f"{module}.resolve_verified_identity", lambda: identity)

    settings = replace(settings, rbac_policy_path=str(policy_path))
    mcp, registry, _oauth, _up, policy_manager, _obs, _rec = build_server(
        settings=settings,
        login_providers=[dev_token_login({VALID_TOKEN})],
        register_builtin_catalog=False,
    )
    registry.add_route("ping", StubAdapter(), mode="live")
    if policy_manager is not None:
        policy_manager.load_initial(registry)
    return mcp


async def _tool_calls(mcp, times: int) -> None:
    async with Client(mcp) as client:
        for _ in range(times):
            await client.call_tool("ping", {})


@pytest.mark.asyncio
async def test_two_replicas_share_one_budget(
    policy_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Four call_tool hits plus one tools/list per Client session.
    settings = _redis_settings(throttle_max_requests=6, throttle_window_seconds=60)
    mcp_a = _build_mcp(settings, policy_path, monkeypatch)
    mcp_b = _build_mcp(settings, policy_path, monkeypatch)
    await _tool_calls(mcp_a, 2)
    await _tool_calls(mcp_b, 2)
    with pytest.raises((ToolError, MCPError), match=THROTTLE_MESSAGE):
        await _tool_calls(mcp_a, 1)


@pytest.mark.asyncio
async def test_memory_backend_keeps_per_replica_budget(
    policy_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _redis_settings(
        throttle_backend="memory",
        throttle_max_requests=5,
        throttle_window_seconds=60,
    )
    mcp_a = _build_mcp(settings, policy_path, monkeypatch)
    mcp_b = _build_mcp(settings, policy_path, monkeypatch)
    await _tool_calls(mcp_a, 4)
    await _tool_calls(mcp_b, 4)


@pytest.mark.asyncio
async def test_window_slides() -> None:
    window = InMemorySlidingWindow()
    now = 1000.0
    for _ in range(4):
        decision = await window.hit("k", limit=4, window_seconds=60, now=now)
        assert decision.allowed
    blocked = await window.hit("k", limit=4, window_seconds=60, now=now)
    assert not blocked.allowed
    assert blocked.retry_after >= 1
    later = await window.hit("k", limit=4, window_seconds=60, now=now + 61)
    assert later.allowed


@pytest.mark.asyncio
async def test_retry_after_is_positive() -> None:
    window = InMemorySlidingWindow()
    now = 0.0
    for _ in range(3):
        await window.hit("ip", limit=3, window_seconds=300, now=now)
    denied = await window.hit("ip", limit=3, window_seconds=300, now=now)
    assert not denied.allowed
    assert denied.retry_after >= 1


@pytest.mark.asyncio
async def test_keys_are_hashed_and_expire(redis_url: str) -> None:
    oauth_store, _pending = build_shared_auth_stores(
        Settings(redis_url=redis_url, redis_key_prefix=redis_key_prefix("oauth"))
    )
    assert oauth_store.redis is not None
    sliding = RedisSlidingWindow(
        oauth_store.redis,
        key_prefix=redis_key_prefix("oauth"),
        kind="tool",
    )
    email = "person@example.com"
    ip = "198.51.100.44"
    await sliding.hit(email, limit=2, window_seconds=60)
    await sliding.hit(ip, limit=2, window_seconds=60)

    sync = redis.Redis.from_url(redis_url, decode_responses=True)
    prefix = redis_key_prefix("oauth")
    keys: list[str] = []
    cursor = 0
    while True:
        cursor, batch = sync.scan(cursor, match=f"{prefix}throttle:*", count=100)
        keys.extend(batch)
        if cursor == 0:
            break
    assert keys
    for key in keys:
        assert "@" not in key
        assert "198.51.100" not in key
        pttl = sync.pttl(key)
        assert 0 < pttl <= 60_000


@pytest.mark.asyncio
async def test_redis_error_allows_and_counts(
    redis_url: str, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    from keystone_mcp.auth import rate_window as rate_window_mod

    monkeypatch.setattr(rate_window_mod, "_last_error_log_at", 0.0)
    oauth_store, _pending = build_shared_auth_stores(
        Settings(redis_url=redis_url, redis_key_prefix=redis_key_prefix("oauth"))
    )
    assert oauth_store.redis is not None
    sliding = RedisSlidingWindow(
        oauth_store.redis,
        key_prefix=redis_key_prefix("oauth"),
        kind="tool",
    )
    sliding._script = AsyncMock(side_effect=RedisError("down"))
    before = (
        REGISTRY.get_sample_value("keystone_mcp_throttle_backend_errors_total", {"kind": "tool"})
        or 0.0
    )
    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            decision = await sliding.hit("x", limit=1, window_seconds=60)
            assert decision.allowed
    after = REGISTRY.get_sample_value(
        "keystone_mcp_throttle_backend_errors_total", {"kind": "tool"}
    )
    assert after == before + 3
    assert sum(1 for r in caplog.records if "throttle Redis backend error" in r.message) == 1


@pytest.mark.asyncio
async def test_login_ip_limit_shared(redis_url: str) -> None:
    settings = _redis_settings(
        login_throttle_ip_max=3,
        login_throttle_email_max=0,
        login_throttle_window_seconds=300,
    )
    login = dev_token_login({VALID_TOKEN})

    def _app():
        mcp, *_rest = build_server(
            settings=settings,
            login_providers=[login],
            register_builtin_catalog=False,
        )
        return mcp.http_app(path=settings.http_path)

    app_a = _app()
    app_b = _app()
    async with LifespanManager(app_a):
        async with LifespanManager(app_b):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app_a), base_url=BASE_URL
            ) as client_a:
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app_b), base_url=BASE_URL
                ) as client_b:
                    for client in (client_a, client_b, client_a):
                        r = await client.post(
                            "/register",
                            json={
                                "redirect_uris": [REDIRECT_URI],
                                "token_endpoint_auth_method": "none",
                            },
                        )
                        assert r.status_code in (200, 201), r.text
                    blocked = await client_b.post(
                        "/register",
                        json={
                            "redirect_uris": [REDIRECT_URI],
                            "token_endpoint_auth_method": "none",
                        },
                    )
                    assert blocked.status_code == 429
                    assert int(blocked.headers["retry-after"]) >= 1


@pytest.mark.asyncio
async def test_ipv6_same_64_shares_bucket(redis_url: str) -> None:
    oauth_store, _pending = build_shared_auth_stores(
        Settings(redis_url=redis_url, redis_key_prefix=redis_key_prefix("oauth"))
    )
    assert oauth_store.redis is not None
    prefix = redis_key_prefix("oauth")
    throttle = LoginAttemptThrottle(
        ip_max=2,
        email_max=0,
        window_seconds=300,
        window=RedisSlidingWindow(oauth_store.redis, key_prefix=prefix, kind="login_ip"),
    )
    a = "2001:db8::1"
    b = "2001:db8::2"
    assert ip_bucket(a) == ip_bucket(b)
    assert (await throttle.acheck_ip(a))[0]
    assert (await throttle.acheck_ip(b))[0]
    allowed, retry = await throttle.acheck_ip("2001:db8::3")
    assert not allowed
    assert retry >= 1


def test_invalid_backend_value_refuses_start(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_THROTTLE_BACKEND", "cluster")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_THROTTLE_BACKEND must be one of"):
        load_settings()


def test_production_memory_backend_warns() -> None:
    settings = Settings(deployment_profile="production", throttle_backend="memory")
    warnings = startup_warnings(settings)
    assert any("KEYSTONE_MCP_THROTTLE_BACKEND=memory" in w for w in warnings)


def test_redis_backend_without_redis_url_refused() -> None:
    settings = Settings(throttle_backend="redis", redis_url="")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_REDIS_URL is required"):
        validate_settings(settings)
