"""Rate limit applies to MCP list operations."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from typing import AsyncIterator

import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.exceptions import PromptError
from fastmcp.server.middleware import MiddlewareContext
from mcp.shared.exceptions import MCPError
from mcp.types import GetPromptRequestParams

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore, build_shared_auth_stores
from keystone_mcp.auth.throttle import PerIdentityThrottle
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.throttle_middleware import THROTTLE_MESSAGE, ThrottleMiddleware
from keystone_mcp.server import bootstrap_platform, build_server
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from support.login import dev_token_login
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)
from support.test_env import redis_key_prefix, require_redis_url

SUBJECT = "throttle-lists@example.com"
THROTTLE_LIMIT = 3

ALLOW_ALL_POLICY = """\
version: "throttle-lists"
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


@pytest.fixture
def patch_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = VerifiedIdentity(email=SUBJECT)
    for module in (
        "keystone_mcp.identity",
        "keystone_mcp.router.rbac_middleware",
        "keystone_mcp.router.throttle_middleware",
    ):
        monkeypatch.setattr(f"{module}.resolve_verified_identity", lambda: identity)


def _settings(policy_path: Path, *, throttle_backend: str = "memory") -> Settings:
    return Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        throttle_max_requests=THROTTLE_LIMIT,
        throttle_window_seconds=60,
        throttle_backend=throttle_backend,  # type: ignore[arg-type]
        redis_url=require_redis_url(),
        redis_key_prefix=redis_key_prefix("oauth"),
        login_pending_key_prefix=redis_key_prefix("login"),
        users_service_url="http://users:8000",
        users_service_token="token",
        rbac_audit_subject_salt="throttle-list-salt",
    )


@asynccontextmanager
async def _list_harness(
    policy_path: Path,
    *,
    throttle_backend: str = "memory",
) -> AsyncIterator[Client]:
    settings = _settings(policy_path, throttle_backend=throttle_backend)
    upstreams_json = json.dumps(
        [
            {
                "name": "hello-upstream",
                "url": UPSTREAM_MCP_URL,
                "namespace": "hello",
                "enabled": True,
            }
        ]
    )
    settings = replace(settings, upstreams_json=upstreams_json)

    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed(SUBJECT, roles=("administrator",))

    observed: dict = {}
    upstream_app = build_lowlevel_upstream_app(
        tools=["greet"],
        prompts=True,
        resources=True,
        observed=observed,
    )

    build_kwargs: dict = {
        "settings": settings,
        "user_resolver": resolver,
        "login_providers": [dev_token_login({"dev"})],
        "register_builtin_catalog": False,
    }
    if throttle_backend == "memory":
        build_kwargs["oauth_store"] = InMemoryOAuthStore()
    else:
        oauth_store, pending = build_shared_auth_stores(settings)
        build_kwargs["oauth_store"] = oauth_store
        build_kwargs["login_pending_store"] = pending
    mcp, registry, _oauth, upstreams, policy_manager, observability, _reconciler = build_server(
        **build_kwargs
    )
    factory = asgi_http_client_factory(upstream_app)
    upstreams.http_client_factory = factory
    for adapter in upstreams._adapters.values():  # noqa: SLF001 — test harness
        adapter._http_client_factory = factory  # noqa: SLF001

    if policy_manager is not None:
        policy_manager.load_initial(registry)

    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(upstream_app):
        async with LifespanManager(app):
            await bootstrap_platform(
                upstreams,
                registry,
                settings,
                policy_manager,
                observability=observability,
            )
            async with Client(mcp) as client:
                yield client


@pytest.mark.asyncio
@pytest.mark.parametrize("throttle_backend", ["memory", "redis"])
async def test_list_requests_consume_throttle_budget(
    policy_path: Path,
    patch_identity: None,
    throttle_backend: str,
) -> None:
    async with _list_harness(policy_path, throttle_backend=throttle_backend) as client:
        for _ in range(THROTTLE_LIMIT):
            tools = await client.list_tools()
            assert len(tools) > 0
        with pytest.raises(MCPError, match=THROTTLE_MESSAGE):
            await client.list_tools()


@pytest.mark.asyncio
async def test_throttled_list_is_an_error_not_an_empty_list(
    policy_path: Path,
    patch_identity: None,
) -> None:
    async with _list_harness(policy_path) as client:
        for _ in range(THROTTLE_LIMIT):
            await client.list_tools()
        with pytest.raises(MCPError, match=THROTTLE_MESSAGE):
            await client.list_tools()

    async with _list_harness(policy_path) as client:
        for _ in range(THROTTLE_LIMIT):
            await client.list_prompts()
        with pytest.raises(MCPError, match=THROTTLE_MESSAGE):
            await client.list_prompts()

    async with _list_harness(policy_path) as client:
        for _ in range(THROTTLE_LIMIT):
            await client.list_resources()
        with pytest.raises(MCPError, match=THROTTLE_MESSAGE):
            await client.list_resources()

    async with _list_harness(policy_path) as client:
        for _ in range(THROTTLE_LIMIT):
            await client.list_resource_templates()
        with pytest.raises(MCPError, match=THROTTLE_MESSAGE):
            await client.list_resource_templates()


@pytest.mark.asyncio
async def test_throttled_prompt_raises_prompt_error(
    patch_identity: None,
) -> None:
    middleware = ThrottleMiddleware(PerIdentityThrottle(max_requests=1, window_seconds=60))

    async def _noop(_context):
        return "ok"

    params = GetPromptRequestParams(name="hello_summarize", arguments={"topic": "x"})
    context = MiddlewareContext(message=params, fastmcp_context=None)  # type: ignore[arg-type]

    await middleware.on_get_prompt(context, _noop)
    with pytest.raises(PromptError, match=THROTTLE_MESSAGE):
        await middleware.on_get_prompt(context, _noop)


@pytest.mark.asyncio
async def test_throttle_audit_uses_real_operation(
    patch_identity: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from keystone_mcp.router.rbac_middleware import RbacDenialReason

    caplog.set_level(logging.INFO, logger="keystone_mcp.observability.audit")

    recorded: list[dict] = []

    class _Recorder:
        def record_tool_call_attempt(self, *, tool_name: str) -> None:
            return None

        def record_authz_decision(self, **fields):
            recorded.append(fields)

    middleware = ThrottleMiddleware(
        PerIdentityThrottle(max_requests=1, window_seconds=60),
        observability=_Recorder(),  # type: ignore[arg-type]
    )

    async def _noop(_context):
        return "ok"

    params = GetPromptRequestParams(name="hello_summarize", arguments={"topic": "x"})
    context = MiddlewareContext(message=params, fastmcp_context=None)  # type: ignore[arg-type]

    await middleware.on_get_prompt(context, _noop)
    with pytest.raises(PromptError, match=THROTTLE_MESSAGE):
        await middleware.on_get_prompt(context, _noop)

    assert len(recorded) == 1
    assert recorded[0]["operation"] == "get_prompt"
    assert recorded[0]["reason"] is RbacDenialReason.THROTTLED
