"""MCP-level API key flood does not break the service account key."""

from __future__ import annotations

import os
import secrets
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from asgi_lifespan import LifespanManager
from fastmcp.client import Client
from fastmcp.client.transports import StreamableHttpTransport
from httpx import ASGITransport, AsyncClient

from support.fastmcp_transport import asgi_mcp_http_client_factory

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from keystone_mcp.user_directory.factory import build_user_directory_resolver
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.types import generate_api_key_material
from keystone_mcp.users import service
from keystone_mcp.users.db import make_session_factory, session_scope
from support.oauth_harness import BASE_URL
from support.users_store import make_users_store

_MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


@pytest.mark.asyncio
async def test_service_key_works_during_garbage_bearer_flood(tmp_path, monkeypatch) -> None:
    redis_url = os.environ.get("KEYSTONE_MCP_REDIS_URL", "").strip()
    if not redis_url:
        pytest.skip("KEYSTONE_MCP_REDIS_URL is not set")

    store, revision = await make_users_store(tmp_path)
    directory = LocalUserDirectory(store)
    settings = Settings(
        base_url=BASE_URL,
        deployment_profile="local",
        redis_url=redis_url,
        rbac_mode="off",
        enabled_login_methods=frozenset({"api_key"}),
        primary_login_method="api_key",
        metrics_enabled=True,
    )
    resolver = build_user_directory_resolver(
        settings,
        directory=directory,
        revision_reader=revision,
    )

    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_service_account(
            session,
            name="ci",
            description=None,
            roles=["member"],
            created_by="test",
        )
        _row, service_key = service.issue_api_key(
            session,
            subject="svc:ci",
            label="ci",
            expires_in_days=90,
            created_by="test",
        )

    verify_mock = AsyncMock(wraps=directory.verify_api_key)
    with patch.object(directory, "verify_api_key", verify_mock):
        mcp, _registry, _oauth, _upstreams, _policy, _obs, _reconciler = build_server(
            settings=settings,
            users_store=store,
            user_resolver=resolver,
            oauth_store=InMemoryOAuthStore(),
            register_builtin_catalog=False,
        )
        app = mcp.http_app(path=settings.http_path)
        mcp_url = settings.transport_url

        transport = StreamableHttpTransport(
            mcp_url,
            headers={"Authorization": f"Bearer {service_key}"},
            httpx_client_factory=asgi_mcp_http_client_factory(app),
        )

        async with LifespanManager(app):
            async with httpx.AsyncClient(
                transport=ASGITransport(app=app),
                base_url=BASE_URL,
                timeout=30.0,
            ) as raw_client:
                async with Client(transport) as mcp_client:
                    for i in range(2000):
                        if i % 2 == 0:
                            garbage = "ksk_" + secrets.token_hex(16)
                        else:
                            garbage = generate_api_key_material()[2]
                        response = await raw_client.post(
                            mcp_url,
                            headers={
                                **_MCP_HEADERS,
                                "Authorization": f"Bearer {garbage}",
                            },
                            json={"jsonrpc": "2.0", "id": i, "method": "tools/list"},
                        )
                        assert response.status_code == 401
                        if i % 200 == 199:
                            tools = await mcp_client.list_tools()
                            assert tools is not None

    unknown_calls = [c for c in verify_mock.await_args_list if c.args and c.args[0] != service_key]
    assert len(unknown_calls) == 0
    assert resolver._api_key_cache.positive_size <= 10_000  # noqa: SLF001
    assert resolver._api_key_cache.negative_size <= 10_000  # noqa: SLF001
