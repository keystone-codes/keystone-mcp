"""Shared harness for service-account Bearer API key integration tests."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx2
from asgi_lifespan import LifespanManager
from fastmcp.client.transports import StreamableHttpTransport
from httpx2 import ASGITransport, AsyncClient

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.server import bootstrap_platform, build_server
from keystone_mcp.users import service
from keystone_mcp.users.db import make_session_factory, session_scope
from keystone_mcp.users.factory import build_users_store
from support.login import dev_token_login
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)
from support.oauth_harness import BASE_URL
from support.test_env import require_redis_url, users_revision_key

ADMIN_EMAIL = "admin@example.com"
SERVICE_NAME = "ci"

POLICY_YAML = """\
version: "service-bearer"
default_deny: true
roles:
  administrator:
    allow: ["*"]
  machine:
    allow: ["hello_greet", "hello_whoami"]
requires_human_identity: ["human_only"]
critical_tools: []
"""


@dataclass
class ServiceBearerHarness:
    settings: Settings
    service_key: str
    key_id: str
    observed: dict
    registry: object
    oauth: object
    upstreams: object
    app: object
    store: object

    def mcp_client_factory(self):
        app = self.app

        def factory(headers=None, timeout=None, auth=None, **_kw):
            return AsyncClient(
                transport=ASGITransport(app=app),
                base_url=BASE_URL,
                headers=dict(headers or {}),
                timeout=timeout or httpx2.Timeout(30.0),
                auth=auth,
                follow_redirects=True,
            )

        return factory

    def bearer_transport(self, key: str) -> StreamableHttpTransport:
        return StreamableHttpTransport(
            self.settings.transport_url,
            headers={"Authorization": f"Bearer {key}"},
            httpx_client_factory=self.mcp_client_factory(),
        )


@asynccontextmanager
async def service_bearer_harness(
    tmp_path: Path,
    *,
    deployment_profile: str = "local",
    rbac_mode: str = "enforce",
    require_resource_indicator: bool = False,
    block_service: bool = False,
) -> AsyncIterator[ServiceBearerHarness]:
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(POLICY_YAML, encoding="utf-8")

    observed: dict = {}
    upstream_app = build_lowlevel_upstream_app(tools=["greet", "whoami"], observed=observed)

    store = build_users_store(
        Settings(
            users_db_url=f"sqlite:///{tmp_path}/keystone-users.db",
            redis_url=require_redis_url(),
        )
    )
    await store.migrate()
    factory = make_session_factory(store._engine)  # noqa: SLF001 — test harness
    with session_scope(factory) as session:
        service.create_user(
            session,
            email=ADMIN_EMAIL,
            full_name="Admin",
            roles=["administrator"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )
        service.create_service_account(
            session,
            name=SERVICE_NAME,
            description=None,
            roles=["machine"],
            created_by="test",
        )
        row, service_key = service.issue_api_key(
            session,
            subject=f"svc:{SERVICE_NAME}",
            label="ci",
            expires_in_days=90,
            created_by=ADMIN_EMAIL,
        )
        if block_service:
            service.update_service_account(
                session,
                name=SERVICE_NAME,
                description=None,
                roles=None,
                is_blocked=True,
                actor=ADMIN_EMAIL,
            )
        key_id = row.key_id

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

    base_url = BASE_URL if deployment_profile == "local" else "https://mcp.example.com"
    users_db_url = (
        f"sqlite:///{tmp_path}/keystone-users.db"
        if deployment_profile == "local"
        else "postgresql+psycopg://u:p@db:5432/keystone"
    )

    settings = Settings(
        base_url=base_url,
        deployment_profile=deployment_profile,
        rbac_mode=rbac_mode,
        rbac_policy_path=str(policy_path),
        rbac_audit_subject_salt="service-bearer-salt",
        redis_url=require_redis_url(),
        users_redis_revision_key=users_revision_key("e2e"),
        users_backend="local",
        users_db_url=users_db_url,
        upstreams_json=upstreams_json,
        require_resource_indicator=require_resource_indicator,
        enabled_login_methods=frozenset({"api_key"}),
        primary_login_method="api_key",
    )

    mcp, registry, oauth, upstreams, policy_manager, observability, _reconciler = build_server(
        settings=settings,
        users_store=store,
        oauth_store=InMemoryOAuthStore(),
        login_providers=[dev_token_login({"admin-dev"})],
        register_builtin_catalog=True,
    )
    registry.add_route("human_only", StubAdapter(), mode="live", description="Human gate probe")
    in_process_upstream = asgi_http_client_factory(upstream_app)
    upstreams.http_client_factory = in_process_upstream
    for adapter in upstreams._adapters.values():  # noqa: SLF001 — test harness
        adapter._http_client_factory = in_process_upstream  # noqa: SLF001
    app = mcp.http_app(path=settings.http_path)

    login_providers = [dev_token_login({"admin-dev"})]
    async with LifespanManager(upstream_app):
        async with LifespanManager(app):
            await bootstrap_platform(
                upstreams,
                registry,
                settings,
                policy_manager,
                observability=observability,
                users_store=store,
                login_providers=login_providers,
            )
            yield ServiceBearerHarness(
                settings=settings,
                service_key=service_key,
                key_id=key_id,
                observed=observed,
                registry=registry,
                oauth=oauth,
                upstreams=upstreams,
                app=app,
                store=store,
            )


ADMIN = VerifiedIdentity(email=ADMIN_EMAIL)
