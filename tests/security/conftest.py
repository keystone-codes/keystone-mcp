"""Adversarial test stand: HTTP/MCP only, no Keystone login helpers in attack tests."""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import httpx2
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from fastmcp.client.transports import StreamableHttpTransport
from httpx2 import ASGITransport, AsyncClient

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.oauth_store import build_shared_auth_stores
from keystone_mcp.config import Settings
from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.login.oidc import OidcLoginProvider
from keystone_mcp.server import bootstrap_platform, build_server
from keystone_mcp.users import service
from keystone_mcp.users.db import make_session_factory, session_scope
from keystone_mcp.users.factory import build_users_store
from security.hostile_upstream import build_hostile_upstream_app
from support.login import dev_token_login
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)
from support.test_env import (
    redis_key_prefix,
    require_redis_url,
    users_revision_key,
)

pytestmark = pytest.mark.security


def pytest_configure(config) -> None:
    try:
        from hypothesis import HealthCheck, Phase, settings
    except ImportError:
        return
    profile = __import__("os").environ.get("HYPOTHESIS_PROFILE", "ci")
    if profile == "nightly":
        settings.register_profile(
            "nightly",
            max_examples=5000,
            deadline=None,
            suppress_health_check=[
                HealthCheck.too_slow,
                HealthCheck.function_scoped_fixture,
            ],
        )
        settings.load_profile("nightly")
    else:
        settings.register_profile(
            "ci",
            max_examples=50,
            deadline=None,
            suppress_health_check=[
                HealthCheck.too_slow,
                HealthCheck.function_scoped_fixture,
            ],
            phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.target],
        )
        settings.load_profile("ci")


BASE_URL = "http://127.0.0.1:8080"
REDIRECT_URI = "http://127.0.0.1:9999/callback"
DEV_TOKEN = "sec-attacker-dev-token"
ADMIN_EMAIL = "admin@sec.test"
MEMBER_EMAIL = "member@sec.test"

_CSRF_FIELD_RE = re.compile(r'name="csrf" value="([^"]*)"')

DEFAULT_POLICY = """\
version: "sec-stand"
default_deny: true
roles:
  administrator:
    allow: ["*"]
  member:
    allow: ["hello_greet", "hello_whoami", "member_probe"]
  robot:
    allow: ["*"]
requires_human_identity: []
critical_tools: []
"""


@dataclass
class AttackerStand:
    settings: Settings
    app: object
    upstream_app: object
    oauth_store: object
    observed: dict
    dev_token: str
    machine_api_key: str

    def raw_client(self) -> AsyncClient:
        return AsyncClient(
            transport=ASGITransport(app=self.app),
            base_url=BASE_URL,
            follow_redirects=False,
        )

    def mcp_transport(
        self, bearer: str, *, extra_headers: dict[str, str] | None = None
    ) -> StreamableHttpTransport:
        headers = dict(extra_headers or {})

        def factory(headers=None, timeout=None, auth=None, **_kw):
            merged = dict(headers or {})
            merged.update(extra_headers or {})
            return AsyncClient(
                transport=ASGITransport(app=self.app),
                base_url=BASE_URL,
                headers=merged,
                timeout=timeout or httpx2.Timeout(30.0),
                auth=auth,
                follow_redirects=True,
            )

        return StreamableHttpTransport(
            self.settings.transport_url,
            auth=bearer,
            headers=headers,
            httpx_client_factory=factory,
        )


def parse_csrf(html: str) -> str:
    match = _CSRF_FIELD_RE.search(html)
    assert match is not None, html
    return match.group(1)


@pytest_asyncio.fixture
async def attacker_stand(tmp_path: Path, monkeypatch) -> AsyncIterator[AttackerStand]:
    require_redis_url()
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(DEFAULT_POLICY, encoding="utf-8")
    observed: dict = {}
    upstream_app = build_lowlevel_upstream_app(tools=["greet", "whoami"], observed=observed)
    store = build_users_store(
        Settings(
            users_db_url=f"sqlite:///{tmp_path}/users.db",
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
            created_by="security-test",
            allowed_roles=None,
        )
        service.create_user(
            session,
            email=MEMBER_EMAIL,
            full_name="Member",
            roles=["member"],
            note=None,
            created_by="security-test",
            allowed_roles=None,
        )
        service.create_service_account(
            session,
            name="bot",
            description="machine probe",
            roles=["robot"],
            created_by=ADMIN_EMAIL,
        )
        _row, machine_key = service.issue_api_key(
            session,
            subject="svc:bot",
            label="sec",
            expires_in_days=30,
            created_by=ADMIN_EMAIL,
        )

    identity_env = "KEYSTONE_MCP_UPSTREAM_HELLO_IDENTITY_SECRET"
    monkeypatch.setenv(identity_env, "sec-test-identity-secret-" + "x" * 20)
    upstreams_json = json.dumps(
        [
            {
                "name": "hello-upstream",
                "url": UPSTREAM_MCP_URL,
                "namespace": "hello",
                "enabled": True,
                "auth": {"identity_secret_env": identity_env},
            }
        ]
    )
    settings = Settings(
        base_url=BASE_URL,
        deployment_profile="local",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        rbac_audit_subject_salt="sec-attacker-salt",
        redis_url=require_redis_url(),
        redis_key_prefix=redis_key_prefix("oauth"),
        login_pending_key_prefix=redis_key_prefix("login"),
        users_redis_revision_key=users_revision_key("sec"),
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/users.db",
        upstreams_json=upstreams_json,
        dev_tokens=DEV_TOKEN,
        enabled_login_methods=frozenset({"api_key"}),
        primary_login_method="api_key",
        log_level="INFO",
        log_redact=True,
        refresh_interval_seconds=0,
        oauth_refresh_grace_seconds=1,
    )
    fake_oidc = FakeOidcIssuer(client_id="sec-oidc", client_secret="sec-oidc-secret")
    oidc_provider = OidcLoginProvider(
        fake_oidc.config(name="fakeoidc", title="Fake OIDC"),
        http_client_factory=fake_oidc.http_client,
    )
    oauth_store, pending_store = build_shared_auth_stores(settings)
    login_providers = [dev_token_login({DEV_TOKEN}), oidc_provider]
    mcp, registry, _oauth, upstreams, policy_manager, observability, _rec = build_server(
        settings=settings,
        users_store=store,
        oauth_store=oauth_store,
        login_pending_store=pending_store,
        login_providers=login_providers,
        register_builtin_catalog=True,
    )
    registry.add_route("member_probe", StubAdapter(), mode="live")
    in_process = asgi_http_client_factory(upstream_app)
    upstreams.http_client_factory = in_process
    for adapter in upstreams._adapters.values():  # noqa: SLF001
        adapter._http_client_factory = in_process  # noqa: SLF001
    app = mcp.http_app(path=settings.http_path)
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
            yield AttackerStand(
                settings=settings,
                app=app,
                upstream_app=upstream_app,
                oauth_store=oauth_store,
                observed=observed,
                dev_token=DEV_TOKEN,
                machine_api_key=machine_key,
            )


@pytest_asyncio.fixture
async def hostile_attacker_stand(
    tmp_path: Path, monkeypatch, request
) -> AsyncIterator[tuple[AttackerStand, str]]:
    """Like ``attacker_stand`` but the upstream is a hostile MCP server ``mode``."""
    mode: str = getattr(request, "param", "bad_tool_names")
    require_redis_url()
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(DEFAULT_POLICY, encoding="utf-8")
    observed: dict = {}
    upstream_app = build_hostile_upstream_app(mode, observed=observed)
    store = build_users_store(
        Settings(
            users_db_url=f"sqlite:///{tmp_path}/users.db",
            redis_url=require_redis_url(),
        )
    )
    await store.migrate()
    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_user(
            session,
            email=ADMIN_EMAIL,
            full_name="Admin",
            roles=["administrator"],
            note=None,
            created_by="security-test",
            allowed_roles=None,
        )
        service.create_user(
            session,
            email=MEMBER_EMAIL,
            full_name="Member",
            roles=["member"],
            note=None,
            created_by="security-test",
            allowed_roles=None,
        )

    identity_env = "KEYSTONE_MCP_UPSTREAM_HELLO_IDENTITY_SECRET"
    monkeypatch.setenv(identity_env, "sec-test-identity-secret-" + "x" * 20)
    upstreams_json = json.dumps(
        [
            {
                "name": "hello-upstream",
                "url": UPSTREAM_MCP_URL,
                "namespace": "hello",
                "enabled": True,
                "auth": {"identity_secret_env": identity_env},
            }
        ]
    )
    settings = Settings(
        base_url=BASE_URL,
        deployment_profile="local",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        rbac_audit_subject_salt="sec-attacker-salt",
        redis_url=require_redis_url(),
        redis_key_prefix=redis_key_prefix("oauth"),
        login_pending_key_prefix=redis_key_prefix("login"),
        users_redis_revision_key=users_revision_key("sec"),
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/users.db",
        upstreams_json=upstreams_json,
        dev_tokens=DEV_TOKEN,
        enabled_login_methods=frozenset({"api_key"}),
        primary_login_method="api_key",
        log_level="INFO",
        log_redact=True,
        refresh_interval_seconds=1 if mode == "list_changed_flood" else 0,
        oauth_refresh_grace_seconds=1,
        upstream_max_catalog_items=500,
        upstream_max_schema_bytes=65536,
    )
    fake_oidc = FakeOidcIssuer(client_id="sec-oidc", client_secret="sec-oidc-secret")
    oidc_provider = OidcLoginProvider(
        fake_oidc.config(name="fakeoidc", title="Fake OIDC"),
        http_client_factory=fake_oidc.http_client,
    )
    oauth_store, pending_store = build_shared_auth_stores(settings)
    login_providers = [dev_token_login({DEV_TOKEN}), oidc_provider]
    mcp, registry, _oauth, upstreams, policy_manager, observability, _rec = build_server(
        settings=settings,
        users_store=store,
        oauth_store=oauth_store,
        login_pending_store=pending_store,
        login_providers=login_providers,
        register_builtin_catalog=True,
    )
    registry.add_route("member_probe", StubAdapter(), mode="live")
    in_process = asgi_http_client_factory(upstream_app)
    upstreams.http_client_factory = in_process
    for adapter in upstreams._adapters.values():  # noqa: SLF001
        adapter._http_client_factory = in_process  # noqa: SLF001
    app = mcp.http_app(path=settings.http_path)
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
            stand = AttackerStand(
                settings=settings,
                app=app,
                upstream_app=upstream_app,
                oauth_store=oauth_store,
                observed=observed,
                dev_token=DEV_TOKEN,
                machine_api_key="unused",
            )
            yield stand, mode
