"""Identity provider account binding (iss, sub) at interactive OIDC login."""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta

import httpx
import pytest
from asgi_lifespan import LifespanManager
from prometheus_client import REGISTRY
from sqlalchemy import text

from conftest import (
    BASE_URL,
    VALID_TOKEN,
    authorize_to_login,
    make_pkce,
    register_client,
)
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import ConfigError, Settings
from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.login.oidc import OidcLoginProvider
from keystone_mcp.server import build_server
from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.cli import main as cli_main
from keystone_mcp.users.db import create_users_engine
from support.test_env import require_redis_url
from support.users_db import sqlite_url
from support.users_store import make_users_store

pytestmark = pytest.mark.asyncio

_CSRF_FIELD_RE = re.compile(r'name="csrf" value="([^"]*)"')


def _metric(outcome: str) -> float:
    return (
        REGISTRY.get_sample_value("keystone_mcp_login_identity_binding_total", {"outcome": outcome})
        or 0.0
    )


def _audit_events(caplog) -> list[dict]:
    events: list[dict] = []
    for record in caplog.records:
        msg = record.getMessage()
        if not msg.startswith("rbac audit "):
            continue
        payload = msg.removeprefix("rbac audit ")
        events.append(json.loads(payload))
    return events


def _settings(tmp_path, **overrides) -> Settings:
    base = {
        "base_url": BASE_URL,
        "users_backend": "local",
        "users_db_url": sqlite_url(tmp_path),
        "redis_url": require_redis_url(),
        "login_identity_binding": "off",
        "rbac_mode": "off",
        "rbac_audit_enabled": True,
        "rbac_audit_subject_salt": "a" * 32,
        "metrics_enabled": True,
    }
    base.update(overrides)
    return Settings(**base)


@asynccontextmanager
async def _oidc_harness(
    tmp_path,
    *,
    binding: str = "off",
    second_provider: OidcLoginProvider | None = None,
    seed_users: bool = True,
) -> AsyncIterator[dict]:
    fake = FakeOidcIssuer(client_id="oidc-cid", client_secret="oidc-secret")
    provider = OidcLoginProvider(
        fake.config(name="oidc"),
        http_client_factory=fake.http_client,
    )
    login_providers = [provider]
    if second_provider is not None:
        login_providers.insert(0, second_provider)
    settings = _settings(tmp_path, login_identity_binding=binding)
    store, _revision = await make_users_store(tmp_path)
    if seed_users:
        await store.create_user(
            email="alice@example.com",
            full_name="Alice",
            roles=["member"],
            note=None,
            created_by="seed@test",
            allowed_roles=None,
        )
        await store.create_user(
            email="bob@example.com",
            full_name="Bob",
            roles=["member"],
            note=None,
            created_by="seed@test",
            allowed_roles=None,
        )
    mcp, _reg, oauth, *_rest = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        users_store=store,
        login_providers=login_providers,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            yield {
                "client": client,
                "fake": fake,
                "store": store,
                "settings": settings,
                "oauth": oauth,
            }
    store.dispose()


async def _start_oidc(client, txn: str, provider_name: str = "oidc") -> str:
    page = await client.get(f"/login?txn={txn}")
    csrf = _CSRF_FIELD_RE.search(page.text).group(1)
    response = await client.post(f"/login/{provider_name}", data={"txn": txn, "csrf": csrf})
    assert response.status_code == 302
    return response.headers["location"]


async def _complete_oidc_login(
    client,
    fake: FakeOidcIssuer,
    settings: Settings,
    *,
    email: str,
    sub: str,
    provider_name: str = "oidc",
) -> httpx.Response:
    fake.user.email = email
    fake.user.subject_id = sub
    client_id = await register_client(client)
    _verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    redirect_url = await _start_oidc(client, txn, provider_name=provider_name)
    callback = await fake.authorize(redirect_url)
    return await client.get(f"/login/{provider_name}/callback", params=callback)


@pytest.fixture
def caplog_audit(caplog):
    caplog.set_level("INFO")
    return caplog


async def test_binding_off_by_default_allows_any_sub(tmp_path) -> None:
    async with _oidc_harness(tmp_path, binding="off") as harness:
        client = harness["client"]
        fake = harness["fake"]
        store = harness["store"]
        settings = harness["settings"]
        r1 = await _complete_oidc_login(
            client, fake, settings, email="alice@example.com", sub="sub-one"
        )
        assert r1.status_code == 302
        r2 = await _complete_oidc_login(
            client, fake, settings, email="alice@example.com", sub="sub-two"
        )
        assert r2.status_code == 302
        engine = create_users_engine(harness["settings"].users_db_url)
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT idp_issuer, idp_subject FROM keystone_user "
                    "WHERE email = 'alice@example.com'"
                )
            ).first()
        assert row == (None, None)
        store.dispose()
        engine.dispose()


async def test_first_login_binds_and_second_matches(tmp_path, caplog_audit) -> None:
    before_bound = _metric("bound")
    before_matched = _metric("matched")
    async with _oidc_harness(tmp_path, binding="bind") as harness:
        client = harness["client"]
        fake = harness["fake"]
        settings = harness["settings"]
        r1 = await _complete_oidc_login(
            client, fake, settings, email="alice@example.com", sub="stable-sub"
        )
        assert r1.status_code == 302
        r2 = await _complete_oidc_login(
            client, fake, settings, email="alice@example.com", sub="stable-sub"
        )
        assert r2.status_code == 302
        engine = create_users_engine(harness["settings"].users_db_url)
        with engine.connect() as conn:
            row = conn.execute(
                text(
                    "SELECT idp_issuer, idp_subject FROM keystone_user "
                    "WHERE email = 'alice@example.com'"
                )
            ).first()
        assert row[0] is not None
        assert row[1] == "stable-sub"
        engine.dispose()
    assert _metric("bound") >= before_bound + 1
    assert _metric("matched") >= before_matched + 1


async def test_other_sub_is_refused(tmp_path, caplog_audit) -> None:
    async with _oidc_harness(tmp_path, binding="bind") as harness:
        client = harness["client"]
        fake = harness["fake"]
        settings = harness["settings"]
        await _complete_oidc_login(
            client, fake, settings, email="alice@example.com", sub="first-sub"
        )
        response = await _complete_oidc_login(
            client, fake, settings, email="alice@example.com", sub="other-sub"
        )
        assert response.status_code == 403
        assert "error_user_denied" in response.text.lower() or response.status_code == 403
        assert "code=" not in response.headers.get("location", "")
        events = [e for e in _audit_events(caplog_audit) if e.get("action") == "identity_mismatch"]
        assert events
        assert "other-sub" not in json.dumps(events[0])
        assert _metric("mismatch") >= 1


async def test_other_issuer_is_refused(tmp_path) -> None:
    fake_a = FakeOidcIssuer(
        issuer="https://idp-a.test",
        client_id="cid-a",
        client_secret="secret-a",
    )
    provider_a = OidcLoginProvider(
        fake_a.config(name="idp_a"),
        http_client_factory=fake_a.http_client,
    )
    async with _oidc_harness(tmp_path, binding="bind", second_provider=provider_a) as harness:
        client = harness["client"]
        fake = harness["fake"]
        settings = harness["settings"]
        await _complete_oidc_login(
            client, fake, settings, email="alice@example.com", sub="same-sub"
        )
        fake_a.user.email = "alice@example.com"
        fake_a.user.subject_id = "same-sub"
        client_id = await register_client(client)
        _verifier, challenge = make_pkce()
        txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
        redirect_url = await _start_oidc(client, txn, provider_name="idp_a")
        callback = await fake_a.authorize(redirect_url)
        response = await client.get("/login/idp_a/callback", params=callback)
        assert response.status_code == 403


async def test_same_pair_for_two_people_is_conflict(tmp_path) -> None:
    async with _oidc_harness(tmp_path, binding="bind") as harness:
        client = harness["client"]
        fake = harness["fake"]
        settings = harness["settings"]
        await _complete_oidc_login(
            client, fake, settings, email="alice@example.com", sub="shared-sub"
        )
        response = await _complete_oidc_login(
            client, fake, settings, email="bob@example.com", sub="shared-sub"
        )
        assert response.status_code == 403
        assert _metric("conflict") >= 1


async def test_api_key_login_ignores_binding(tmp_path) -> None:
    from keystone_mcp.login.api_key import ApiKeyLoginProvider
    from keystone_mcp.user_directory.types import ApiKeyVerification
    from keystone_mcp.users.models import utcnow

    async with _oidc_harness(tmp_path, binding="bind") as harness:
        client = harness["client"]
        fake = harness["fake"]
        store = harness["store"]
        settings = harness["settings"]
        await _complete_oidc_login(
            client, fake, settings, email="alice@example.com", sub="oidc-sub"
        )
        issued = await store.issue_api_key(
            subject="alice@example.com",
            label="test",
            expires_in_days=None,
            created_by="test",
        )

        class _Resolver:
            async def verify_api_key(self, _key: str) -> ApiKeyVerification:
                return ApiKeyVerification(
                    key_id="kid",
                    subject="alice@example.com",
                    subject_type="human",
                    expires_at=utcnow() + timedelta(days=1),
                )

        key_provider = ApiKeyLoginProvider(resolver=_Resolver(), resolve_directory_keys=True)
        settings = harness["settings"]
        mcp, *_ = build_server(
            settings=settings,
            oauth_store=InMemoryOAuthStore(),
            users_store=store,
            login_providers=[key_provider],
        )
        app = mcp.http_app(path=settings.http_path)
        async with LifespanManager(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url=BASE_URL
            ) as key_client:
                client_id = await register_client(key_client)
                verifier, challenge = make_pkce()
                txn = await authorize_to_login(
                    key_client, client_id, challenge, settings.resource_url
                )
                response = await key_client.post(
                    "/login",
                    data={
                        "txn": txn,
                        "email": "alice@example.com",
                        "api_token": issued.key,
                    },
                )
                assert response.status_code == 302


async def _bind_alice_first_sub(tmp_path) -> str:
    async with _oidc_harness(tmp_path, binding="bind") as harness:
        await _complete_oidc_login(
            harness["client"],
            harness["fake"],
            harness["settings"],
            email="alice@example.com",
            sub="first-sub",
        )
        return harness["settings"].users_db_url


async def _login_alice_second_sub(tmp_path) -> None:
    async with _oidc_harness(tmp_path, binding="bind", seed_users=False) as harness:
        response = await _complete_oidc_login(
            harness["client"],
            harness["fake"],
            harness["settings"],
            email="alice@example.com",
            sub="second-sub",
        )
        assert response.status_code == 302


def test_cli_unbind_allows_new_pair(tmp_path, monkeypatch) -> None:
    import asyncio

    users_db_url = asyncio.run(_bind_alice_first_sub(tmp_path))
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", users_db_url)
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "local")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())
    exit_code = cli_main(["users", "unbind-identity", "--email", "alice@example.com"])
    assert exit_code == 0
    asyncio.run(_login_alice_second_sub(tmp_path))
    engine = create_users_engine(users_db_url)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT idp_subject FROM keystone_user WHERE email = 'alice@example.com'")
        ).first()
    assert row[0] == "second-sub"
    engine.dispose()


def test_bind_mode_without_capability_refuses_start(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())
    settings = Settings(
        base_url=BASE_URL,
        users_backend="http",
        users_service_url="http://users.test",
        users_service_token="token",
        login_identity_binding="bind",
        rbac_mode="off",
    )
    from support.login import dev_token_login

    with pytest.raises(ConfigError, match="identity_binding"):
        build_server(
            settings=settings,
            oauth_store=InMemoryOAuthStore(),
            login_providers=[dev_token_login({VALID_TOKEN})],
        )


async def test_directory_unavailable_during_binding_is_503(tmp_path) -> None:
    class _BrokenBinder:
        name = "local"
        capabilities = frozenset({"identity_binding"})

        async def bind_identity(self, *, email: str, issuer: str, subject: str):
            raise UserDirectoryUnavailableError("down", code="catalog_unavailable")

        async def get_identity_binding(self, email: str):
            return None

        async def clear_identity_binding(self, *, email: str, actor: str) -> bool:
            return False

    fake = FakeOidcIssuer(client_id="oidc-cid", client_secret="oidc-secret")
    provider = OidcLoginProvider(
        fake.config(name="oidc"),
        http_client_factory=fake.http_client,
    )
    settings = _settings(tmp_path, login_identity_binding="bind")
    store, _revision = await make_users_store(tmp_path)
    await store.create_user(
        email="alice@example.com",
        full_name="Alice",
        roles=["member"],
        note=None,
        created_by="seed@test",
        allowed_roles=None,
    )
    mcp, _reg, oauth, *_ = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        users_store=store,
        login_providers=[provider],
    )
    oauth._identity_binder = _BrokenBinder()  # noqa: SLF001
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            fake.user.email = "alice@example.com"
            fake.user.subject_id = "sub"
            client_id = await register_client(client)
            verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            redirect_url = await _start_oidc(client, txn)
            callback = await fake.authorize(redirect_url)
            response = await client.get("/login/oidc/callback", params=callback)
            assert response.status_code == 503
    store.dispose()
