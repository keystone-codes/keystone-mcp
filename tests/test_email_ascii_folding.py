"""Reject sign-in and write paths when email characters fold to ASCII."""

from __future__ import annotations

import re

import httpx
import pytest
from asgi_lifespan import LifespanManager

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.login.oidc import OidcLoginProvider
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.server import build_server
from keystone_mcp.user_directory.factory import build_user_directory_resolver
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.revision import InMemoryRevisionReader
from keystone_mcp.user_directory.util import email_folds_to_ascii
from keystone_mcp.users import service
from keystone_mcp.users.db import make_session_factory, session_scope
from keystone_mcp.users.revision import InProcessRevisionWriter
from keystone_mcp.users.store import UsersStore
from support.oauth_harness import BASE_URL, authorize_to_login, make_pkce, register_client
from support.users_db import users_engine  # noqa: F401 -- fixture import
from support.users_store import make_users_store

KELVIN_EMAIL = "mar\u212a@corp.example"
FULLWIDTH_EMAIL = "\uff41lice@corp.example"
LIGATURE_EMAIL = "\ufb01n@corp.example"

pytestmark = pytest.mark.asyncio

_CSRF_FIELD_RE = re.compile(r'name="csrf" value="([^"]*)"')


def test_folds_to_ascii_detects_kelvin_and_fullwidth() -> None:
    assert email_folds_to_ascii(KELVIN_EMAIL) is True
    assert email_folds_to_ascii(FULLWIDTH_EMAIL) is True
    assert email_folds_to_ascii(LIGATURE_EMAIL) is True


def test_plain_unicode_addresses_are_not_flagged() -> None:
    assert email_folds_to_ascii("иван@пример.рф") is False
    assert email_folds_to_ascii("josé@corp.example") is False
    assert email_folds_to_ascii("user@xn--e1afmkfd.xn--p1ai") is False


async def test_oidc_login_with_kelvin_sign_is_identity_invalid() -> None:
    fake = FakeOidcIssuer()
    provider = OidcLoginProvider(fake.config(name="oidc"), http_client_factory=fake.http_client)
    settings = Settings(base_url=BASE_URL, enabled_login_methods=frozenset({"api_key"}))
    resolver, backend, _ = _resolver()
    backend.seed("mark@corp.example", roles=("member",))
    mcp, _, _oauth, *_ = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
        login_providers=[provider],
    )
    app = mcp.http_app(path=settings.http_path)
    fake.user.email = KELVIN_EMAIL
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            page = await client.get(f"/login?txn={txn}")
            csrf = _CSRF_FIELD_RE.search(page.text).group(1)  # type: ignore[union-attr]
            redirect = await client.post("/login/oidc", data={"txn": txn, "csrf": csrf})
            assert redirect.status_code == 302
            params = await fake.authorize(redirect.headers["location"])
            response = await client.get("/login/oidc/callback", params=params)
            assert response.status_code == 400
            assert "code=" not in response.headers.get("location", "")


async def test_api_key_login_with_kelvin_sign_is_refused(tmp_path) -> None:
    store, revision = await make_users_store(tmp_path)
    directory = LocalUserDirectory(store)
    resolver = build_user_directory_resolver(
        Settings(base_url=BASE_URL, deployment_profile="local"),
        directory=directory,
        revision_reader=revision,
    )
    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_user(
            session,
            email="mark@corp.example",
            full_name="Mark",
            roles=["member"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )
        _row, key = service.issue_api_key(
            session,
            subject="mark@corp.example",
            label=None,
            expires_in_days=90,
            created_by="test",
        )
    settings = Settings(
        base_url=BASE_URL,
        deployment_profile="local",
        enabled_login_methods=frozenset({"api_key"}),
        primary_login_method="api_key",
    )
    mcp, *_ = build_server(
        settings=settings,
        users_store=store,
        user_resolver=resolver,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            response = await client.post(
                "/login",
                data={"txn": txn, "api_token": key, "email": KELVIN_EMAIL},
            )
            assert response.status_code == 401


async def test_users_add_refuses_folding_email(users_engine) -> None:  # noqa: ANN001, F811
    settings = Settings(base_url=BASE_URL, users_backend="local", rbac_mode="enforce")
    revision = InMemoryRevisionReader()
    store = UsersStore(users_engine, revision=InProcessRevisionWriter(revision.bump))
    engine = RouterEngine(settings)
    registry = RouterRegistry(engine)
    register_catalog(
        registry,
        settings,
        directory=LocalUserDirectory(store),
        role_source=lambda: frozenset({"administrator", "member"}),
    )
    add_route = registry.get("users_add")
    admin = VerifiedIdentity(email="admin@example.com")

    bad = await engine.execute(
        add_route,
        {"email": KELVIN_EMAIL, "full_name": "Fold", "roles": ["member"]},
        identity=admin,
    )
    assert bad["state"] == "error"
    assert bad["code"] == "validation_error"

    ok = await engine.execute(
        add_route,
        {"email": "иван@пример.рф", "full_name": "Ivan", "roles": ["member"]},
        identity=admin,
    )
    assert ok["state"] == "done"


def _resolver():
    from keystone_mcp.user_directory.factory import build_in_memory_user_directory_resolver

    return build_in_memory_user_directory_resolver()
