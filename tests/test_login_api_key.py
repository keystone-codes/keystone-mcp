"""Sign-in with directory-backed API keys on the login form."""

from __future__ import annotations

import contextlib
from urllib.parse import parse_qs, urlparse

import httpx
from asgi_lifespan import LifespanManager

from conftest import BASE_URL, authorize_to_login, make_pkce, register_client
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.factory import build_user_directory_resolver
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.users import service
from keystone_mcp.users.db import make_session_factory, session_scope
from support.users_store import make_users_store

VALID_DEV = "local-dev-token"


@contextlib.asynccontextmanager
async def _api_key_login_server(tmp_path, *, user_resolver=None, **settings_overrides):
    store, revision = await make_users_store(tmp_path)
    settings = Settings(
        base_url=BASE_URL,
        deployment_profile="local",
        dev_tokens=VALID_DEV,
        enabled_login_methods=frozenset({"api_key"}),
        primary_login_method="api_key",
        **settings_overrides,
    )
    if user_resolver is None:
        directory = LocalUserDirectory(store)
        user_resolver = build_user_directory_resolver(
            settings,
            directory=directory,
            revision_reader=revision,
        )
    mcp, _registry, oauth, _upstreams, _policy, _observability, _reconciler = build_server(
        settings=settings,
        users_store=store,
        user_resolver=user_resolver,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client.keystone_settings = settings  # type: ignore[attr-defined]
            client.keystone_oauth = oauth  # type: ignore[attr-defined]
            client.keystone_store = store  # type: ignore[attr-defined]
            yield client


def _seed_keys(store, tmp_path) -> dict[str, str]:
    factory = make_session_factory(store._engine)  # noqa: SLF001
    keys: dict[str, str] = {}
    with session_scope(factory) as session:
        service.create_user(
            session,
            email="alice@example.com",
            full_name="Alice",
            roles=["member"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )
        service.create_user(
            session,
            email="bob@example.com",
            full_name="Bob",
            roles=["member"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )
        service.create_service_account(
            session,
            name="ci",
            description=None,
            roles=["member"],
            created_by="test",
        )
        _row, keys["alice"] = service.issue_api_key(
            session,
            subject="alice@example.com",
            label=None,
            expires_in_days=90,
            created_by="test",
        )
        _row, keys["bob"] = service.issue_api_key(
            session,
            subject="bob@example.com",
            label=None,
            expires_in_days=90,
            created_by="test",
        )
        _row, keys["svc"] = service.issue_api_key(
            session,
            subject="svc:ci",
            label=None,
            expires_in_days=90,
            created_by="test",
        )
    return keys


async def _login_with_key(client, email: str, api_token: str) -> httpx.Response:
    client_id = await register_client(client)
    _verifier, challenge = make_pkce()
    settings = client.keystone_settings  # type: ignore[attr-defined]
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    return await client.post(
        "/login",
        data={"txn": txn, "api_token": api_token, "email": email},
    )


async def test_human_signs_in_with_directory_api_key(tmp_path) -> None:
    async with _api_key_login_server(tmp_path) as client:
        keys = _seed_keys(client.keystone_store, tmp_path)  # type: ignore[attr-defined]
        response = await _login_with_key(client, "alice@example.com", keys["alice"])
        assert response.status_code == 302
        assert "code" in parse_qs(urlparse(response.headers["location"]).query)


async def test_wrong_person_key_is_refused(tmp_path) -> None:
    async with _api_key_login_server(tmp_path) as client:
        keys = _seed_keys(client.keystone_store, tmp_path)  # type: ignore[attr-defined]
        response = await _login_with_key(client, "alice@example.com", keys["bob"])
        assert response.status_code == 401


async def test_service_account_key_is_refused_on_login_form(tmp_path) -> None:
    async with _api_key_login_server(tmp_path) as client:
        keys = _seed_keys(client.keystone_store, tmp_path)  # type: ignore[attr-defined]
        response = await _login_with_key(client, "alice@example.com", keys["svc"])
        assert response.status_code == 401


async def test_dev_token_still_works_in_local_profile(tmp_path) -> None:
    async with _api_key_login_server(tmp_path) as client:
        _seed_keys(client.keystone_store, tmp_path)  # type: ignore[attr-defined]
        response = await _login_with_key(client, "alice@example.com", VALID_DEV)
        assert response.status_code == 302


async def test_directory_unavailable_returns_503_and_keeps_transaction(tmp_path) -> None:
    store, revision = await make_users_store(tmp_path)
    directory = LocalUserDirectory(store)
    resolver = build_user_directory_resolver(
        Settings(base_url=BASE_URL, redis_url=""),
        directory=directory,
        revision_reader=revision,
    )
    real_verify = resolver.verify_api_key
    calls = {"n": 0}

    async def flaky_verify(key: str):
        calls["n"] += 1
        if calls["n"] == 1:
            raise UserDirectoryUnavailableError("down", code="catalog_unavailable")
        return await real_verify(key)

    resolver.verify_api_key = flaky_verify  # type: ignore[method-assign]

    async with _api_key_login_server(tmp_path, user_resolver=resolver) as client:
        keys = _seed_keys(client.keystone_store, tmp_path)  # type: ignore[attr-defined]

        client_id = await register_client(client)
        _verifier, challenge = make_pkce()
        settings = client.keystone_settings  # type: ignore[attr-defined]
        txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

        unavailable = await client.post(
            "/login",
            data={"txn": txn, "api_token": keys["alice"], "email": "alice@example.com"},
        )
        assert unavailable.status_code == 503
        assert 'name="login_error" value="error_directory_unavailable"' in unavailable.text

        recovered = await client.post(
            "/login",
            data={"txn": txn, "api_token": keys["alice"], "email": "alice@example.com"},
        )
        assert recovered.status_code == 302
