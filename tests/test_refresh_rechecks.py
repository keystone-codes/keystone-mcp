"""Refresh-token exchange re-checks directory, API key, and session max age."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from keystone_mcp.auth import keystone_oauth_provider
from keystone_mcp.auth.keystone_oauth_provider import RefreshMeta, encode_refresh_meta
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore, token_digest
from keystone_mcp.config import Settings, startup_warnings
from keystone_mcp.server import build_server
from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.users import service
from keystone_mcp.users.db import make_session_factory, session_scope
from keystone_mcp.users.models import utcnow
from support.fake_users_service import build_fake_users_service
from support.login import dev_token_login
from support.oauth_harness import (
    BASE_URL,
    obtain_access_token,
    refresh_access_token,
    register_client,
)
from support.test_env import require_redis_url
from support.users_store import make_users_store

VALID_TOKEN = "valid-test-token"
HUMAN = "alice@example.com"


def _refresh_meta_key(refresh_token: str) -> str:
    if refresh_token.startswith("km_rt_"):
        return token_digest(refresh_token)
    return refresh_token


class _Harness:
    def __init__(self, ctx, http, client, settings, login, store, oauth, api_key):
        self._ctx = ctx
        self._http = http
        self.client = client
        self.settings = settings
        self.login = login
        self.store = store
        self.oauth = oauth
        self.api_key = api_key

    async def aclose(self) -> None:
        await self._http.aclose()
        await self._ctx.__aexit__(None, None, None)


async def _key_login_harness(tmp_path: Path, **settings_kw) -> _Harness:
    key_expires_in = settings_kw.pop("key_expires_in", None)
    key_days = settings_kw.pop("key_days", 90)

    store, revision = await make_users_store(tmp_path)
    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_user(
            session,
            email=HUMAN,
            full_name="Alice",
            roles=["member"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )
        row, api_key = service.issue_api_key(
            session,
            subject=HUMAN,
            label=None,
            expires_in_days=key_days,
            created_by="test",
        )
        if key_expires_in is not None:
            row.expires_at = utcnow() + key_expires_in
            session.add(row)

    session_max_age_seconds = settings_kw.pop("session_max_age_seconds", 0)
    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/keystone-users.db",
        redis_url=require_redis_url(),
        dev_tokens=VALID_TOKEN,
        enabled_login_methods=frozenset({"api_key"}),
        session_max_age_seconds=session_max_age_seconds,
        **settings_kw,
    )
    directory = LocalUserDirectory(store)
    from keystone_mcp.user_directory.factory import build_user_directory_resolver

    resolver = build_user_directory_resolver(
        settings, directory=directory, revision_reader=revision
    )
    mcp, _reg, oauth, *_ = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
        users_store=store,
        login_providers=None,
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    ctx = LifespanManager(app)
    await ctx.__aenter__()
    http = AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL)
    client = http
    login = await obtain_access_token(client, settings.resource_url, api_token=api_key, email=HUMAN)
    return _Harness(ctx, http, client, settings, login, store, oauth, api_key)


@pytest.mark.asyncio
async def test_expired_key_session_cannot_refresh(tmp_path):
    h = await _key_login_harness(tmp_path, key_expires_in=timedelta(seconds=2))
    try:
        await asyncio.sleep(2.5)
        res = await refresh_access_token(
            h.client,
            h.login["client_id"],
            h.login["body"]["refresh_token"],
            h.settings.resource_url,
        )
        assert res["body"].get("error") == "invalid_grant"
    finally:
        await h.aclose()


async def test_refresh_never_outlives_key(tmp_path):
    h = await _key_login_harness(
        tmp_path,
        key_expires_in=timedelta(days=1),
        refresh_token_ttl_seconds=30 * 86400,
    )
    try:
        res = await refresh_access_token(
            h.client,
            h.login["client_id"],
            h.login["body"]["refresh_token"],
            h.settings.resource_url,
        )
        assert res["status"] == 200
        new_rt = res["body"]["refresh_token"]
        stored = await h.oauth._store.get_refresh_token(new_rt)  # noqa: SLF001
        assert stored is not None
        assert stored.expires_at is not None
        assert stored.expires_at <= int(time.time()) + 86400 + 5
    finally:
        await h.aclose()


async def test_blocked_in_http_directory_cannot_refresh(tmp_path):
    from keystone_mcp.user_directory.http import HttpUserDirectory

    TOKEN = "test-service-token"

    block_dir = tmp_path / "http-block"
    block_dir.mkdir()
    store, _revision = await make_users_store(block_dir)
    fake = build_fake_users_service(store, token=TOKEN)
    http_dir_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fake),
        base_url="http://fake-users.test",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    directory = HttpUserDirectory(
        base_url="http://fake-users.test",
        service_token=TOKEN,
        timeout_seconds=5.0,
        client=http_dir_client,
    )
    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_user(
            session,
            email=HUMAN,
            full_name="Alice",
            roles=["member"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )
    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        users_backend="http",
        users_service_url="http://fake-users.test",
        users_service_token="test-service-token",
        users_service_allow_insecure_http=True,
        redis_url=require_redis_url(),
        enabled_login_methods=frozenset({"api_key"}),
        session_max_age_seconds=0,
    )
    from keystone_mcp.user_directory.factory import build_user_directory_resolver
    from keystone_mcp.user_directory.revision import InMemoryRevisionReader

    resolver = build_user_directory_resolver(
        settings, directory=directory, revision_reader=InMemoryRevisionReader()
    )
    from keystone_mcp.login.api_key import ApiKeyLoginProvider

    api_key_login = ApiKeyLoginProvider(
        resolver=resolver,
        dev_tokens=frozenset({VALID_TOKEN}),
        resolve_directory_keys=False,
    )
    mcp, _reg, oauth, *_ = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
        login_providers=[api_key_login],
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL) as client:
            login = await obtain_access_token(
                client, settings.resource_url, api_token=VALID_TOKEN, email=HUMAN
            )
            await store.set_blocked(email=HUMAN, blocked=True, actor_email="test")
            res = await refresh_access_token(
                client,
                login["client_id"],
                login["body"]["refresh_token"],
                settings.resource_url,
            )
            assert res["body"].get("error") == "invalid_grant"
            access = login["body"]["access_token"]
            verified = await oauth.verify_token(access)
            assert verified is None


async def test_unknown_user_cannot_refresh(tmp_path):
    h = await _key_login_harness(tmp_path)
    try:
        from keystone_mcp.users.models import UserRow

        factory = make_session_factory(h.store._engine)  # noqa: SLF001
        with session_scope(factory) as session:
            row = session.get(UserRow, HUMAN)
            assert row is not None
            session.delete(row)
        res = await refresh_access_token(
            h.client,
            h.login["client_id"],
            h.login["body"]["refresh_token"],
            h.settings.resource_url,
        )
        assert res["body"].get("error") == "invalid_grant"
    finally:
        await h.aclose()


async def test_directory_unavailable_is_503_and_token_survives(tmp_path):
    h = await _key_login_harness(tmp_path)
    try:
        resolver = h.oauth._user_resolver  # noqa: SLF001

        async def fail_resolve(*args, **kwargs):  # noqa: ANN002
            raise UserDirectoryUnavailableError(
                "users directory is unavailable", code="catalog_unavailable"
            )

        with patch.object(resolver, "resolve", side_effect=fail_resolve):
            res = await refresh_access_token(
                h.client,
                h.login["client_id"],
                h.login["body"]["refresh_token"],
                h.settings.resource_url,
            )
        assert res["status"] == 503
        assert res["body"].get("error") == "temporarily_unavailable"
        assert res["body"].get("error_description", "").startswith("users directory")

        res2 = await refresh_access_token(
            h.client,
            h.login["client_id"],
            h.login["body"]["refresh_token"],
            h.settings.resource_url,
        )
        assert res2["status"] == 200
    finally:
        await h.aclose()


async def test_open_circuit_breaker_is_503(tmp_path):
    h = await _key_login_harness(tmp_path)
    try:
        resolver = h.oauth._user_resolver  # noqa: SLF001
        for _ in range(10):
            resolver._circuit.record_failure()  # noqa: SLF001
        res = await refresh_access_token(
            h.client,
            h.login["client_id"],
            h.login["body"]["refresh_token"],
            h.settings.resource_url,
        )
        assert res["status"] == 503
    finally:
        await h.aclose()


async def test_session_max_age_refuses_refresh(tmp_path):
    h = await _key_login_harness(tmp_path, session_max_age_seconds=60)
    try:
        rt = h.login["body"]["refresh_token"]
        meta_key = _refresh_meta_key(rt)
        raw = await h.oauth._pending_store.get("refresh_auth", meta_key)  # noqa: SLF001
        from keystone_mcp.auth.keystone_oauth_provider import parse_refresh_meta

        existing = parse_refresh_meta(raw)
        assert existing is not None
        await h.oauth._pending_store.put(  # noqa: SLF001
            "refresh_auth",
            meta_key,
            encode_refresh_meta(
                RefreshMeta(
                    auth_method=existing.auth_method,
                    resource=existing.resource,
                    interactive=existing.interactive,
                    auth_time=int(time.time()) - 61,
                    key_id=existing.key_id,
                    key_id_known=existing.key_id_known,
                    key_expires_at=existing.key_expires_at,
                )
            ),
            3600,
        )
        res = await refresh_access_token(
            h.client,
            h.login["client_id"],
            rt,
            h.settings.resource_url,
        )
        assert res["body"].get("error") == "invalid_grant"
    finally:
        await h.aclose()


async def test_session_max_age_zero_means_no_limit(tmp_path):
    h = await _key_login_harness(tmp_path, session_max_age_seconds=0)
    try:
        rt = h.login["body"]["refresh_token"]
        await h.oauth._pending_store.put(  # noqa: SLF001
            "refresh_auth",
            _refresh_meta_key(rt),
            encode_refresh_meta(
                RefreshMeta(
                    auth_method="api_key",
                    resource=h.settings.resource_url,
                    interactive=False,
                    auth_time=int(time.time()) - 86400 * 400,
                    key_id=None,
                    key_id_known=True,
                    key_expires_at=None,
                )
            ),
            3600,
        )
        res = await refresh_access_token(
            h.client,
            h.login["client_id"],
            rt,
            h.settings.resource_url,
        )
        assert res["status"] == 200
    finally:
        await h.aclose()


def test_session_max_age_default_is_thirty_days():
    settings = Settings()
    assert settings.session_max_age_seconds == 30 * 24 * 3600


def test_session_max_age_default_no_startup_warning():
    settings = Settings(deployment_profile="production", base_url="https://example.com")
    warnings = startup_warnings(settings)
    joined = "\n".join(warnings)
    assert "SESSION_MAX_AGE" not in joined.upper()


async def test_auth_time_written_even_without_limit(tmp_path):
    h = await _key_login_harness(tmp_path, session_max_age_seconds=0)
    try:
        rt = h.login["body"]["refresh_token"]
        await h.oauth._pending_store.put(  # noqa: SLF001
            "refresh_auth",
            _refresh_meta_key(rt),
            encode_refresh_meta(
                RefreshMeta(
                    auth_method="api_key",
                    resource=h.settings.resource_url,
                    interactive=False,
                    auth_time=None,
                    key_id=None,
                    key_id_known=True,
                    key_expires_at=None,
                )
            ),
            3600,
        )
        res = await refresh_access_token(
            h.client,
            h.login["client_id"],
            rt,
            h.settings.resource_url,
        )
        assert res["status"] == 200
        new_rt = res["body"]["refresh_token"]
        raw = await h.oauth._pending_store.get("refresh_auth", _refresh_meta_key(new_rt))  # noqa: SLF001
        from keystone_mcp.auth.keystone_oauth_provider import parse_refresh_meta

        meta = parse_refresh_meta(raw)
        assert meta is not None
        assert meta.auth_time is not None
        assert abs(meta.auth_time - int(time.time())) < 10
    finally:
        await h.aclose()


async def test_legacy_session_counts_from_upgrade(tmp_path, monkeypatch):
    h = await _key_login_harness(tmp_path, session_max_age_seconds=60)
    try:
        rt = h.login["body"]["refresh_token"]
        await h.oauth._pending_store.put(  # noqa: SLF001
            "refresh_auth",
            _refresh_meta_key(rt),
            encode_refresh_meta(
                RefreshMeta(
                    auth_method="api_key",
                    resource=h.settings.resource_url,
                    interactive=False,
                    auth_time=None,
                    key_id=None,
                    key_id_known=False,
                    key_expires_at=None,
                )
            ),
            3600,
        )
        res = await refresh_access_token(
            h.client,
            h.login["client_id"],
            rt,
            h.settings.resource_url,
        )
        assert res["status"] == 200
        new_rt = res["body"]["refresh_token"]
        raw = await h.oauth._pending_store.get("refresh_auth", _refresh_meta_key(new_rt))  # noqa: SLF001
        from keystone_mcp.auth.keystone_oauth_provider import parse_refresh_meta

        meta = parse_refresh_meta(raw)
        assert meta is not None
        assert meta.auth_time is not None

        t0 = int(time.time()) + 61
        with patch("keystone_mcp.auth.keystone_oauth_provider.time.time", return_value=t0):
            res2 = await refresh_access_token(
                h.client,
                h.login["client_id"],
                new_rt,
                h.settings.resource_url,
            )
        assert res2["body"].get("error") == "invalid_grant"
    finally:
        await h.aclose()


async def test_refresh_without_resolver_skips_directory_check(tmp_path, caplog):
    keystone_oauth_provider._REFRESH_NO_RESOLVER_WARNED = False
    store, _revision = await make_users_store(tmp_path)
    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_user(
            session,
            email="user@example.com",
            full_name="User",
            roles=["member"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )
    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        rbac_mode="off",
        redis_url="",
        dev_tokens=VALID_TOKEN,
        primary_login_method="dev_token",
        enabled_login_methods=frozenset({"dev_token"}),
        session_max_age_seconds=0,
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/users.db",
    )
    mcp, _reg, oauth, *_ = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=None,
        users_store=store,
        login_providers=[dev_token_login({VALID_TOKEN})],
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    caplog.set_level(logging.WARNING)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL) as client:
            login = await obtain_access_token(client, settings.resource_url)
            oauth._user_resolver = None  # noqa: SLF001
            for _ in range(2):
                res = await refresh_access_token(
                    client,
                    login["client_id"],
                    login["body"]["refresh_token"],
                    settings.resource_url,
                )
                assert res["status"] == 200
                login["body"]["refresh_token"] = res["body"]["refresh_token"]
    assert caplog.text.count("refresh does not re-check the users directory") == 1


async def test_key_session_without_resolver_is_refused(tmp_path):
    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        rbac_mode="off",
        redis_url="",
        enabled_login_methods=frozenset({"api_key"}),
        session_max_age_seconds=0,
    )
    mcp, _reg, oauth, *_ = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=None,
        login_providers=None,
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL) as client:
            client_id = await register_client(client)
            oauth._user_resolver = None  # noqa: SLF001
            now = int(time.time())
            from mcp.server.auth.provider import RefreshToken

            rt = "km_rt_testonly"
            await oauth._store.put_refresh_token(  # noqa: SLF001
                RefreshToken(
                    token=rt,
                    client_id=client_id,
                    scopes=[],
                    expires_at=now + 3600,
                    subject=HUMAN,
                )
            )
            await oauth._pending_store.put(  # noqa: SLF001
                "refresh_auth",
                _refresh_meta_key(rt),
                encode_refresh_meta(
                    RefreshMeta(
                        auth_method="api_key",
                        resource=settings.resource_url,
                        interactive=False,
                        auth_time=now,
                        key_id="abc123",
                        key_id_known=True,
                        key_expires_at=None,
                    )
                ),
                3600,
            )
            res = await refresh_access_token(client, client_id, rt, settings.resource_url)
            assert res["body"].get("error") == "invalid_grant"
