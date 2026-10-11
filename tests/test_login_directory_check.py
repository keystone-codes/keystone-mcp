"""Login-time users-directory checks for token-based sign-in (A01).

Before this check, ``POST /login`` only verified the ``api_token``: any
holder of a shared DEV-token (or an auth-service-issued one) could sign in as
an arbitrary email, including one with no account at all. Now, once the
token checks out, the email is looked up in the users directory and the
login is refused unless the email exists and is not blocked. The email is
also lowercased before it becomes the access token's subject/claim, so
``Alice@Example.COM`` and ``alice@example.com`` are the same person.

The check runs whenever a ``user_resolver`` is wired — in every RBAC mode,
including ``off`` — not only when Google login or RBAC enforcement is on.
"""

from __future__ import annotations

import contextlib
from urllib.parse import parse_qs, urlparse

import httpx
from asgi_lifespan import LifespanManager

from conftest import (
    BASE_URL,
    VALID_TOKEN,
    authorize_to_login,
    make_pkce,
    register_client,
)
from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import build_server
from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.factory import build_in_memory_user_directory_resolver


@contextlib.asynccontextmanager
async def _login_client(*, user_resolver=None, **setting_overrides):
    """A server with api_key login only, wired to the given (optional) resolver."""
    settings = Settings(base_url=BASE_URL, **setting_overrides)
    mcp, _registry, oauth, _upstreams, _policy, _observability, _reconciler = build_server(
        identity_provider=StaticIdentityProvider({VALID_TOKEN}),
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=user_resolver,
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client.keystone_settings = settings  # type: ignore[attr-defined]
            client.keystone_oauth = oauth  # type: ignore[attr-defined]
            yield client


async def _new_txn(client: httpx.AsyncClient) -> tuple[str, str]:
    """Register a client and drive /authorize; return (txn, client_id)."""
    settings = client.keystone_settings  # type: ignore[attr-defined]
    client_id = await register_client(client)
    _verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    return txn, client_id


async def test_login_email_is_lowercased_in_token_subject():
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))

    async with _login_client(user_resolver=resolver) as client:
        oauth = client.keystone_oauth  # type: ignore[attr-defined]
        settings = client.keystone_settings  # type: ignore[attr-defined]
        client_id = await register_client(client)
        verifier, challenge = make_pkce()
        txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)

        response = await client.post(
            "/login",
            data={"txn": txn, "api_token": VALID_TOKEN, "email": "Alice@Example.COM"},
        )
        assert response.status_code == 302
        code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]

        token = await client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "http://localhost:9999/callback",
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": settings.resource_url,
            },
        )
        assert token.status_code == 200
        access_token = token.json()["access_token"]
        loaded = await oauth.load_access_token(access_token)
        assert loaded is not None
        assert loaded.subject == "alice@example.com"
        assert loaded.claims["email"] == "alice@example.com"


async def test_login_unknown_email_is_refused():
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))

    async with _login_client(user_resolver=resolver) as client:
        txn, _client_id = await _new_txn(client)

        denied = await client.post(
            "/login",
            data={"txn": txn, "api_token": VALID_TOKEN, "email": "retry@example.com"},
        )
        assert denied.status_code == 403
        assert 'name="api_token"' in denied.text
        assert "location" not in denied.headers

        # The transaction was not consumed: the same txn can be retried with
        # a known email.
        retried = await client.post(
            "/login",
            data={"txn": txn, "api_token": VALID_TOKEN, "email": "alice@example.com"},
        )
        assert retried.status_code == 302
        assert "code" in parse_qs(urlparse(retried.headers["location"]).query)


async def test_login_checks_directory_with_rbac_off():
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))

    async with _login_client(
        user_resolver=resolver,
        rbac_mode="off",
        enabled_login_methods=frozenset({"api_key"}),
        primary_login_method="api_key",
    ) as client:
        txn, _client_id = await _new_txn(client)
        denied = await client.post(
            "/login",
            data={"txn": txn, "api_token": VALID_TOKEN, "email": "unknown@example.com"},
        )
        assert denied.status_code == 403


async def test_login_blocked_email_is_refused():
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("blocked@example.com", roles=("operator",), is_blocked=True)

    async with _login_client(user_resolver=resolver) as client:
        txn, _client_id = await _new_txn(client)
        denied = await client.post(
            "/login",
            data={"txn": txn, "api_token": VALID_TOKEN, "email": "blocked@example.com"},
        )
        assert denied.status_code == 403


async def test_login_directory_unavailable_returns_503():
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))

    original_resolve = resolver.resolve
    calls = {"n": 0}

    async def flaky_resolve(email: str, *, critical: bool = False):
        calls["n"] += 1
        if calls["n"] == 1:
            raise UserDirectoryUnavailableError("directory is down", code="catalog_unavailable")
        return await original_resolve(email, critical=critical)

    resolver.resolve = flaky_resolve  # type: ignore[method-assign]

    async with _login_client(user_resolver=resolver) as client:
        txn, _client_id = await _new_txn(client)

        unavailable = await client.post(
            "/login",
            data={"txn": txn, "api_token": VALID_TOKEN, "email": "alice@example.com"},
        )
        assert unavailable.status_code == 503
        assert "location" not in unavailable.headers

        # The transaction was not consumed: once the directory recovers, the
        # same txn succeeds.
        recovered = await client.post(
            "/login",
            data={"txn": txn, "api_token": VALID_TOKEN, "email": "alice@example.com"},
        )
        assert recovered.status_code == 302
        assert "code" in parse_qs(urlparse(recovered.headers["location"]).query)


async def test_login_directory_is_not_consulted_before_token_check():
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))

    original_resolve = resolver.resolve
    calls = {"n": 0}

    async def counting_resolve(email: str, *, critical: bool = False):
        calls["n"] += 1
        return await original_resolve(email, critical=critical)

    resolver.resolve = counting_resolve  # type: ignore[method-assign]

    async with _login_client(user_resolver=resolver) as client:
        txn, _client_id = await _new_txn(client)
        response = await client.post(
            "/login",
            data={"txn": txn, "api_token": "WRONG", "email": "unknown@example.com"},
        )
        assert response.status_code == 401
        assert calls["n"] == 0


async def test_provider_without_resolver_accepts_any_email(harness):
    """Test-only path: a provider built without a resolver skips the directory check.

    The production server always wires a user_resolver (built-in users
    directory, A01's dependency on U02), so this only happens when a test
    builds the server/provider without supplying one, as ``harness`` does.
    """
    client_id = await register_client(harness.client)
    verifier, challenge = make_pkce()
    txn = await authorize_to_login(
        harness.client, client_id, challenge, harness.settings.resource_url
    )
    response = await harness.client.post(
        "/login",
        data={"txn": txn, "api_token": VALID_TOKEN, "email": "nobody@example.com"},
    )
    assert response.status_code == 302


async def test_unknown_email_counts_as_failed_login():
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("alice@example.com", roles=("operator",))

    async with _login_client(user_resolver=resolver, login_throttle_email_max=2) as client:
        for _ in range(2):
            txn, _client_id = await _new_txn(client)
            denied = await client.post(
                "/login",
                data={"txn": txn, "api_token": VALID_TOKEN, "email": "unknown@example.com"},
            )
            assert denied.status_code == 403

        txn, _client_id = await _new_txn(client)
        throttled = await client.post(
            "/login",
            data={"txn": txn, "api_token": VALID_TOKEN, "email": "unknown@example.com"},
        )
        assert throttled.status_code == 429


async def test_dev_token_login_checks_directory_in_local_profile_with_rbac_off(
    monkeypatch, tmp_path
):
    """A04 coordinator finding: a DEV-token holder must not sign in as anyone.

    With ``KEYSTONE_MCP_RBAC_MODE=off`` and Google login disabled — the
    ``local`` profile's common case — ``build_server`` used to leave
    ``user_resolver`` unset, so a DEV token let its holder sign in as *any*
    email. Here no resolver is injected and no identity provider is injected
    either: both are built automatically by ``build_server`` from settings
    alone (the built-in, migrated-but-empty users directory), exactly as the
    real server does with a DEV token configured.
    """
    from support.users_store import make_users_store

    store, _revision = await make_users_store(tmp_path)

    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    settings = Settings(
        base_url=BASE_URL,
        rbac_mode="off",
        dev_tokens="local-dev-token",
        enabled_login_methods=frozenset({"api_key"}),
        primary_login_method="api_key",
    )
    mcp, _registry, _oauth, _upstreams, _policy, _observability, _reconciler = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
        users_store=store,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            client_id = await register_client(client)
            _verifier, challenge = make_pkce()
            txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
            response = await client.post(
                "/login",
                data={
                    "txn": txn,
                    "api_token": "local-dev-token",
                    "email": "ghost@example.com",
                },
            )
            assert response.status_code == 403
