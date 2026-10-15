"""SEC-20…SEC-25: hostile users-directory and login-provider behaviour."""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.exceptions import ToolError

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import ConfigError, Settings
from keystone_mcp.server import build_server
from keystone_mcp.user_directory.cache import ResolutionCache
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker
from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.factory import (
    build_in_memory_user_directory_resolver,
    validate_directory_capabilities,
)
from keystone_mcp.user_directory.http import HttpUserDirectory
from keystone_mcp.user_directory.resolver import CachedUserDirectoryResolver
from keystone_mcp.user_directory.revision import InMemoryRevisionReader
from keystone_mcp.user_directory.types import UserResolveResult
from security.conftest import BASE_URL, DEV_TOKEN, MEMBER_EMAIL
from security.helpers import obtain_bearer_token
from security.hostile_plugins import (
    HostileCapabilityDirectory,
    HostileFormLoginProvider,
    HostileRedirectLoginProvider,
    HostileResolveDirectory,
)
from support.fake_login import FakeRedirectProvider
from support.login import dev_token_login

pytestmark = pytest.mark.security


def _resolver_with(directory) -> CachedUserDirectoryResolver:
    return CachedUserDirectoryResolver(
        directory,
        revision_reader=InMemoryRevisionReader(),
        cache=ResolutionCache(allow_ttl_seconds=60, deny_ttl_seconds=30),
        circuit_breaker=CircuitBreaker(failure_threshold=2, recovery_seconds=30),
    )


@pytest.mark.asyncio
async def test_hostile_directory_exists_string_does_not_grant_access():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"exists": "false", "roles": ["administrator"], "is_blocked": False},
        )

    directory = HttpUserDirectory(
        base_url="http://users.test",
        service_token="t",
        timeout_seconds=1.0,
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://users.test"
        ),
    )
    resolver = _resolver_with(directory)
    with pytest.raises(UserDirectoryUnavailableError):
        await resolver.resolve("user@example.com")
    await directory.aclose()


@pytest.mark.asyncio
async def test_hostile_directory_wildcard_and_unknown_roles_denied_at_enforce(
    attacker_stand,
):
    directory = HostileResolveDirectory(
        result=UserResolveResult(exists=True, roles=("not_in_policy",), is_blocked=False)
    )
    resolver = _resolver_with(directory)
    settings = attacker_stand.settings
    mcp, registry, *_rest = build_server(
        settings=settings,
        oauth_store=attacker_stand.oauth_store,
        user_resolver=resolver,
        login_providers=[dev_token_login({attacker_stand.dev_token})],
        register_builtin_catalog=True,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        token = await obtain_bearer_token(attacker_stand, email=MEMBER_EMAIL)
        transport = attacker_stand.mcp_transport(token)
        async with Client(transport) as client:
            with pytest.raises(ToolError, match="access denied|denied"):
                await client.call_tool("hello_greet", {"name": "x"})


@pytest.mark.asyncio
async def test_hostile_directory_blocked_user_denied(attacker_stand):
    directory = HostileResolveDirectory(
        result=UserResolveResult(exists=True, roles=("member",), is_blocked=True)
    )
    resolver = _resolver_with(directory)
    settings = attacker_stand.settings
    mcp, *_rest = build_server(
        settings=settings,
        oauth_store=attacker_stand.oauth_store,
        user_resolver=resolver,
        login_providers=[dev_token_login({attacker_stand.dev_token})],
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL, follow_redirects=False
        ) as client:
            from security.helpers import pkce_pair

            verifier, challenge = pkce_pair()
            reg = await client.post(
                "/register",
                json={
                    "redirect_uris": ["http://127.0.0.1:9999/callback"],
                    "token_endpoint_auth_method": "none",
                },
            )
            client_id = reg.json()["client_id"]
            auth = await client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": "http://127.0.0.1:9999/callback",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "state": "s",
                    "resource": settings.resource_url,
                },
            )
            txn = parse_qs(urlparse(auth.headers["location"]).query)["txn"][0]
            login = await client.post(
                "/login",
                data={"txn": txn, "api_token": attacker_stand.dev_token, "email": MEMBER_EMAIL},
            )
            assert login.status_code in (403, 400, 503)


@pytest.mark.asyncio
async def test_hostile_directory_non_directory_error_trips_breaker():
    directory = HostileResolveDirectory(behavior="connection_error")
    resolver = _resolver_with(directory)
    for _ in range(2):
        with pytest.raises(UserDirectoryUnavailableError):
            await resolver.resolve("user@example.com")
    with pytest.raises(UserDirectoryUnavailableError) as exc_info:
        await resolver.resolve("user@example.com")
    assert exc_info.value.code == "circuit_open"


@pytest.mark.asyncio
async def test_hostile_directory_hang_does_not_kill_healthz():
    directory = HostileResolveDirectory(behavior="hang")
    resolver = _resolver_with(directory)
    settings = Settings(base_url=BASE_URL, rbac_mode="enforce")
    mcp, *_rest = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
        login_providers=[dev_token_login({DEV_TOKEN})],
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)

    async def attack():
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(resolver.resolve("user@example.com"), timeout=1.0)

    async with LifespanManager(app):
        from security.hostile_upstream import poll_healthz_while

        await poll_healthz_while(app, attack(), max_latency=1.0)


@pytest.mark.parametrize("capability", ["admin", "identity_binding"])
def test_hostile_directory_missing_capability_methods_refused(capability: str):
    with pytest.raises(ConfigError):
        validate_directory_capabilities(HostileCapabilityDirectory(capability))


def test_hostile_directory_delete_capability_without_methods_refused():
    with pytest.raises(ConfigError):
        validate_directory_capabilities(HostileCapabilityDirectory("delete"))


@pytest.mark.asyncio
async def test_hostile_http_directory_email_mismatch_refused():
    requested = "bob@example.com"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params.get("email") == requested
        return httpx.Response(
            200,
            json={
                "exists": True,
                "email": "alice@example.com",
                "roles": ["member"],
                "is_blocked": False,
            },
        )

    directory = HttpUserDirectory(
        base_url="http://users.test",
        service_token="t",
        timeout_seconds=1.0,
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://users.test"
        ),
    )
    result = await directory.resolve_user(requested)
    assert result.exists is False
    await directory.aclose()


@pytest.mark.asyncio
async def test_hostile_login_svc_robot_subject_refused(caplog):
    provider = HostileFormLoginProvider(email="svc:robot")
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed("svc:robot", roles=("robot",))
    settings = Settings(base_url=BASE_URL, dev_tokens=DEV_TOKEN)
    mcp, *_rest = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
        login_providers=[provider],
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            response = await client.post(
                "/login",
                data={"email": "human@example.com", "token": "x"},
            )
            assert response.status_code in (400, 401, 403, 404, 422)
            assert "Traceback" not in response.text


@pytest.mark.asyncio
async def test_hostile_login_oversized_name_and_runtime_error():
    provider = HostileFormLoginProvider(
        email="user@example.com", full_name="n" * (1024 * 1024), behavior="raise_runtime"
    )
    settings = Settings(base_url=BASE_URL)
    mcp, *_rest = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        login_providers=[provider],
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            response = await client.post("/login", data={"email": "user@example.com", "token": "z"})
            assert response.status_code in (400, 401, 403, 404, 422, 500, 503)
            assert "Traceback" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["javascript:alert(1)", "data:text/html,hi"])
async def test_hostile_redirect_provider_dangerous_url_refused(url: str):
    provider = HostileRedirectLoginProvider(redirect_url=url, name="evilredirect")
    settings = Settings(
        base_url=BASE_URL,
        enabled_login_methods=frozenset({"evilredirect"}),
    )
    mcp, *_rest = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        login_providers=[provider],
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL, follow_redirects=False
        ) as client:
            response = await client.post(
                "/login/evilredirect",
                data={"txn": "t", "csrf": "c"},
                headers={"Cookie": "km_login_csrf=c", "Origin": BASE_URL},
            )
            assert response.status_code in (400, 403, 404)
            location = response.headers.get("location", "")
            assert not location.startswith("javascript:")
            assert not location.startswith("data:")


@pytest.mark.asyncio
async def test_hostile_login_wrong_provider_name_refused(caplog):
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed(MEMBER_EMAIL, roles=("member",))
    provider = FakeRedirectProvider("acme", reported_provider="google")
    settings = Settings(base_url=BASE_URL)
    mcp, *_rest = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=resolver,
        login_providers=[provider],
        register_builtin_catalog=False,
    )
    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        with caplog.at_level(logging.WARNING, logger="keystone_mcp.auth.keystone_oauth_provider"):
            response = await httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url=BASE_URL
            ).get(
                "/login/acme/callback",
                params={"state": "s", "code": "x", "email": MEMBER_EMAIL},
            )
    assert response.status_code == 400
