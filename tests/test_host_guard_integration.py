"""End-to-end DNS-rebinding scenario against a real server (finding #1).

Builds the app exactly the way `server.main` does — `build_server` plus
`mcp.http_app(path=..., middleware=_http_asgi_middleware(settings))` — rather
than the bare `mcp.http_app(path=settings.http_path)` most other tests use,
since `HostGuardMiddleware` is wired through `_http_asgi_middleware`, not
`build_server` itself.

Reproduces the reviewer's scenario: a person runs the Docker demo (DEV token
`demo-token`, DCR enabled) and opens a page on a hostname an attacker
controls; the attacker rebinds that hostname's DNS to `127.0.0.1` and has the
page's own JavaScript carry on issuing requests with `Host:
rebind.attacker.test:8080`. Every route Keystone serves — the OAuth
endpoints, metadata, and the MCP transport itself — must refuse that Host;
`/healthz`/`/readyz` must keep answering regardless (a container healthcheck
or a Kubernetes probe reaches them by IP, not by the configured Host).
"""

from __future__ import annotations

import httpx
import pytest
from asgi_lifespan import LifespanManager

from conftest import BASE_URL, VALID_TOKEN, make_pkce
from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import _http_asgi_middleware, build_server

pytestmark = pytest.mark.asyncio

_ATTACKER_HOST = "rebind.attacker.test:8080"
_GOOD_HOST = "localhost:8080"


def _build_app(**settings_overrides):
    settings = Settings(base_url=BASE_URL, refresh_interval_seconds=0, **settings_overrides)
    idp = StaticIdentityProvider({VALID_TOKEN})
    mcp, *_rest = build_server(
        identity_provider=idp,
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
    )
    app = mcp.http_app(path=settings.http_path, middleware=_http_asgi_middleware(settings))
    return app, settings


async def test_rebinding_host_is_refused_on_every_route() -> None:
    app, settings = _build_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            _verifier, challenge = make_pkce()

            register = await client.post(
                "/register",
                json={
                    "redirect_uris": ["http://localhost:9999/callback"],
                    "token_endpoint_auth_method": "none",
                },
                headers={"Host": _ATTACKER_HOST},
            )
            assert register.status_code == 421, register.text

            authorize = await client.get(
                "/authorize",
                params={
                    "response_type": "code",
                    "client_id": "whatever",
                    "redirect_uri": "http://localhost:9999/callback",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "resource": f"{BASE_URL}/",
                },
                headers={"Host": _ATTACKER_HOST},
            )
            assert authorize.status_code == 421, authorize.text

            login_get = await client.get(
                "/login", params={"txn": "x"}, headers={"Host": _ATTACKER_HOST}
            )
            assert login_get.status_code == 421, login_get.text

            login_post = await client.post(
                "/login",
                data={"txn": "x", "api_token": VALID_TOKEN, "email": "user@example.com"},
                headers={"Host": _ATTACKER_HOST},
            )
            assert login_post.status_code == 421, login_post.text

            token = await client.post(
                "/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "whatever",
                    "redirect_uri": "http://localhost:9999/callback",
                    "client_id": "whatever",
                    "code_verifier": "whatever",
                    "resource": f"{BASE_URL}/",
                },
                headers={"Host": _ATTACKER_HOST},
            )
            assert token.status_code == 421, token.text

            metadata = await client.get(
                "/.well-known/oauth-authorization-server", headers={"Host": _ATTACKER_HOST}
            )
            assert metadata.status_code == 421, metadata.text

            mcp_call = await client.post(
                settings.http_path,
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                headers={
                    "Host": _ATTACKER_HOST,
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            )
            assert mcp_call.status_code == 421, mcp_call.text


async def test_correct_host_is_unaffected() -> None:
    """The same requests, with the legitimate Host, behave as before this fix."""
    app, settings = _build_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            register = await client.post(
                "/register",
                json={
                    "redirect_uris": ["http://localhost:9999/callback"],
                    "token_endpoint_auth_method": "none",
                },
                headers={"Host": _GOOD_HOST},
            )
            assert register.status_code == 201, register.text

            metadata = await client.get(
                "/.well-known/oauth-authorization-server", headers={"Host": _GOOD_HOST}
            )
            assert metadata.status_code == 200, metadata.text

            mcp_call = await client.post(
                settings.http_path,
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                headers={
                    "Host": _GOOD_HOST,
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            )
            # Unauthenticated (no Bearer token): refused for that reason, but
            # never by the Host guard.
            assert mcp_call.status_code != 421, mcp_call.text


async def test_healthz_and_readyz_answer_regardless_of_host() -> None:
    app, _settings = _build_app()
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            healthz = await client.get("/healthz", headers={"Host": "127.0.0.1:8080"})
            assert healthz.status_code == 200, healthz.text

            readyz_by_ip = await client.get("/readyz", headers={"Host": "127.0.0.1:8080"})
            assert readyz_by_ip.status_code in (200, 503), readyz_by_ip.text

            # Even a wholly unrelated Host still reaches these two routes.
            readyz_rebind = await client.get("/readyz", headers={"Host": _ATTACKER_HOST})
            assert readyz_rebind.status_code in (200, 503), readyz_rebind.text


async def test_allowed_hosts_env_extends_the_allowlist() -> None:
    app, _settings = _build_app(allowed_hosts_extra=("lb.internal",))
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE_URL
        ) as client:
            via_lb = await client.get(
                "/.well-known/oauth-authorization-server", headers={"Host": "lb.internal"}
            )
            assert via_lb.status_code == 200, via_lb.text

            still_refused = await client.get(
                "/.well-known/oauth-authorization-server", headers={"Host": _ATTACKER_HOST}
            )
            assert still_refused.status_code == 421, still_refused.text
