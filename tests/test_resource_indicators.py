"""RFC 8707 resource-indicator handling: equivalence and the strict-mode gate."""

from __future__ import annotations

import time

import httpx
import pytest
from asgi_lifespan import LifespanManager
from mcp.server.auth.provider import AccessToken

from conftest import BASE_URL as HTTP_BASE_URL
from conftest import VALID_TOKEN, obtain_access_token, refresh_access_token
from keystone_mcp.auth.keystone_oauth_provider import KeystoneOAuthProvider
from keystone_mcp.auth.login_pending_store import InMemoryLoginPendingStore
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings, resources_equivalent
from keystone_mcp.server import build_server
from support.login import dev_token_login

BASE_URL = "https://mcp.example.com"


# ── Equivalence ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("left", "right"),
    [
        # Trailing slash on the root and on a path.
        ("https://mcp.example.com", "https://mcp.example.com/"),
        ("https://mcp.example.com/mcp", "https://mcp.example.com/mcp/"),
        # Host case is not significant (RFC 3986).
        ("https://MCP.Example.COM/mcp", "https://mcp.example.com/mcp"),
        ("https://mcp.example.com/mcp", "https://MCP.EXAMPLE.COM/mcp"),
        # Scheme case is not significant.
        ("HTTPS://mcp.example.com/mcp", "https://mcp.example.com/mcp"),
        # A scheme's default port stated explicitly means the same thing.
        ("https://mcp.example.com:443/mcp", "https://mcp.example.com/mcp"),
        ("http://mcp.example.com:80/mcp", "http://mcp.example.com/mcp"),
        ("https://mcp.example.com:443", "https://mcp.example.com/"),
        # All of the above at once.
        ("HTTPS://MCP.Example.com:443/mcp/", "https://mcp.example.com/mcp"),
    ],
)
def test_equivalent_resource_indicators(left: str, right: str):
    assert resources_equivalent(left, right)
    assert resources_equivalent(right, left)


@pytest.mark.parametrize(
    ("left", "right"),
    [
        # A different host, path or scheme is a different resource.
        ("https://mcp.example.com/mcp", "https://evil.example.com/mcp"),
        ("https://mcp.example.com/mcp", "https://mcp.example.com/other"),
        ("https://mcp.example.com/mcp", "http://mcp.example.com/mcp"),
        # A non-default port is significant.
        ("https://mcp.example.com:8443/mcp", "https://mcp.example.com/mcp"),
        ("https://mcp.example.com:443/mcp", "https://mcp.example.com:8443/mcp"),
        # http's default port is not https's.
        ("https://mcp.example.com:80/mcp", "https://mcp.example.com/mcp"),
        # The path is case-sensitive.
        ("https://mcp.example.com/MCP", "https://mcp.example.com/mcp"),
    ],
)
def test_distinct_resource_indicators(left: str, right: str):
    assert not resources_equivalent(left, right)
    assert not resources_equivalent(right, left)


# ── verify_token and the strict-mode gate ───────────────────────────────────
def _provider(**overrides) -> tuple[KeystoneOAuthProvider, InMemoryOAuthStore, Settings]:
    settings = Settings(base_url=BASE_URL, **overrides)
    store = InMemoryOAuthStore()
    provider = KeystoneOAuthProvider(
        settings,
        store,
        InMemoryLoginPendingStore(),
        login_providers=[
            dev_token_login(
                {"token"} if isinstance({"token"}, set) else set({"token"}) if False else {"token"}
            )
        ],
    )
    return provider, store, settings


async def _seed(store: InMemoryOAuthStore, token: str, resource: str | None) -> None:
    await store.put_access_token(
        AccessToken(
            token=token,
            client_id="client-1",
            scopes=[],
            expires_at=int(time.time()) + 600,
            resource=resource,
            subject="user@example.com",
            claims={"email": "user@example.com"},
        )
    )


def test_require_resource_indicator_defaults_to_false():
    assert Settings().require_resource_indicator is False


async def test_unbound_token_is_accepted_by_default():
    provider, store, _settings = _provider()
    await _seed(store, "km_at_unbound", None)
    assert await provider.verify_token("km_at_unbound") is not None


async def test_unbound_token_is_refused_in_strict_mode():
    """A token naming no audience cannot be shown to belong to this resource."""
    provider, store, _settings = _provider(require_resource_indicator=True)
    await _seed(store, "km_at_unbound", None)
    assert await provider.verify_token("km_at_unbound") is None
    # It is still loadable, so the refusal is the audience check, not absence.
    assert await provider.load_access_token("km_at_unbound") is not None


async def test_strict_mode_accepts_a_correctly_bound_token():
    provider, store, settings = _provider(require_resource_indicator=True)
    await _seed(store, "km_at_bound", settings.resource_url)
    assert await provider.verify_token("km_at_bound") is not None


@pytest.mark.parametrize("strict", [False, True])
async def test_foreign_audience_is_refused_in_both_modes(strict: bool):
    provider, store, _settings = _provider(require_resource_indicator=strict)
    await _seed(store, "km_at_foreign", "https://evil.example.com/mcp")
    assert await provider.verify_token("km_at_foreign") is None


@pytest.mark.parametrize("strict", [False, True])
@pytest.mark.parametrize(
    "resource",
    [
        "https://mcp.example.com",
        "https://mcp.example.com/",
        "https://MCP.Example.com",
        "https://mcp.example.com:443",
        "HTTPS://mcp.example.com:443/",
    ],
)
async def test_equivalent_spellings_of_our_own_resource_are_accepted(strict: bool, resource: str):
    """Case and a default port must not make a legitimate token look foreign."""
    provider, store, _settings = _provider(require_resource_indicator=strict)
    await _seed(store, "km_at_variant", resource)
    assert await provider.verify_token("km_at_variant") is not None


# ── Refresh must keep the resource binding ────────────────────────────
async def _http_app(**settings_overrides):
    """Build a KeystoneOAuthProvider behind a live ASGI app with custom settings."""
    settings = Settings(base_url=HTTP_BASE_URL, **settings_overrides)
    _login = dev_token_login({VALID_TOKEN})
    store = InMemoryOAuthStore()
    mcp, _registry, oauth, _upstreams, _policy_manager, _observability, _reconciler = build_server(
        login_providers=[_login], settings=settings, oauth_store=store
    )
    app = mcp.http_app(path=settings.http_path)
    return app, oauth, settings


async def test_refreshed_access_token_keeps_resource(harness):
    """A refreshed access token must keep the resource bound at first issuance."""
    res = await obtain_access_token(harness.client, harness.settings.resource_url)
    assert res["status"] == 200, res

    refreshed = await refresh_access_token(
        harness.client,
        res["client_id"],
        res["body"]["refresh_token"],
        harness.settings.resource_url,
    )
    assert refreshed["status"] == 200, refreshed

    access = await harness.oauth.load_access_token(refreshed["body"]["access_token"])
    assert access is not None
    assert access.resource is not None
    assert resources_equivalent(access.resource, harness.settings.resource_url)


async def test_refreshed_token_accepted_when_resource_indicator_required():
    """In strict mode, a refreshed token must still pass the audience check."""
    app, oauth, settings = await _http_app(require_resource_indicator=True)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=HTTP_BASE_URL
        ) as client:
            res = await obtain_access_token(client, settings.resource_url)
            assert res["status"] == 200, res

            refreshed = await refresh_access_token(
                client,
                res["client_id"],
                res["body"]["refresh_token"],
                settings.resource_url,
            )
            assert refreshed["status"] == 200, refreshed

            verified = await oauth.verify_token(refreshed["body"]["access_token"])
            assert verified is not None


async def test_legacy_plain_marker_is_read():
    """A marker written before this change (a bare string) still parses."""
    provider, _store, _settings = _provider()
    await provider._pending_store.put("refresh_auth", "km_rt_legacy", "google", 3600)

    meta = await provider._read_refresh_meta("km_rt_legacy")

    assert meta is not None
    assert meta.auth_method == "google"
    assert meta.resource is None
    assert meta.interactive is True
