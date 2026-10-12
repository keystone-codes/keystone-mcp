"""Unauthenticated internal endpoints are guarded by source address.

/metrics and the live-published-names route carry no credential. Their only
guard used to be the absence of an X-Forwarded-For header, which is not a
source check at all: any caller that could reach the port and simply omitted
the header was served, and a proxy that does not add the header exposed both
endpoints to whoever could reach it. The guard is now the peer address matched
against KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS, with the header rejection kept as
an additional signal.
"""

from __future__ import annotations

import httpx
import pytest
from asgi_lifespan import LifespanManager

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import ConfigError, Settings, client_address_allowed
from keystone_mcp.rbac.catalog import LIVE_PUBLISHED_NAMES_PATH
from keystone_mcp.server import build_server
from support.login import dev_token_login

BASE_URL = "http://localhost:8080"


# ── The address matcher ─────────────────────────────────────────────────────
DEFAULT_CIDRS = ("127.0.0.1/32", "::1/128")


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_default_allowlist_admits_loopback(host: str):
    assert client_address_allowed(host, DEFAULT_CIDRS)


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.2",  # loopback range, but outside a /32
        "10.0.0.5",
        "192.168.1.1",
        "203.0.113.1",
        "::2",
        "fe80::1",
    ],
)
def test_default_allowlist_refuses_everything_else(host: str):
    assert not client_address_allowed(host, DEFAULT_CIDRS)


def test_container_network_can_be_allowed():
    """A Prometheus scraping from a sibling container is a normal deployment."""
    cidrs = ("127.0.0.1/32", "::1/128", "172.18.0.0/16")
    assert client_address_allowed("172.18.0.7", cidrs)
    assert client_address_allowed("127.0.0.1", cidrs)
    assert not client_address_allowed("172.19.0.7", cidrs)


@pytest.mark.parametrize("host", [None, "", "   ", "not-an-ip", "127.0.0.1:9000"])
def test_unknown_peer_address_is_refused(host):
    """A caller we cannot place must not reach an unauthenticated endpoint."""
    assert not client_address_allowed(host, DEFAULT_CIDRS)


def test_empty_allowlist_denies_everyone():
    assert not client_address_allowed("127.0.0.1", ())


def test_a_bare_address_is_accepted_as_a_single_host():
    monkey_cidrs = ("10.1.2.3",)
    assert client_address_allowed("10.1.2.3", monkey_cidrs)
    assert not client_address_allowed("10.1.2.4", monkey_cidrs)


def test_ipv4_address_does_not_match_an_ipv6_network():
    assert not client_address_allowed("127.0.0.1", ("::1/128",))
    assert not client_address_allowed("::1", ("127.0.0.1/32",))


# ── Parsing ─────────────────────────────────────────────────────────────────
def test_default_cidrs_are_loopback_only(monkeypatch):
    monkeypatch.delenv("KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS", raising=False)
    assert Settings().internal_allowed_cidrs == ("127.0.0.1/32", "::1/128")


def test_cidrs_parsed_from_env(monkeypatch):
    monkeypatch.setenv(
        "KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS", "127.0.0.1/32, 172.18.0.0/16 ,::1/128"
    )
    assert Settings().internal_allowed_cidrs == (
        "127.0.0.1/32",
        "172.18.0.0/16",
        "::1/128",
    )


@pytest.mark.parametrize("value", ["not-a-cidr", "127.0.0.1/33", "10.0.0.0/x", "300.1.1.1/32"])
def test_malformed_cidr_is_refused_at_startup(monkeypatch, value: str):
    monkeypatch.setenv("KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS", value)
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS"):
        Settings()


# ── Over the wire ───────────────────────────────────────────────────────────
async def _client(settings: Settings):
    mcp, *_rest = build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    return mcp.http_app(path=settings.http_path)


async def _get(settings: Settings, path: str, *, client_host: str, headers=None):
    """Issue a request that arrives from `client_host`."""
    app = await _client(settings)
    async with LifespanManager(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=(client_host, 12345)),
            base_url=BASE_URL,
        ) as client:
            return await client.get(path, headers=headers)


METRICS_SETTINGS = dict(base_url=BASE_URL, metrics_enabled=True)


async def test_healthz_is_public_and_unauthenticated():
    response = await _get(Settings(base_url=BASE_URL), "/healthz", client_host="203.0.113.1")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_metrics_served_to_an_allowed_peer():
    response = await _get(Settings(**METRICS_SETTINGS), "/metrics", client_host="127.0.0.1")
    assert response.status_code == 200
    assert "keystone_mcp_rbac_decisions_total" in response.text
    assert "keystone_mcp_tool_call_attempts_total" in response.text


@pytest.mark.parametrize("peer", ["10.0.0.5", "203.0.113.1", "127.0.0.2"])
async def test_metrics_denied_to_a_peer_outside_the_allowlist(peer: str):
    response = await _get(Settings(**METRICS_SETTINGS), "/metrics", client_host=peer)
    assert response.status_code == 403


async def test_metrics_served_to_a_configured_container_network():
    settings = Settings(
        **METRICS_SETTINGS,
        internal_allowed_cidrs=("127.0.0.1/32", "172.18.0.0/16"),
    )
    response = await _get(settings, "/metrics", client_host="172.18.0.9")
    assert response.status_code == 200


async def test_metrics_denied_when_forwarded_for_present_even_from_an_allowed_peer():
    """A request proxied from outside is not internal, whatever its peer is."""
    response = await _get(
        Settings(**METRICS_SETTINGS),
        "/metrics",
        client_host="127.0.0.1",
        headers={"X-Forwarded-For": "203.0.113.1"},
    )
    assert response.status_code == 403


# ── The introspection route is off by default ───────────────────────────────
async def test_live_published_names_is_not_registered_by_default():
    settings = Settings(base_url=BASE_URL)
    assert settings.internal_endpoints_enabled is False
    response = await _get(settings, LIVE_PUBLISHED_NAMES_PATH, client_host="127.0.0.1")
    assert response.status_code == 404


async def test_live_published_names_served_when_enabled():
    settings = Settings(base_url=BASE_URL, internal_endpoints_enabled=True)
    response = await _get(settings, LIVE_PUBLISHED_NAMES_PATH, client_host="127.0.0.1")
    assert response.status_code == 200


@pytest.mark.parametrize("peer", ["10.0.0.5", "203.0.113.1"])
async def test_live_published_names_denied_to_an_outside_peer(peer: str):
    settings = Settings(base_url=BASE_URL, internal_endpoints_enabled=True)
    response = await _get(settings, LIVE_PUBLISHED_NAMES_PATH, client_host=peer)
    assert response.status_code == 403


async def test_live_published_names_denied_when_forwarded_for_present():
    settings = Settings(base_url=BASE_URL, internal_endpoints_enabled=True)
    response = await _get(
        settings,
        LIVE_PUBLISHED_NAMES_PATH,
        client_host="127.0.0.1",
        headers={"X-Forwarded-For": "203.0.113.1"},
    )
    assert response.status_code == 403
