"""`HostGuardMiddleware` and `config.effective_allowed_hosts` (finding #1, DNS rebinding).

A demo deployment (``docker-compose.demo.yml``, DEV tokens, DCR enabled)
binds its HTTP port with no Host/Origin check by default: fastmcp 3.4.4's own
guard (``http_host_origin_protection``) defaults to off, and even turned on
cannot exempt ``/healthz``/``/readyz`` (which a container healthcheck or a
Kubernetes probe reaches by an address that cannot be enumerated ahead of
time). An attacker who gets a victim to open a page on a hostname they
control can rebind its DNS to ``127.0.0.1`` after the page loads and have the
page's own JavaScript reach `/register`, `/authorize`, `POST /login` (with a
DEV token), `/token`, then call `users_*` — all with `Host:
<attacker-controlled-name>:<port>`.

These tests cover the unit-level pieces directly (`_parse_host_port`,
`HostGuardMiddleware` wrapping a bare Starlette app, `effective_allowed_hosts`)
and, in `test_host_guard_integration.py`, the full attack scenario against a
real server assembled the way `server.main` assembles one.
"""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from keystone_mcp.config import Settings, effective_allowed_hosts
from keystone_mcp.http.host_guard import HostGuardMiddleware, _parse_host_port

# ── _parse_host_port ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", ("example.com", None)),
        ("example.com:8080", ("example.com", 8080)),
        ("127.0.0.1", ("127.0.0.1", None)),
        ("127.0.0.1:8080", ("127.0.0.1", 8080)),
        ("::1", ("::1", None)),  # bare IPv6 literal: no way to separate a port
        ("[::1]", ("::1", None)),
        ("[::1]:8080", ("::1", 8080)),
        ("2001:db8::1", ("2001:db8::1", None)),
        ("[2001:db8::1]:443", ("2001:db8::1", 443)),
        ("", ("", None)),
        ("EXAMPLE.COM:8080", ("example.com", 8080)),  # lower-cased
    ],
)
def test_parse_host_port(value: str, expected: tuple[str, int | None]) -> None:
    assert _parse_host_port(value) == expected


# ── HostGuardMiddleware ───────────────────────────────────────────────────────


async def _ok(_request):
    return PlainTextResponse("ok")


def _guarded_app(allowed_hosts: tuple[str, ...]) -> HostGuardMiddleware:
    base = Starlette(
        routes=[
            Route("/hello", _ok),
            Route("/healthz", _ok),
            Route("/readyz", _ok),
        ]
    )
    return HostGuardMiddleware(base, allowed_hosts=allowed_hosts)


def test_allowed_host_passes() -> None:
    app = _guarded_app(("example.com:8080",))
    with TestClient(app, base_url="http://example.com:8080") as client:
        response = client.get("/hello", headers={"Host": "example.com:8080"})
    assert response.status_code == 200


def test_disallowed_host_is_refused_with_421() -> None:
    app = _guarded_app(("example.com:8080",))
    with TestClient(app, base_url="http://example.com:8080") as client:
        response = client.get("/hello", headers={"Host": "rebind.attacker.test:8080"})
    assert response.status_code == 421
    assert "rebind.attacker.test" not in response.text


def test_bare_allowlist_entry_matches_any_port() -> None:
    app = _guarded_app(("lb.internal",))
    with TestClient(app, base_url="http://lb.internal") as client:
        ok_default = client.get("/hello", headers={"Host": "lb.internal"})
        ok_other_port = client.get("/hello", headers={"Host": "lb.internal:9999"})
    assert ok_default.status_code == 200
    assert ok_other_port.status_code == 200


def test_exact_allowlist_entry_does_not_match_a_different_port() -> None:
    app = _guarded_app(("example.com:8080",))
    with TestClient(app, base_url="http://example.com:9090") as client:
        response = client.get("/hello", headers={"Host": "example.com:9090"})
    assert response.status_code == 421


def test_healthz_and_readyz_bypass_the_host_check() -> None:
    app = _guarded_app(("example.com:8080",))
    with TestClient(app, base_url="http://example.com:8080") as client:
        healthz = client.get("/healthz", headers={"Host": "127.0.0.1:8080"})
        readyz = client.get("/readyz", headers={"Host": "198.51.100.7:8080"})
    assert healthz.status_code == 200
    assert readyz.status_code == 200


def test_matching_origin_passes() -> None:
    app = _guarded_app(("example.com:8080",))
    with TestClient(app, base_url="http://example.com:8080") as client:
        response = client.get(
            "/hello",
            headers={"Host": "example.com:8080", "Origin": "http://example.com:8080"},
        )
    assert response.status_code == 200


def test_mismatched_origin_is_refused_with_400() -> None:
    app = _guarded_app(("example.com:8080",))
    with TestClient(app, base_url="http://example.com:8080") as client:
        response = client.get(
            "/hello",
            headers={"Host": "example.com:8080", "Origin": "http://evil.example"},
        )
    assert response.status_code == 400


def test_absent_origin_is_not_checked() -> None:
    """Only `Host` is mandatory; a non-browser client sends no `Origin` at all."""
    app = _guarded_app(("example.com:8080",))
    with TestClient(app, base_url="http://example.com:8080") as client:
        response = client.get("/hello", headers={"Host": "example.com:8080"})
    assert response.status_code == 200


def test_ipv6_loopback_entry_matches_bracketed_host_header() -> None:
    # The middleware reads the `Host` header, not the connection URL, so the
    # client's own `base_url` stays a plain one here — Starlette's TestClient
    # (via httpx) does not parse an IPv6 literal in *its* base_url correctly,
    # which is a test-harness limitation, not something this middleware does.
    app = _guarded_app(("[::1]:8080",))
    with TestClient(app, base_url="http://testserver") as client:
        response = client.get("/hello", headers={"Host": "[::1]:8080"})
    assert response.status_code == 200


# ── config.effective_allowed_hosts ───────────────────────────────────────────


def test_effective_allowed_hosts_pins_base_host_and_adds_loopback_aliases() -> None:
    settings = Settings(base_url="http://localhost:18084")
    hosts = effective_allowed_hosts(settings)
    assert "localhost" in hosts  # bare: any port
    assert "localhost:18084" in hosts
    assert "127.0.0.1:18084" in hosts
    assert "[::1]:18084" in hosts


def test_effective_allowed_hosts_does_not_add_loopback_aliases_for_a_public_host() -> None:
    settings = Settings(base_url="https://mcp-stage.keystone.codes")
    hosts = effective_allowed_hosts(settings)
    assert "mcp-stage.keystone.codes" in hosts
    assert "mcp-stage.keystone.codes:443" in hosts
    assert not any("127.0.0.1" in h for h in hosts)
    assert not any("localhost" in h for h in hosts)


def test_effective_allowed_hosts_includes_extra_names(monkeypatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_ALLOWED_HOSTS", "lb.internal,edge.example.com:8443")
    settings = Settings(base_url="https://mcp.example.com")
    hosts = effective_allowed_hosts(settings)
    assert "lb.internal" in hosts
    assert "edge.example.com:8443" in hosts


def test_allowed_hosts_env_parsing_refuses_scheme_or_path(monkeypatch) -> None:
    from keystone_mcp.config import ConfigError

    monkeypatch.setenv("KEYSTONE_MCP_ALLOWED_HOSTS", "https://lb.internal")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_ALLOWED_HOSTS"):
        Settings(base_url="https://mcp.example.com")

    monkeypatch.setenv("KEYSTONE_MCP_ALLOWED_HOSTS", "lb.internal/path")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_ALLOWED_HOSTS"):
        Settings(base_url="https://mcp.example.com")
