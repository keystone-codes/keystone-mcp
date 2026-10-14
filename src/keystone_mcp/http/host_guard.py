"""ASGI middleware refusing a request whose ``Host``/``Origin`` is not allowed.

Closes a DNS-rebinding gap (finding #1, second review): fastmcp 3.4.4 ships a
``Host``/``Origin`` guard (``fastmcp.server.http.HostOriginGuardMiddleware``,
``http_host_origin_protection`` in ``FastMCPSettings``) but it defaults to
off, and even enabled it validates every route uniformly — there is no way to
exempt ``/healthz``/``/readyz`` from it, which a container healthcheck or a
Kubernetes probe reaches by IP (``127.0.0.1``, or a pod IP that cannot be
enumerated ahead of time) rather than by the configured ``Host``. This module
is Keystone's own guard instead: applied to every route including the OAuth
endpoints (``/register``, ``/authorize``, ``/login``, ``/token``, ``/revoke``,
``/.well-known/*``) and ``/mcp``, with the two health endpoints carved out.

Without it, an attacker who gets a victim to open a page on a hostname they
control can rebind that hostname's DNS to ``127.0.0.1`` (or an internal
address) after the page loads, then have the page's own JavaScript issue
requests that the browser still addresses with ``Host: <attacker's
hostname>`` — reaching Keystone's loopback-bound HTTP port from inside the
victim's own browser, past any network-level isolation. See
``docs/security-model.md`` for the full scenario and the demo reproduction.
"""

from __future__ import annotations

import ipaddress
import logging
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

# Docker HEALTHCHECK (`keystone_mcp.healthcheck`, scripts/smoke_image.sh) and
# a Kubernetes liveness/readiness probe both reach this process by a source
# address that cannot be put on an allowlist ahead of time: 127.0.0.1 inside
# the container, or the pod's own IP, assigned at pod start. Both endpoints
# answer with only a coarse status and no secret, so excluding them from the
# Host/Origin check entirely is safe — see docs/security-model.md.
_PROBE_PATHS = frozenset({"/healthz", "/readyz"})


def _parse_host_port(value: str) -> tuple[str, int | None]:
    """Split ``host``, ``host:port``, ``[ipv6]`` or ``[ipv6]:port`` into ``(host, port)``.

    A bare IPv6 literal with no brackets (``::1``, two or more colons) is
    recognized as a host with no port — there is no way to separate a port
    from an unbracketed IPv6 address, so the whole thing must be the host.
    Anything with exactly one colon is ``host:port`` (covers an IPv4 address
    or a name); the port is kept only when it actually parses as one.
    """
    value = value.strip().lower()
    if not value:
        return "", None
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return value, None  # malformed; treat the whole thing as the host
        host = value[1:end]
        rest = value[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, None
    if value.count(":") >= 2:
        return value, None  # bare IPv6 literal, no brackets, so no port either
    if ":" in value:
        host, _, port_str = value.rpartition(":")
        if port_str.isdigit():
            return host, int(port_str)
        return value, None
    return value, None


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def host_allowlist_sets(
    allowed_hosts: tuple[str, ...],
) -> tuple[frozenset[str], frozenset[tuple[str, int]]]:
    """Build the host sets used by :func:`host_allowed` from an allowlist."""
    any_port: set[str] = set()
    exact: set[tuple[str, int]] = set()
    for entry in allowed_hosts:
        host, port = _parse_host_port(entry)
        if not host:
            continue
        if port is None:
            any_port.add(host)
        else:
            exact.add((host, port))
    return frozenset(any_port), frozenset(exact)


def host_allowed(
    value: str,
    *,
    any_port: frozenset[str],
    exact: frozenset[tuple[str, int]],
    allow_ip_literal: bool = False,
) -> bool:
    """Whether ``value`` (a ``Host`` or ``Origin`` host part) is on the allowlist."""
    host, port = _parse_host_port(value)
    if not host:
        return False
    if allow_ip_literal and _is_ip_literal(host):
        return True
    if host in any_port:
        return True
    return port is not None and (host, port) in exact


def origin_header_allowed(origin_header: str, allowed_hosts: tuple[str, ...]) -> bool:
    """Whether an ``Origin`` header value is on *allowed_hosts* (same rule as ``Host``)."""
    parsed = urlsplit(origin_header)
    host = parsed.hostname or ""
    if not host:
        return False
    bracketed = f"[{host}]" if ":" in host else host
    value = f"{bracketed}:{parsed.port}" if parsed.port is not None else bracketed
    any_port, exact = host_allowlist_sets(allowed_hosts)
    return host_allowed(
        value,
        any_port=any_port,
        exact=exact,
        allow_ip_literal=False,
    )


def cross_site_origin_refusal(
    request: Request, allowed_hosts: tuple[str, ...]
) -> Response | None:
    """Return a 400 response when *request* carries a disallowed ``Origin``, else ``None``."""
    origin_header = request.headers.get("origin")
    if origin_header == "null":
        origin_header = None
    if origin_header and not origin_header_allowed(origin_header, allowed_hosts):
        logger.warning("refused request: Origin %r is not allowed", origin_header)
        return Response(status_code=400, content="Forbidden Origin")
    return None


class HostGuardMiddleware:
    """Refuse an HTTP request whose ``Host`` (and, if present, ``Origin``) is not allowed.

    *allowed_hosts* entries come from ``config.effective_allowed_hosts``: each
    is either a bare host (allowed on any port) or ``host:port`` (that exact
    pair only). ``Host``/``Origin`` headers are matched the same way: an
    incoming value with no port matches only a bare (any-port) allowlist
    entry for that host, never an entry pinned to a specific port, since a
    client that omits the port is not asserting which one it means.

    A ``Host`` mismatch is refused with ``421 Misdirected Request`` (RFC
    7540 §9.1.2 — this request was sent to a server not configured to answer
    for it); an ``Origin`` mismatch (checked only when the header is
    present) with ``400``. Neither response carries any detail beyond the
    status line.
    """

    def __init__(
        self,
        app: ASGIApp,
        allowed_hosts: tuple[str, ...],
        *,
        internal_paths: tuple[str, ...] = (),
        internal_prefixes: tuple[str, ...] = (),
    ) -> None:
        self.app = app
        self._allowed_hosts = allowed_hosts
        self._internal_paths = frozenset(internal_paths)
        self._internal_prefixes = internal_prefixes
        self._any_port, self._exact = host_allowlist_sets(allowed_hosts)

    def _is_allowed(self, value: str, *, allow_ip_literal: bool) -> bool:
        return host_allowed(
            value,
            any_port=self._any_port,
            exact=self._exact,
            allow_ip_literal=allow_ip_literal,
        )

    def _path_allows_ip_literal_host(self, path: str) -> bool:
        if path in self._internal_paths:
            return True
        return any(path.startswith(prefix) for prefix in self._internal_prefixes)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path in _PROBE_PATHS:
            await self.app(scope, receive, send)
            return

        allow_ip_literal = self._path_allows_ip_literal_host(path)

        request = Request(scope, receive)
        host_header = request.headers.get("host", "")
        if not self._is_allowed(host_header, allow_ip_literal=allow_ip_literal):
            logger.warning("refused request: Host %r is not allowed", host_header)
            response = Response(status_code=421, content="Misdirected Request")
            await response(scope, receive, send)
            return

        refusal = cross_site_origin_refusal(request, self._allowed_hosts)
        if refusal is not None:
            await refusal(scope, receive, send)
            return

        await self.app(scope, receive, send)
