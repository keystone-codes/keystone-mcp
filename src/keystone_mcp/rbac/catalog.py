"""Live published-tool catalog with multiplicity.

Source is ``Route.published_name`` of routes with ``mode="live"``. No static
tool-name list is on this path: the catalog is whatever the router discovered.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import urllib.error
import urllib.request
from collections import Counter
from collections.abc import Sequence
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from keystone_mcp.router.registry import RouterRegistry

LIVE_PUBLISHED_NAMES_PATH = "/internal/live-published-names"

UNIQUENESS_REFUSAL_TEMPLATE = (
    "live published name {name} occurs {count} times; uniqueness requires exactly once"
)


class DuplicateLivePublishedNameError(ValueError):
    """Raised when a live published name occurs more than once."""


def collect_live_tool_names(registry: RouterRegistry) -> tuple[str, ...]:
    """Return client-visible published names for live routes, with multiplicity.

    Each live route contributes one entry of route.published_name. A set cannot
    store multiplicity; this sequence can.
    """
    return tuple(route.published_name for route in registry.routes.values() if route.mode == "live")


def live_published_name_counts(names: Sequence[str]) -> dict[str, int]:
    return dict(Counter(names))


def format_live_published_names(names: Sequence[str]) -> str:
    """One published name per line. Empty sequence yields an empty string."""
    if not names:
        return ""
    return "\n".join(names) + "\n"


def parse_live_published_names(body: str) -> tuple[str, ...]:
    if not body:
        return ()
    return tuple(line for line in body.splitlines() if line != "")


def uniqueness_refusal_message(name: str, count: int) -> str:
    return UNIQUENESS_REFUSAL_TEMPLATE.format(name=name, count=count)


def _is_loopback_host(host: str) -> bool:
    lowered = host.strip().lower().rstrip(".")
    if lowered == "localhost" or lowered.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(lowered).is_loopback
    except ValueError:
        return False


def assert_loopback_live_catalog_url(url: str) -> None:
    """Refuse live-name fetches that are not explicit loopback HTTP to the internal route."""
    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme != "http":
        raise ValueError(f"live catalog URL must use http (got scheme {scheme or 'missing'!r})")
    if parsed.username or parsed.password:
        raise ValueError("live catalog URL must not include userinfo")
    host = parsed.hostname
    if not host or not _is_loopback_host(host):
        raise ValueError("live catalog URL host must be loopback (127.0.0.1, ::1, or localhost)")
    path = parsed.path or ""
    if path != LIVE_PUBLISHED_NAMES_PATH:
        raise ValueError(
            f"live catalog URL path must be {LIVE_PUBLISHED_NAMES_PATH} (got {path!r})"
        )


def assert_unique_live_published_names(names: Sequence[str]) -> None:
    """Refuse when any published name occurs more than once.

    Not a process startup gate: an external consumer must be able to observe a
    running process that still publishes one name twice.
    """
    for name, count in sorted(Counter(names).items()):
        if count > 1:
            raise DuplicateLivePublishedNameError(uniqueness_refusal_message(name, count))


def fetch_live_published_names(
    *,
    host: str = "127.0.0.1",
    port: int | None = None,
    timeout: float = 5.0,
) -> tuple[str, ...]:
    """Read the live sequence from the running process over loopback HTTP.

    Consumer call (inside the container, outside the MCP process):

        python -m keystone_mcp.rbac.catalog
    """
    if port is None:
        from keystone_mcp.config import Settings

        port = Settings().port
    if not _is_loopback_host(host):
        raise ValueError("live catalog fetch host must be loopback (127.0.0.1, ::1, or localhost)")
    url = f"http://{host}:{port}{LIVE_PUBLISHED_NAMES_PATH}"
    assert_loopback_live_catalog_url(url)
    with urllib.request.urlopen(url, timeout=timeout) as response:
        body = response.read().decode()
    return parse_live_published_names(body)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=("Dump live published names with multiplicity from the running router.")
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument(
        "--check-unique",
        action="store_true",
        help="Refuse (exit 1) if any name occurs more than once.",
    )
    args = parser.parse_args(argv)
    try:
        names = fetch_live_published_names(host=args.host, port=args.port)
    except (urllib.error.URLError, OSError) as exc:
        print(f"live published names dump unreachable: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(format_live_published_names(names))
    if args.check_unique:
        try:
            assert_unique_live_published_names(names)
        except DuplicateLivePublishedNameError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
