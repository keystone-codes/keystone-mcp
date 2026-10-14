"""Standalone HTTP healthcheck used by the container `HEALTHCHECK` instruction.

A dedicated module avoids shell quoting inside the exec-form `HEALTHCHECK`
(`CMD ["python", "-m", "keystone_mcp.healthcheck", ...]`), works without
`curl` in the runtime image, and reads the port from the same
`KEYSTONE_MCP_PORT` environment variable the server itself uses.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

from keystone_mcp.config import ConfigError
from keystone_mcp.env_file import load_env_file

DEFAULT_PATH = "/healthz"
DEFAULT_PORT = "8080"
TIMEOUT_SECONDS = 4


def _healthcheck_host(host: str) -> str:
    value = host.strip()
    if not value or value == "0.0.0.0":
        return "127.0.0.1"
    if value == "::":
        return "::1"
    return value


def _format_url_host(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def main(argv: list[str] | None = None) -> int:
    """Request `path` on the local server and report its health.

    Returns 0 when the server answers with HTTP 200, 1 otherwise (non-200
    status, connection failure, or timeout). The reason is printed to stderr
    on failure.
    """
    args = sys.argv[1:] if argv is None else argv
    path = args[0] if args else DEFAULT_PATH

    environ = dict(os.environ)
    try:
        load_env_file(environ)
    except ConfigError as exc:
        print(f"healthcheck failed: {exc}", file=sys.stderr)
        return 1

    port = environ.get("KEYSTONE_MCP_PORT", DEFAULT_PORT)
    host = _healthcheck_host(environ.get("KEYSTONE_MCP_HOST", "127.0.0.1"))
    url = f"http://{_format_url_host(host)}:{port}{path}"

    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:
            status = response.status
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"healthcheck failed: {url} unreachable: {exc}", file=sys.stderr)
        return 1

    if status != 200:
        print(f"healthcheck failed: {url} returned status {status}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
