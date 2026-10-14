"""``keystone-mcp oauth`` subcommands."""

from __future__ import annotations

import argparse
import asyncio
import logging
import re
import sys
from urllib.parse import urlparse

from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl
from redis.exceptions import RedisError

from keystone_mcp.auth.keystone_oauth_provider import (
    _redirect_uri_allowed,
    _register_metadata_error,
)
from keystone_mcp.auth.oauth_store import build_oauth_store, client_ttl_seconds
from keystone_mcp.config import OAUTH_CLI_VARIABLES, ConfigError, settings_for_command
from keystone_mcp.users.cli import EXIT_OK, EXIT_STORE, EXIT_USAGE

logger = logging.getLogger(__name__)

_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def add_oauth_commands(subparsers: argparse._SubParsersAction) -> None:
    group = subparsers.add_parser(
        "oauth",
        help="Manage OAuth clients when self-registration is off",
    )
    sub = group.add_subparsers(dest="oauth_command", required=True)

    register_cmd = sub.add_parser(
        "register-client",
        help="Register a public OAuth client in the shared Redis store",
    )
    register_cmd.add_argument("--client-id", required=True)
    register_cmd.add_argument(
        "--redirect-uri",
        action="append",
        required=True,
        dest="redirect_uris",
        metavar="URL",
        help="Redirect URI (repeat for multiple)",
    )
    register_cmd.add_argument(
        "--name",
        default=None,
        help="Display name (defaults to client id)",
    )
    register_cmd.set_defaults(handler=_cmd_register_client)


def _cmd_register_client(args: argparse.Namespace) -> int:
    client_id = args.client_id.strip()
    if not _CLIENT_ID_RE.fullmatch(client_id):
        print("client_id is invalid", file=sys.stderr)
        return EXIT_USAGE

    redirect_uris: list[str] = []
    for uri in args.redirect_uris:
        parsed = urlparse(uri)
        if not parsed.scheme or not parsed.hostname:
            print(
                f"redirect URI must be an absolute URL with scheme and host: {uri}", file=sys.stderr
            )
            return EXIT_USAGE
        redirect_uris.append(uri)

    client_name = (args.name if args.name is not None else client_id).strip()
    metadata_error = _register_metadata_error(
        {
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        }
    )
    if metadata_error is not None:
        print(metadata_error, file=sys.stderr)
        return EXIT_USAGE

    try:
        settings = settings_for_command(OAUTH_CLI_VARIABLES)
    except ConfigError as exc:
        print(f"keystone-mcp: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if not settings.redis_url.strip():
        print(
            "KEYSTONE_MCP_REDIS_URL is not set; the client must be written to the server's Redis",
            file=sys.stderr,
        )
        return EXIT_USAGE

    for uri in redirect_uris:
        if not _redirect_uri_allowed(
            uri,
            settings.oauth_allowed_redirect_hosts,
            settings.oauth_allowed_redirect_scheme_hosts,
        ):
            print(
                f"redirect URI not allowed by KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS: {uri}",
                file=sys.stderr,
            )
            return EXIT_USAGE

    client = OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=[AnyUrl(uri) for uri in redirect_uris],
        token_endpoint_auth_method="none",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        client_name=client_name,
    )

    store = build_oauth_store(settings)

    async def _run() -> bool:
        try:
            existed = await store.get_client(client_id) is not None
            await store.put_client(client)
            await store.touch_client(client_id)
            return existed
        finally:
            await store.aclose()

    try:
        existed = asyncio.run(_run())
    except (RedisError, OSError) as exc:
        print(f"Redis is unavailable ({type(exc).__name__})", file=sys.stderr)
        return EXIT_STORE

    verb = "updated" if existed else "registered"
    days = client_ttl_seconds(settings) // 86400
    print(f"{verb} client {client_id}")
    print(f"expires after {days} days without use; signing in renews it")

    redirect_hosts = sorted({urlparse(uri).hostname or "" for uri in redirect_uris})
    logger.info(
        "oauth client registered by CLI client_id=%s redirect_hosts=%s",
        client_id,
        redirect_hosts,
    )
    return EXIT_OK
