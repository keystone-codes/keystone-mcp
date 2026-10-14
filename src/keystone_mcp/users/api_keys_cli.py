"""``keystone-mcp keys`` subcommands."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from keystone_mcp.auth.oauth_store import build_shared_auth_stores
from keystone_mcp.auth.sessions import SessionRevoker
from keystone_mcp.user_directory.types import subject_type_of
from keystone_mcp.users.cli import _CliExit, _open_store, _settings_for_users_cli
from keystone_mcp.users.errors import UsersError


def add_api_keys_commands(subparsers: argparse._SubParsersAction) -> None:
    group = subparsers.add_parser("keys", help="Manage API keys in the built-in directory")
    sub = group.add_subparsers(dest="keys_command", required=True)

    issue_cmd = sub.add_parser("issue", help="Issue an API key (shown once)")
    issue_cmd.add_argument("--subject", required=True)
    issue_cmd.add_argument("--label", default=None)
    expiry = issue_cmd.add_mutually_exclusive_group()
    expiry.add_argument("--days", type=int, default=90)
    expiry.add_argument("--no-expiry", action="store_true")
    issue_cmd.set_defaults(handler=_cmd_issue)

    list_cmd = sub.add_parser("list", help="List API keys without secrets")
    list_cmd.add_argument("--subject", default=None)
    list_cmd.add_argument("--all", action="store_true", help="Include revoked keys")
    list_cmd.set_defaults(handler=_cmd_list)

    revoke_cmd = sub.add_parser("revoke", help="Revoke an API key")
    revoke_cmd.add_argument("--key-id", required=True)
    revoke_cmd.set_defaults(handler=_cmd_revoke)


def _cmd_issue(args: argparse.Namespace) -> int:
    try:
        settings = _settings_for_users_cli()
    except _CliExit as exc:
        return exc.code
    store = None
    expires_in_days = None if args.no_expiry else args.days
    try:
        store = _open_store(settings)
        issued = asyncio.run(
            store.issue_api_key(
                subject=args.subject,
                label=args.label,
                expires_in_days=expires_in_days,
                created_by="system:cli",
            )
        )
    except _CliExit as exc:
        return exc.code
    except UsersError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    finally:
        if store is not None:
            store.dispose()
    payload = issued.record.to_dict()
    payload["key"] = issued.key
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    try:
        settings = _settings_for_users_cli()
    except _CliExit as exc:
        return exc.code
    store = None
    try:
        store = _open_store(settings)
        rows = asyncio.run(
            store.list_api_keys(subject=args.subject, include_revoked=bool(args.all))
        )
    except _CliExit as exc:
        return exc.code
    except UsersError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    finally:
        if store is not None:
            store.dispose()
    payload = {"api_keys": [row.to_dict() for row in rows], "total": len(rows)}
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _revoke_key_sessions(settings, record) -> int:
    if subject_type_of(record.subject) != "human":
        return 0
    if not settings.redis_url.strip():
        print(
            "sessions not revoked: KEYSTONE_MCP_REDIS_URL is not set",
            file=sys.stderr,
        )
        return 0

    async def _run() -> int:
        oauth_store, login_store = build_shared_auth_stores(settings)
        revoker = SessionRevoker(oauth_store, login_store)
        try:
            return await revoker.revoke_api_key_sessions(record.subject, record.key_id)
        finally:
            await oauth_store.aclose()

    return asyncio.run(_run())


def _cmd_revoke(args: argparse.Namespace) -> int:
    try:
        settings = _settings_for_users_cli()
    except _CliExit as exc:
        return exc.code
    store = None
    try:
        store = _open_store(settings)
        record, _changed = asyncio.run(store.revoke_api_key(key_id=args.key_id, actor="system:cli"))
    except _CliExit as exc:
        return exc.code
    except UsersError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    finally:
        if store is not None:
            store.dispose()
    payload = record.to_dict()
    payload["revoked_tokens"] = _revoke_key_sessions(settings, record)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0
