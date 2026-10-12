"""``keystone-mcp service-accounts`` subcommands."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from keystone_mcp.config import Settings
from keystone_mcp.rbac.policy import PolicyContractError, load_policy_file
from keystone_mcp.users.cli import _CliExit, _open_store
from keystone_mcp.users.errors import UsersError
from keystone_mcp.users.roles import normalize_roles


def add_service_accounts_commands(subparsers: argparse._SubParsersAction) -> None:
    group = subparsers.add_parser(
        "service-accounts",
        help="Manage service accounts in the built-in directory",
    )
    sub = group.add_subparsers(dest="service_accounts_command", required=True)

    add_cmd = sub.add_parser("add", help="Create a service account")
    add_cmd.add_argument("--name", required=True)
    add_cmd.add_argument("--description", default=None)
    add_cmd.add_argument("--role", action="append", dest="roles", default=[])
    add_cmd.set_defaults(handler=_cmd_add)

    list_cmd = sub.add_parser("list", help="List service accounts")
    list_cmd.add_argument("--blocked", action="store_true")
    list_cmd.set_defaults(handler=_cmd_list)

    update_cmd = sub.add_parser("update", help="Update a service account")
    update_cmd.add_argument("--name", required=True)
    update_cmd.add_argument("--description", default=None)
    update_cmd.add_argument("--role", action="append", dest="roles", default=None)
    block = update_cmd.add_mutually_exclusive_group()
    block.add_argument("--block", action="store_true")
    block.add_argument("--unblock", action="store_true")
    update_cmd.set_defaults(handler=_cmd_update)


def _policy_roles(settings: Settings) -> frozenset[str] | None:
    if not settings.rbac_enforcing:
        return None
    path = settings.rbac_policy_path
    if not path:
        return None
    try:
        policy = load_policy_file(path)
    except PolicyContractError as exc:
        print(str(exc), file=sys.stderr)
        raise _CliExit(1) from exc
    return frozenset(policy.role_names)


def _cmd_add(args: argparse.Namespace) -> int:
    settings = Settings()
    store = _open_store(settings)
    allowed = _policy_roles(settings)
    roles = normalize_roles(args.roles or [], allowed=allowed)
    try:
        mutation = asyncio.run(
            store.create_service_account(
                name=args.name,
                description=args.description,
                roles=roles,
                created_by="system:cli",
            )
        )
    except UsersError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    finally:
        store.dispose()
    print(json.dumps(mutation.account.to_dict(), indent=2, sort_keys=True))
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    settings = Settings()
    store = _open_store(settings)
    try:
        rows = asyncio.run(
            store.list_service_accounts(is_blocked=True if args.blocked else False)
        )
    except UsersError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    finally:
        store.dispose()
    payload = {"service_accounts": [row.to_dict() for row in rows], "total": len(rows)}
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _cmd_update(args: argparse.Namespace) -> int:
    settings = Settings()
    store = _open_store(settings)
    allowed = _policy_roles(settings)
    roles = None
    if args.roles is not None:
        roles = normalize_roles(args.roles, allowed=allowed)
    is_blocked = None
    if args.block:
        is_blocked = True
    elif args.unblock:
        is_blocked = False
    if args.description is None and roles is None and is_blocked is None:
        print("at least one of --description, --role, --block or --unblock is required", file=sys.stderr)
        return 1
    try:
        mutation = asyncio.run(
            store.update_service_account(
                name=args.name,
                description=args.description,
                roles=roles,
                is_blocked=is_blocked,
                actor="system:cli",
            )
        )
    except UsersError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    finally:
        store.dispose()
    print(json.dumps(mutation.account.to_dict(), indent=2, sort_keys=True))
    return 0
