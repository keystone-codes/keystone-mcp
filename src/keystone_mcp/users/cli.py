"""``keystone-mcp users`` subcommands: ``grant-admin``, ``import``, and directory ops.

Both commands open the configured users directory directly — the same
``KEYSTONE_MCP_USERS_DB_URL`` a running server uses — rather than going
through a running server's ``users_*`` tools. That matters because the one
situation ``grant-admin`` exists for is an administrator who can no longer
call those tools at all (blocked, demoted, or without a working mailbox), and
``import`` is typically run once, before a server backed by the built-in
directory has even started — though it can be run again later to resync (see
``keystone_mcp.users.service.upsert_imported_user`` for exactly what a second
run does to changes made locally since the first).

Neither command reads or writes any new ``KEYSTONE_MCP_*`` setting: the
import source token is a ``--token`` flag or an interactive prompt, never a
persisted environment variable, so it never lingers in a deployment's
configuration after the one-time migration is done.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import sys

import httpx

from keystone_mcp.auth.oauth_store import build_shared_auth_stores
from keystone_mcp.auth.sessions import SessionRevoker
from keystone_mcp.config import USERS_CLI_VARIABLES, ConfigError, Settings, settings_for_command
from keystone_mcp.rbac.policy import PolicyContractError, load_policy_file
from keystone_mcp.users.db import (
    UsersConfigError,
    check_users_db_url,
    describe_db_url,
    sqlite_file_path,
)
from keystone_mcp.users.errors import InvalidUserFieldError, LastAdministratorError, UsersError
from keystone_mcp.users.factory import build_users_store
from keystone_mcp.users.importer import ImportSourceError, fetch_source_users
from keystone_mcp.users.store import MutationResult, UsersStore

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_IMPORT_SOURCE = 2
EXIT_STORE = 3


class _CliExit(Exception):
    """Raised by a setup helper to unwind straight to an exit code."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


def _settings_for_users_cli() -> Settings:
    try:
        return settings_for_command(USERS_CLI_VARIABLES)
    except ConfigError as exc:
        print(f"keystone-mcp: {exc}", file=sys.stderr)
        raise _CliExit(EXIT_USAGE)


def _source_transport() -> httpx.BaseTransport | None:
    """The transport used for the import source's HTTP client.

    Always ``None`` (the real network) outside tests; ``tests/test_users_cli.py``
    monkeypatches this function to return an ``httpx.MockTransport``.
    """
    return None


def _open_store(settings: Settings, *, allow_create: bool = True) -> UsersStore:
    """Validate configuration, print the target database, and migrate it.

    Raises ``_CliExit`` for every refusal; callers catch it and return
    ``exc.code`` without printing anything further.

    ``allow_create=False`` refuses to proceed when the configured SQLite file
    does not exist yet instead of silently creating one. ``grant-admin`` asks
    for this unless ``--create`` was passed: the default
    ``KEYSTONE_MCP_USERS_DB_URL`` is a path relative to the current working
    directory, and a break-glass recovery command run from the wrong
    directory (not the server's) would otherwise create an unrelated, empty
    database and write the new administrator into it — silently, since that
    looks exactly like the documented "works on a brand-new database" case.
    ``import`` leaves this at the default: writing into a fresh database is
    its normal, expected use.
    """
    if settings.users_backend != "local":
        print(
            "users commands work only with KEYSTONE_MCP_USERS_BACKEND=local",
            file=sys.stderr,
        )
        raise _CliExit(EXIT_USAGE)

    try:
        check_users_db_url(settings.users_db_url)
    except UsersConfigError as exc:
        print(str(exc), file=sys.stderr)
        raise _CliExit(EXIT_USAGE) from exc

    # Printed before any database error can appear: an operator must always be
    # able to see which database this command is about to touch, even when it
    # turns out to be unreachable. An absolute path for SQLite so a wrong
    # working directory is obvious at a glance (see describe_db_url).
    print(f"Users directory: {describe_db_url(settings.users_db_url)}", file=sys.stderr)

    db_path = sqlite_file_path(settings.users_db_url)
    if db_path is not None and not db_path.exists():
        if not allow_create:
            print(
                f"no users database at {db_path}; refusing to create one "
                "implicitly: pass --create if this is really a fresh "
                "installation, or check KEYSTONE_MCP_USERS_DB_URL and the "
                "current working directory",
                file=sys.stderr,
            )
            raise _CliExit(EXIT_USAGE)
        print(f"a new, empty users database will be created at {db_path}", file=sys.stderr)

    if not settings.redis_url.strip():
        print(
            "KEYSTONE_MCP_REDIS_URL is not set: running servers will see the "
            "change after the cache TTL",
            file=sys.stderr,
        )

    store = build_users_store(settings)
    try:
        asyncio.run(store.migrate())
    except UsersError as exc:
        print(str(exc), file=sys.stderr)
        raise _CliExit(EXIT_STORE) from exc
    except Exception as exc:  # noqa: BLE001 - reported by type only, never the password
        print(f"users directory database is unavailable: {type(exc).__name__}", file=sys.stderr)
        raise _CliExit(EXIT_STORE) from exc
    return store


_CLI_ACTOR = "system:cli"


def _revoke_sessions(settings: Settings, email: str) -> int:
    async def _run() -> int:
        oauth_store, login_store = build_shared_auth_stores(settings)
        revoker = SessionRevoker(oauth_store, login_store)
        try:
            return await revoker.revoke_subject(email)
        finally:
            await oauth_store.aclose()

    return asyncio.run(_run())


def _describe_grant_admin(before: MutationResult) -> str:
    was_admin = "administrator" in before.roles_before
    was_blocked = before.blocked_before

    if before.created:
        return f"Created administrator: {before.user.email}"
    if not was_admin and was_blocked:
        return f"Granted administrator and unblocked: {before.user.email}"
    if not was_admin:
        return f"Granted administrator: {before.user.email}"
    if was_blocked:
        return f"Unblocked administrator: {before.user.email}"
    return f"Administrator already active: {before.user.email}"


def _cmd_grant_admin(args: argparse.Namespace) -> int:
    try:
        settings = _settings_for_users_cli()
    except _CliExit as exc:
        return exc.code
    try:
        store = _open_store(settings, allow_create=args.create)
    except _CliExit as exc:
        return exc.code

    try:
        email = args.email
        if not email:
            email = input("Administrator email: ").strip()
        if not email:
            print("an email is required", file=sys.stderr)
            return EXIT_USAGE

        try:
            result = asyncio.run(store.ensure_administrator(email, created_by="system:cli"))
        except InvalidUserFieldError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USAGE
        except UsersError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_STORE

        print(_describe_grant_admin(result))
        return EXIT_OK
    finally:
        store.dispose()


def _cmd_block(args: argparse.Namespace) -> int:
    try:
        settings = _settings_for_users_cli()
    except _CliExit as exc:
        return exc.code
    try:
        store = _open_store(settings)
    except _CliExit as exc:
        return exc.code

    email = (args.email or "").strip()
    if not email:
        print("an email is required", file=sys.stderr)
        return EXIT_USAGE

    try:
        try:
            result = asyncio.run(
                store.set_blocked(email=email, blocked=True, actor_email=_CLI_ACTOR)
            )
        except InvalidUserFieldError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USAGE
        except LastAdministratorError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USAGE
        except UsersError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_STORE

        revoked = 0
        if settings.redis_url.strip():
            revoked = _revoke_sessions(settings, email)
        else:
            print("sessions not revoked: KEYSTONE_MCP_REDIS_URL is not set", file=sys.stderr)

        if result.blocked_before:
            print(f"Already blocked {email}; revoked {revoked} token(s)")
        else:
            print(f"Blocked {email}; revoked {revoked} token(s)")
        return EXIT_OK
    finally:
        store.dispose()


def _cmd_unblock(args: argparse.Namespace) -> int:
    try:
        settings = _settings_for_users_cli()
    except _CliExit as exc:
        return exc.code
    try:
        store = _open_store(settings)
    except _CliExit as exc:
        return exc.code

    email = (args.email or "").strip()
    if not email:
        print("an email is required", file=sys.stderr)
        return EXIT_USAGE

    try:
        try:
            asyncio.run(store.set_blocked(email=email, blocked=False, actor_email=_CLI_ACTOR))
        except InvalidUserFieldError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USAGE
        except UsersError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_STORE

        print(f"Unblocked {email}")
        return EXIT_OK
    finally:
        store.dispose()


def _cmd_logout(args: argparse.Namespace) -> int:
    try:
        settings = _settings_for_users_cli()
    except _CliExit as exc:
        return exc.code
    if not settings.redis_url.strip():
        print("KEYSTONE_MCP_REDIS_URL is not set", file=sys.stderr)
        return EXIT_USAGE

    try:
        store = _open_store(settings)
    except _CliExit as exc:
        return exc.code

    email = (args.email or "").strip()
    if not email:
        print("an email is required", file=sys.stderr)
        return EXIT_USAGE

    try:
        revoked = _revoke_sessions(settings, email)
        print(f"Revoked {revoked} token(s) for {email}")
        return EXIT_OK
    finally:
        store.dispose()


def _cmd_import(args: argparse.Namespace) -> int:
    try:
        settings = _settings_for_users_cli()
    except _CliExit as exc:
        return exc.code

    policy_path = args.policy or settings.rbac_policy_path
    if not policy_path:
        print(
            "a policy file is required to filter roles (--policy or KEYSTONE_MCP_RBAC_POLICY_PATH)",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        policy = load_policy_file(policy_path)
    except PolicyContractError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE
    allowed_roles = policy.role_names

    token = args.token
    if not token:
        token = getpass.getpass("Source directory token: ")
    if not token:
        print("a source directory token is required", file=sys.stderr)
        return EXIT_USAGE

    try:
        users = fetch_source_users(
            args.from_url,
            token,
            transport=_source_transport(),
        )
    except ImportSourceError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_IMPORT_SOURCE

    try:
        store = _open_store(settings)
    except _CliExit as exc:
        return exc.code

    try:
        try:
            outcomes = asyncio.run(
                store.import_users(users, allowed_roles=allowed_roles, dry_run=args.dry_run)
            )
        except UsersError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_STORE

        created = sum(1 for outcome in outcomes if outcome.status == "created")
        updated = sum(1 for outcome in outcomes if outcome.status == "updated")
        unchanged = sum(1 for outcome in outcomes if outcome.status == "unchanged")
        invalid = [outcome for outcome in outcomes if outcome.status == "invalid"]
        skipped_role_count = 0
        for outcome in outcomes:
            for role in outcome.skipped_roles:
                skipped_role_count += 1
                logger.warning(
                    "role not in policy; skipped",
                    extra={"email": outcome.email, "role": role},
                )
                print(
                    f"skipped role '{role}' for {outcome.email}: not in policy",
                    file=sys.stderr,
                )
        for outcome in invalid:
            logger.warning(
                "invalid source record; skipped",
                extra={"email": outcome.email, "reason": outcome.invalid_reason},
            )
            print(
                f"skipped invalid record {outcome.email}: {outcome.invalid_reason}",
                file=sys.stderr,
            )

        # Every way a re-run can silently undo something done locally through
        # users_* since the last import: lifting a block, re-applying one,
        # granting/revoking 'administrator', or dropping any other locally
        # granted role the source does not report (see upsert_imported_user's
        # docstring). All four are the same risk to an operator deciding
        # whether to re-run import against a directory people have already
        # been managed in locally, so they share one count.
        admin_or_block_changes = sum(
            1
            for outcome in outcomes
            if outcome.status == "updated"
            and (
                outcome.block_lifted
                or outcome.block_reapplied
                or outcome.administrator_changed
                or outcome.roles_revoked
            )
        )

        revoked_sessions = 0
        if not args.dry_run and settings.redis_url.strip():
            for outcome in outcomes:
                if outcome.status == "updated" and outcome.block_reapplied:
                    revoked_sessions += _revoke_sessions(settings, outcome.email)

        summary = (
            f"created={created} updated={updated} unchanged={unchanged} "
            f"skipped_roles={skipped_role_count} skipped_invalid={len(invalid)} "
            f"admin_or_block_changes={admin_or_block_changes} "
            f"revoked_sessions={revoked_sessions}"
        )
        if args.dry_run:
            summary += " (dry run, nothing written)"
        print(summary)
        if admin_or_block_changes:
            print(
                f"{admin_or_block_changes} existing user(s) will have a block lifted or "
                "re-applied, 'administrator' granted or revoked, or another locally "
                "granted role revoked, to match the source (the source is "
                "authoritative on every run, including this one)",
                file=sys.stderr,
            )

        if not args.dry_run:
            active_admins = asyncio.run(store.count_active_administrators())
            if active_admins == 0:
                print(
                    "no active administrator after import; run "
                    "'keystone-mcp users grant-admin --email ...'",
                    file=sys.stderr,
                )

        return EXIT_OK
    finally:
        store.dispose()


def add_users_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register the ``users`` command group on the top-level CLI parser."""
    users = subparsers.add_parser("users", help="Manage the built-in users directory")
    users_sub = users.add_subparsers(dest="users_command", required=True)

    grant_admin = users_sub.add_parser(
        "grant-admin",
        help="Emergency access recovery: grant administrator and lift any block",
        description=(
            "Create the account if missing, grant it the 'administrator' role, "
            "and clear any block. Run this on the server host or inside the "
            "server container when no administrator can sign in. Example: "
            "keystone-mcp users grant-admin --email admin@example.com"
        ),
    )
    grant_admin.add_argument(
        "--email",
        default=None,
        help="Administrator email; prompted interactively if omitted",
    )
    grant_admin.add_argument(
        "--create",
        action="store_true",
        help=(
            "Allow creating a brand-new, empty users database if "
            "KEYSTONE_MCP_USERS_DB_URL does not point at an existing SQLite "
            "file yet (refused otherwise, to catch a command run from the "
            "wrong directory)"
        ),
    )
    grant_admin.set_defaults(handler=_cmd_grant_admin)

    import_cmd = users_sub.add_parser(
        "import",
        help="Copy users from an external (legacy) users directory service",
        description=(
            "Read every user from an external users directory and write them "
            "into the built-in one. Running it again is safe in the sense "
            "that it will not corrupt data or crash, but the source is "
            "authoritative on every run: a person already imported is "
            "overwritten to match the source again, which can lift a block "
            "or re-apply one, grant or revoke 'administrator', made locally "
            "(through users_*) since the last import, and drops any other "
            "role granted locally that the source does not have. Use "
            "--dry-run first and read 'admin_or_block_changes' in its "
            "output before re-running against a directory people have "
            "already been managed in locally. Example: keystone-mcp users "
            "import --from-url https://old-directory.internal "
            "--policy config/rbac-policy.yaml"
        ),
    )
    import_cmd.add_argument(
        "--from-url",
        required=True,
        metavar="URL",
        help="Base URL of the external users directory (http:// or https://)",
    )
    import_cmd.add_argument(
        "--token",
        default=None,
        help="Bearer token for the external directory; prompted if omitted "
        "(prefer the prompt: a flag value stays in shell history)",
    )
    import_cmd.add_argument(
        "--policy",
        default=None,
        help="RBAC policy YAML path; defaults to KEYSTONE_MCP_RBAC_POLICY_PATH",
    )
    import_cmd.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without writing anything",
    )
    import_cmd.set_defaults(handler=_cmd_import)

    block_cmd = users_sub.add_parser(
        "block",
        help="Block a person and revoke their OAuth sessions",
    )
    block_cmd.add_argument("--email", required=True, help="Email of the person to block")
    block_cmd.set_defaults(handler=_cmd_block)

    unblock_cmd = users_sub.add_parser(
        "unblock",
        help="Lift a block without restoring old OAuth sessions",
    )
    unblock_cmd.add_argument("--email", required=True, help="Email of the person to unblock")
    unblock_cmd.set_defaults(handler=_cmd_unblock)

    logout_cmd = users_sub.add_parser(
        "logout",
        help="Revoke every OAuth session for a person without blocking them",
    )
    logout_cmd.add_argument("--email", required=True, help="Email of the person to sign out")
    logout_cmd.set_defaults(handler=_cmd_logout)
