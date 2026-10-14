"""``keystone-mcp config check``."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import MutableMapping
from pathlib import Path

from keystone_mcp.config import (
    ConfigError,
    Settings,
    _build_settings_for_check,
    check_configuration,
)
from keystone_mcp.env_file import load_env_file
from keystone_mcp.observability.logging.redact import redact_string
from keystone_mcp.rbac.management import build_admins_report
from keystone_mcp.rbac.policy import PolicyContractError, load_policy_file
from keystone_mcp.users.cli import _format_admins_report_text
from keystone_mcp.users.db import UsersConfigError, check_users_db_url, sqlite_file_path
from keystone_mcp.users.factory import build_users_store

_EXIT_OK = 0
_EXIT_PROBLEMS = 1
_EXIT_USAGE = 2


def add_config_commands(subparsers: argparse._SubParsersAction) -> None:
    group = subparsers.add_parser(
        "config", help="Inspect configuration without starting the server"
    )
    sub = group.add_subparsers(dest="config_command", required=True)

    check_cmd = sub.add_parser(
        "check",
        help="List startup refusals and warnings for the current environment",
    )
    check_cmd.add_argument(
        "--env-file",
        default=None,
        help="Load KEYSTONE_MCP_* variables from PATH (same as KEYSTONE_MCP_ENV_FILE)",
    )
    check_cmd.add_argument(
        "--strict",
        action="store_true",
        help="Exit with an error when warnings are present",
    )
    check_cmd.add_argument(
        "--admins",
        action="store_true",
        help="Verify the built-in directory has an active full administrator",
    )
    check_cmd.set_defaults(handler=_cmd_config_check)


def _redact_line(prefix: str, message: str) -> str:
    return f"{prefix}{redact_string(message)}"


def _admins_check(settings: Settings) -> tuple[list[str], list[str]]:
    """Return (errors, info_lines) for ``--admins``."""
    errors: list[str] = []
    info: list[str] = []
    if settings.users_backend != "local":
        errors.append("users admins check requires KEYSTONE_MCP_USERS_BACKEND=local")
        return errors, info

    policy_path = settings.rbac_policy_path.strip()
    if not policy_path or not Path(policy_path).is_file():
        errors.append(f"RBAC policy is not readable: {policy_path or '(empty path)'}")
        return errors, info

    try:
        policy = load_policy_file(policy_path)
    except (PolicyContractError, OSError) as exc:
        errors.append(f"RBAC policy is not readable: {exc}")
        return errors, info

    try:
        check_users_db_url(settings.users_db_url)
    except UsersConfigError as exc:
        errors.append(str(exc))
        return errors, info

    db_path = sqlite_file_path(settings.users_db_url)
    if db_path is not None and not db_path.exists():
        errors.append("users database not found")
        return errors, info

    store = build_users_store(settings)
    try:
        people = asyncio.run(store.list_users(is_blocked=None))
        services = asyncio.run(store.list_service_accounts(is_blocked=None))
        report = build_admins_report(policy, people, services)
        for line in _format_admins_report_text(report).splitlines():
            info.append(line)
        if not report.full_administrators:
            errors.append(
                "no active full administrator; recover with "
                "'keystone-mcp users grant-admin --email …'"
            )
    except Exception as exc:  # noqa: BLE001 - operator-facing type only
        errors.append(f"users directory database is unavailable: {type(exc).__name__}")
    finally:
        store.dispose()

    return errors, info


def _cmd_config_check(args: argparse.Namespace) -> int:
    environ: dict[str, str] = dict(os.environ)
    if args.env_file is not None:
        environ["KEYSTONE_MCP_ENV_FILE"] = args.env_file

    try:
        env_result = load_env_file(environ)
    except ConfigError as exc:
        print(f"keystone-mcp: {exc}", file=sys.stderr)
        return _EXIT_USAGE

    env_file_display = str(env_result.path) if env_result.path is not None else None
    report = check_configuration(
        environ,
        env_file=env_file_display,
        env_file_ignored_forwarded=env_result.ignored_forwarded_allow_ips,
    )

    errors = list(report.errors)
    warnings = list(report.warnings)
    info_lines: list[str] = []

    if args.admins:
        settings, parse_errors, incomplete = _settings_snapshot(environ)
        if incomplete:
            errors.extend(parse_errors)
        elif settings is not None:
            admin_errors, admin_info = _admins_check(settings)
            errors.extend(admin_errors)
            info_lines.extend(admin_info)

    if env_file_display is None:
        print("env file: none")
    else:
        print(f"env file: {env_file_display}")

    for line in errors:
        print(_redact_line("ERROR   ", line))
    for line in warnings:
        print(_redact_line("WARNING ", line))
    for line in info_lines:
        print(_redact_line("INFO    ", line))

    error_count = len(errors)
    warning_count = len(warnings)
    print(
        f"config check: {error_count} error{'s' if error_count != 1 else ''}, "
        f"{warning_count} warning{'s' if warning_count != 1 else ''}"
    )

    if errors:
        return _EXIT_PROBLEMS
    if args.strict and warnings:
        return _EXIT_PROBLEMS
    return _EXIT_OK


def _settings_snapshot(
    environ: MutableMapping[str, str],
) -> tuple[Settings | None, list[str], bool]:
    """Build ``Settings`` on ``environ`` without mutating ``os.environ``."""
    return _build_settings_for_check(environ)
