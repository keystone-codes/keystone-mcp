"""``keystone-mcp plugins`` subcommands."""

from __future__ import annotations

import argparse
import sys

from keystone_mcp.plugins import (
    LOGIN_PROVIDERS_GROUP,
    USER_DIRECTORIES_GROUP,
    PluginConflictError,
    discover,
    entry_point_label,
    is_builtin_entry,
    keystone_distribution,
)


def _cmd_plugins_list(_args: argparse.Namespace) -> int:
    errors: list[str] = []
    try:
        keystone_distribution()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    def _print_group(title: str, group: str) -> None:
        print(title)
        try:
            eps = discover(group)
        except PluginConflictError as exc:
            errors.append(str(exc))
            print(f"  (error: {exc})")
            return
        for name in sorted(eps):
            ep = eps[name]
            dist, version, target = entry_point_label(ep)
            builtin = ""
            if is_builtin_entry(group, name, ep):
                builtin = " (built-in)"
            print(f"  {name}: {dist} {version}, {target}{builtin}")

    _print_group("keystone_mcp.login_providers", LOGIN_PROVIDERS_GROUP)
    print()
    _print_group("keystone_mcp.user_directories", USER_DIRECTORIES_GROUP)

    if errors:
        for line in errors:
            print(line, file=sys.stderr)
        return 1
    return 0


def add_plugins_commands(subparsers: argparse._SubParsersAction) -> None:
    plugins = subparsers.add_parser("plugins", help="List installed plugin entry points")
    plugins_sub = plugins.add_subparsers(dest="plugins_command", required=True)
    list_cmd = plugins_sub.add_parser("list", help="Show declared login and directory plugins")
    list_cmd.set_defaults(handler=_cmd_plugins_list)
