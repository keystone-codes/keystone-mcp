"""Keystone-MCP command-line utilities."""

from __future__ import annotations

import argparse
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Sequence

import yaml

from keystone_mcp.config import Settings
from keystone_mcp.env_file import load_env_file
from keystone_mcp.observability.logging import configure_logging
from keystone_mcp.plugins_cli import add_plugins_commands
from keystone_mcp.rbac.catalog import (
    DuplicateLivePublishedNameError,
    assert_loopback_live_catalog_url,
    assert_unique_live_published_names,
    parse_live_published_names,
)
from keystone_mcp.rbac.catalog_snapshot import (
    EMPTY_CATALOG_SNAPSHOT,
    CatalogSnapshot,
    CatalogSnapshotError,
    load_catalog_snapshot,
)
from keystone_mcp.rbac.loader import assert_live_catalog_validation
from keystone_mcp.rbac.policy import (
    CatalogValidationResult,
    PolicyContractError,
    load_policy_file,
    validate_policy_against_catalog,
)
from keystone_mcp.users.api_keys_cli import add_api_keys_commands
from keystone_mcp.users.cli import add_users_commands
from keystone_mcp.users.service_accounts_cli import add_service_accounts_commands

_EXIT_VALIDATION = 1
_EXIT_LIVE_URL = 3

_CATALOG_TIERS = frozenset({"active", "reserved", "wip"})


class LiveNamesFetchError(OSError):
    """Failed to read live published names from a URL."""


def _load_snapshot(path: Path | None) -> CatalogSnapshot:
    if path is None:
        return EMPTY_CATALOG_SNAPSHOT
    return load_catalog_snapshot(path)


def _load_live_names(
    *,
    live_file: Path | None,
    live_url: str | None,
) -> tuple[str, ...]:
    if live_file is not None:
        try:
            body = live_file.read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyContractError(f"live catalog file unreadable: {exc}") from exc
        return parse_live_published_names(body)
    if live_url is not None:
        try:
            assert_loopback_live_catalog_url(live_url)
        except ValueError as exc:
            raise PolicyContractError(str(exc)) from exc
        try:
            with urllib.request.urlopen(live_url, timeout=10.0) as response:
                body = response.read().decode()
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise LiveNamesFetchError(f"live catalog URL unreachable: {exc}") from exc
        return parse_live_published_names(body)
    return ()


def _catalog_parent_parser() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--policy", type=Path, required=True, help="RBAC policy YAML path")
    parent.add_argument(
        "--snapshot",
        type=Path,
        default=None,
        help="Optional catalog snapshot YAML (active / reserved / wip)",
    )
    live = parent.add_mutually_exclusive_group()
    live.add_argument(
        "--live-file",
        type=Path,
        default=None,
        help="Newline-delimited live published names",
    )
    live.add_argument(
        "--live-url",
        default=None,
        metavar="URL",
        help="Fetch live names from URL (localhost CI only)",
    )
    return parent


def _format_diff_summary(
    live_names: Sequence[str],
    result: CatalogValidationResult,
) -> str:
    live_set = frozenset(live_names)
    only_live_unreachable = sorted(result.unreachable_tools & live_set)
    lines: list[str] = []
    lines.append("Only in live (unreachable by any role):")
    if only_live_unreachable:
        lines.extend(f"  - {name}" for name in only_live_unreachable)
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("Unmatched allow patterns:")
    if result.unmatched_allow_patterns:
        lines.extend(f"  - {pattern}" for pattern in result.unmatched_allow_patterns)
    else:
        lines.append("  (none)")
    return "\n".join(lines) + "\n"


def _cmd_catalog_validate(args: argparse.Namespace) -> int:
    try:
        policy = load_policy_file(args.policy)
        snapshot = _load_snapshot(args.snapshot)
        live_names = _load_live_names(live_file=args.live_file, live_url=args.live_url)
        assert_unique_live_published_names(live_names)
        result = assert_live_catalog_validation(policy, live_names, catalog_snapshot=snapshot)
        if args.strict_unreachable and result.unreachable_tools:
            print(
                "unreachable live tools (strict-unreachable): "
                + ", ".join(sorted(result.unreachable_tools)),
                file=sys.stderr,
            )
            return _EXIT_VALIDATION
    except LiveNamesFetchError as exc:
        print(str(exc), file=sys.stderr)
        return _EXIT_LIVE_URL
    except (PolicyContractError, CatalogSnapshotError, DuplicateLivePublishedNameError) as exc:
        print(str(exc), file=sys.stderr)
        return _EXIT_VALIDATION
    return 0


def _cmd_catalog_diff(args: argparse.Namespace) -> int:
    try:
        policy = load_policy_file(args.policy)
        snapshot = _load_snapshot(args.snapshot)
        live_names = _load_live_names(live_file=args.live_file, live_url=args.live_url)
        live_set = frozenset(live_names)
        result = validate_policy_against_catalog(
            policy,
            live_set | snapshot.active,
            reserved_tool_names=snapshot.reserved,
            wip_tool_names=snapshot.wip,
        )
        sys.stdout.write(_format_diff_summary(live_names, result))
    except LiveNamesFetchError as exc:
        print(str(exc), file=sys.stderr)
        return _EXIT_LIVE_URL
    except (PolicyContractError, CatalogSnapshotError) as exc:
        print(str(exc), file=sys.stderr)
        return _EXIT_VALIDATION
    return 0


def _cmd_catalog_export(args: argparse.Namespace) -> int:
    tier = args.tier
    if tier not in _CATALOG_TIERS:
        print(
            f"unsupported tier {tier!r} (allowed: {', '.join(sorted(_CATALOG_TIERS))})",
            file=sys.stderr,
        )
        return _EXIT_VALIDATION
    try:
        names = _load_live_names(live_file=args.live_file, live_url=None)
    except PolicyContractError as exc:
        print(str(exc), file=sys.stderr)
        return _EXIT_VALIDATION
    payload = {tier: sorted(frozenset(names))}
    sys.stdout.write(yaml.safe_dump(payload, sort_keys=False, default_flow_style=False))
    return 0


def _cmd_serve(_args: argparse.Namespace) -> int:
    # Imported lazily (and module-qualified, not "from ... import main") so
    # that `keystone-mcp serve` and `python -m keystone_mcp.server` always
    # call the same function, and tests can monkeypatch
    # `keystone_mcp.server.main` directly.
    import keystone_mcp.server as server_module

    server_module.main()
    return 0


def _cmd_upstream_validate(path: Path) -> int:
    from keystone_mcp.config import _env_bool
    from keystone_mcp.upstream_registry.load import read_registry_document
    from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy
    from keystone_mcp.upstream_registry.validate import validate_upstream_registry

    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 1
    policy = UpstreamSecurityPolicy(
        allow_insecure_http=_env_bool("KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP", False),
        egress_allow_private=_env_bool("KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE", False),
    )
    try:
        document = read_registry_document(path)
        messages = validate_upstream_registry(document, policy=policy)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if messages:
        for message in messages:
            print(message, file=sys.stderr)
        return 1
    print(f"ok: {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    load_env_file()
    configure_logging(Settings())
    parser = argparse.ArgumentParser(prog="keystone-mcp")
    subparsers = parser.add_subparsers(dest="command", required=True)

    catalog = subparsers.add_parser("catalog", help="RBAC catalog registry (policy vs live tools)")
    catalog_sub = catalog.add_subparsers(dest="catalog_command", required=True)
    parent = _catalog_parent_parser()

    validate = catalog_sub.add_parser(
        "validate",
        parents=[parent],
        help="Validate policy against live catalog and optional snapshot",
    )
    validate.add_argument(
        "--strict-unreachable",
        action="store_true",
        help="Fail when tools are unreachable by every role (normally a warning only)",
    )
    validate.set_defaults(handler=_cmd_catalog_validate)

    diff = catalog_sub.add_parser(
        "diff",
        parents=[parent],
        help="Print only-live unreachable tools and unmatched allow patterns",
    )
    diff.set_defaults(handler=_cmd_catalog_diff)

    export = catalog_sub.add_parser(
        "export",
        help="Emit a catalog snapshot YAML snippet from a live name list",
    )
    export.add_argument("--live-file", type=Path, required=True)
    export.add_argument(
        "--tier",
        choices=sorted(_CATALOG_TIERS),
        default="active",
        help="Snapshot section to populate (default: active)",
    )
    export.set_defaults(handler=_cmd_catalog_export)

    upstream = subparsers.add_parser("upstream", help="Upstream registry utilities")
    upstream_sub = upstream.add_subparsers(dest="upstream_command", required=True)

    upstream_validate = upstream_sub.add_parser(
        "validate",
        help="Validate an upstream registry file",
    )
    upstream_validate.add_argument(
        "--path",
        required=True,
        type=Path,
        help="Path to YAML or JSON upstream registry (schema_version 1)",
    )
    upstream_validate.set_defaults(handler=lambda args: _cmd_upstream_validate(args.path))

    serve = subparsers.add_parser("serve", help="Start the Keystone-MCP server")
    serve.set_defaults(handler=_cmd_serve)

    add_users_commands(subparsers)
    add_api_keys_commands(subparsers)
    add_service_accounts_commands(subparsers)
    add_plugins_commands(subparsers)

    args = parser.parse_args(argv)
    if args.command == "catalog":
        return args.handler(args)
    if args.command == "upstream":
        return args.handler(args)
    if args.command == "serve":
        return args.handler(args)
    if args.command == "users":
        return args.handler(args)
    if args.command == "keys":
        return args.handler(args)
    if args.command == "service-accounts":
        return args.handler(args)
    if args.command == "plugins":
        return args.handler(args)
    parser.error(f"unknown command: {args.command}")
    return _EXIT_VALIDATION


if __name__ == "__main__":
    raise SystemExit(main())
