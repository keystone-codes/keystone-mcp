"""Keystone-MCP command-line utilities."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Sequence

import yaml

from keystone_mcp.auth.oauth_cli import add_oauth_commands
from keystone_mcp.config import (
    OAUTH_CLI_VARIABLES,
    USERS_CLI_VARIABLES,
    ConfigError,
    settings_for_command,
)
from keystone_mcp.config_check_cli import add_config_commands
from keystone_mcp.env_file import EnvFileResult, load_env_file
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

if TYPE_CHECKING:
    from keystone_mcp.upstream_registry.validate import UpstreamProblem

_EXIT_VALIDATION = 1
_EXIT_LIVE_URL = 3

_CATALOG_TIERS = frozenset({"active", "reserved", "wip"})

#: ``--json`` schema version for ``catalog validate`` and ``upstream validate``
#: (frozen since 0.6.0; see docs/compatibility.md). Each command's own document
#: shape is versioned independently, but both start at 1.
_JSON_SCHEMA_VERSION = 1


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


def _duplicate_live_names(names: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted(name for name, count in Counter(names).items() if count > 1))


def _catalog_problem(code: str, message: str) -> dict[str, str | None]:
    """One ``{code, entry, field, message}`` problem for ``catalog validate --json``.

    ``entry``/``field`` are always ``null``: unlike an upstream registry entry,
    a catalog problem is never about one field of one object.
    """
    return {"code": code, "entry": None, "field": None, "message": message}


def _classify_catalog_exception(exc: Exception) -> str:
    if isinstance(exc, DuplicateLivePublishedNameError):
        return "duplicate_live_name"
    if isinstance(exc, CatalogSnapshotError):
        return "snapshot_invalid"
    return "policy_invalid"


def _emit_catalog_json(
    *,
    ok: bool,
    unmatched_allow_patterns: Sequence[str],
    unreachable_tools: Sequence[str],
    duplicate_live_names: Sequence[str],
    problems: Sequence[dict[str, str | None]],
) -> None:
    payload = {
        "schema_version": _JSON_SCHEMA_VERSION,
        "ok": ok,
        "unmatched_allow_patterns": sorted(unmatched_allow_patterns),
        "unreachable_tools": sorted(unreachable_tools),
        "duplicate_live_names": sorted(duplicate_live_names),
        "problems": list(problems),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


def _cmd_catalog_validate(args: argparse.Namespace) -> int:
    as_json: bool = getattr(args, "json", False)
    unmatched_allow_patterns: Sequence[str] = ()
    unreachable_tools: Sequence[str] = ()
    duplicate_live_names: tuple[str, ...] = ()
    problems: list[dict[str, str | None]] = []
    exit_code = 0

    try:
        policy = load_policy_file(args.policy)
        snapshot = _load_snapshot(args.snapshot)
        live_names = _load_live_names(live_file=args.live_file, live_url=args.live_url)
        duplicate_live_names = _duplicate_live_names(live_names)
        assert_unique_live_published_names(live_names)

        # Computed directly (not only via assert_live_catalog_validation below) so
        # unmatched_allow_patterns/unreachable_tools are captured for --json even
        # when that call raises on unmatched allow patterns (P06/S4 errors).
        live_set = frozenset(live_names)
        precheck_result = validate_policy_against_catalog(
            policy,
            live_set | snapshot.active,
            reserved_tool_names=snapshot.reserved,
            wip_tool_names=snapshot.wip,
        )
        unmatched_allow_patterns = precheck_result.unmatched_allow_patterns
        unreachable_tools = tuple(precheck_result.unreachable_tools)

        result = assert_live_catalog_validation(policy, live_names, catalog_snapshot=snapshot)
        if args.strict_unreachable and result.unreachable_tools:
            message = "unreachable live tools (strict-unreachable): " + ", ".join(
                sorted(result.unreachable_tools)
            )
            if not as_json:
                print(message, file=sys.stderr)
            problems.append(_catalog_problem("unreachable_tools_strict", message))
            exit_code = _EXIT_VALIDATION
    except LiveNamesFetchError as exc:
        if not as_json:
            print(str(exc), file=sys.stderr)
        problems.append(_catalog_problem("live_url_unreachable", str(exc)))
        exit_code = _EXIT_LIVE_URL
    except (PolicyContractError, CatalogSnapshotError, DuplicateLivePublishedNameError) as exc:
        if not as_json:
            print(str(exc), file=sys.stderr)
        problems.append(_catalog_problem(_classify_catalog_exception(exc), str(exc)))
        exit_code = _EXIT_VALIDATION

    if as_json:
        _emit_catalog_json(
            ok=exit_code == 0,
            unmatched_allow_patterns=unmatched_allow_patterns,
            unreachable_tools=unreachable_tools,
            duplicate_live_names=duplicate_live_names,
            problems=problems,
        )
    return exit_code


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


def _cmd_serve(args: argparse.Namespace) -> int:
    # Imported lazily (and module-qualified, not "from ... import main") so
    # that `keystone-mcp serve` and `python -m keystone_mcp.server` always
    # call the same function, and tests can monkeypatch
    # `keystone_mcp.server.main` directly.
    import keystone_mcp.server as server_module

    env_file_result: EnvFileResult | None = getattr(args, "env_file_result", None)
    server_module.main(env_file_result=env_file_result)
    return 0


def _emit_upstream_json(*, ok: bool, problems: Sequence[UpstreamProblem]) -> None:
    payload = {
        "schema_version": _JSON_SCHEMA_VERSION,
        "ok": ok,
        "problems": [
            {
                "code": problem.code,
                "entry": problem.entry,
                "field": problem.field,
                "message": problem.message,
            }
            for problem in problems
        ],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))


def _cmd_upstream_validate(args: argparse.Namespace) -> int:
    from keystone_mcp.config import _env_bool
    from keystone_mcp.upstream_registry.load import read_registry_document
    from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy
    from keystone_mcp.upstream_registry.validate import UpstreamProblem, collect_upstream_problems

    path: Path = args.path
    as_json: bool = getattr(args, "json", False)

    if not path.is_file():
        if not as_json:
            print(f"error: file not found: {path}", file=sys.stderr)
        else:
            _emit_upstream_json(
                ok=False,
                problems=[
                    UpstreamProblem(
                        code="file_unreadable",
                        entry=None,
                        field=None,
                        message=f"file not found: {path}",
                    )
                ],
            )
        return 1
    try:
        allow_insecure_http = _env_bool("KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP", False)
        egress_allow_private = _env_bool("KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE", False)
    except ConfigError as exc:
        if not as_json:
            print(f"keystone-mcp: {exc}", file=sys.stderr)
        else:
            _emit_upstream_json(
                ok=False,
                problems=[
                    UpstreamProblem(code="config_invalid", entry=None, field=None, message=str(exc))
                ],
            )
        return 1
    policy = UpstreamSecurityPolicy(
        allow_insecure_http=allow_insecure_http,
        egress_allow_private=egress_allow_private,
    )
    try:
        document = read_registry_document(path)
        problems = collect_upstream_problems(document, policy=policy)
    except OSError as exc:
        if not as_json:
            print(f"error: {exc}", file=sys.stderr)
        else:
            _emit_upstream_json(
                ok=False,
                problems=[
                    UpstreamProblem(
                        code="file_unreadable", entry=None, field=None, message=str(exc)
                    )
                ],
            )
        return 1
    except ValueError as exc:
        if not as_json:
            print(f"error: {exc}", file=sys.stderr)
        else:
            _emit_upstream_json(
                ok=False,
                problems=[
                    UpstreamProblem(
                        code="document_invalid", entry=None, field=None, message=str(exc)
                    )
                ],
            )
        return 1

    if problems:
        if not as_json:
            for problem in problems:
                print(problem.message, file=sys.stderr)
        else:
            _emit_upstream_json(ok=False, problems=problems)
        return 1

    if not as_json:
        print(f"ok: {path}")
    else:
        _emit_upstream_json(ok=True, problems=[])
    return 0


_EXIT_ENV = 2

_USERS_CLI_COMMANDS = frozenset({"users", "keys", "service-accounts"})


def _settings_required_for_cli(command: str) -> frozenset[str]:
    if command == "oauth":
        return OAUTH_CLI_VARIABLES
    if command in _USERS_CLI_COMMANDS:
        return USERS_CLI_VARIABLES
    return frozenset()


def build_cli_argument_parser() -> argparse.ArgumentParser:
    """Build the keystone-mcp CLI parser (used by main and contract snapshots)."""
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
    validate.add_argument(
        "--json",
        action="store_true",
        help="Emit one machine-readable JSON document on stdout instead of text",
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
    upstream_validate.add_argument(
        "--json",
        action="store_true",
        help="Emit one machine-readable JSON document on stdout instead of text",
    )
    upstream_validate.set_defaults(handler=_cmd_upstream_validate)

    serve = subparsers.add_parser("serve", help="Start the Keystone-MCP server")
    serve.set_defaults(handler=_cmd_serve)

    add_users_commands(subparsers)
    add_api_keys_commands(subparsers)
    add_service_accounts_commands(subparsers)
    add_plugins_commands(subparsers)
    add_oauth_commands(subparsers)
    add_config_commands(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_cli_argument_parser()
    args = parser.parse_args(argv)
    if args.command == "config":
        return args.handler(args)
    try:
        env_file_result = load_env_file()
    except ConfigError as exc:
        print(f"keystone-mcp: {exc}", file=sys.stderr)
        return _EXIT_ENV
    args.env_file_result = env_file_result
    try:
        configure_logging(settings_for_command(_settings_required_for_cli(args.command)))
    except ConfigError as exc:
        print(f"keystone-mcp: {exc}", file=sys.stderr)
        return _EXIT_VALIDATION
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
    if args.command == "oauth":
        return args.handler(args)
    parser.error(f"unknown command: {args.command}")
    return _EXIT_VALIDATION


if __name__ == "__main__":
    raise SystemExit(main())
