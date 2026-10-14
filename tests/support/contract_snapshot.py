"""Generate deterministic public-surface snapshots from Keystone source."""

from __future__ import annotations

import argparse
import importlib
import inspect
import os
import subprocess
import sys
import tempfile
import typing
from pathlib import Path
from types import ModuleType
from typing import get_args, get_origin

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SRC = REPO_ROOT / "src"
GENERATOR_VERSION = "1"

SECTIONS = (
    "env-vars",
    "policy-keys",
    "cli-commands",
    "protocols",
    "builtin-tools",
    "metrics",
)

PYTHON_SURFACE = (
    "keystone_mcp.login.protocol",
    "keystone_mcp.login.base",
    "keystone_mcp.login.oidc",
    "keystone_mcp.user_directory.protocol",
    "keystone_mcp.user_directory.base",
    "keystone_mcp.user_directory.types",
    "keystone_mcp.user_directory.errors",
    "keystone_mcp.plugins",
    "keystone_mcp.contract_tests",
)


def anchor(section: str, key: str) -> str:
    if section in ("env-vars", "policy-keys", "cli-commands"):
        return key
    if section == "metrics":
        return key.split("{", 1)[0]
    if section == "builtin-tools":
        return key.split("(", 1)[0]
    if section == "protocols":
        if "(" in key:
            return key.split("(", 1)[0]
        if key.count(".") >= 2:
            return key.rsplit(".", 1)[0]
        return key
    return key


def _clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("KEYSTONE_MCP_")}
    env.setdefault("PYTHONUNBUFFERED", "1")
    return env


def _format_row(key: str, attrs: dict[str, str]) -> str:
    return f"{key}\t{_format_attrs(attrs)}" if attrs else key


def _format_attrs(attrs: dict[str, str]) -> str:
    return " ".join(f"{name}={attrs[name]}" for name in sorted(attrs))


def _header(section: str, source: str) -> str:
    return f"# section={section} source={source} generator={GENERATOR_VERSION}"


def _strip_keystone_env(env: dict[str, str]) -> None:
    for key in list(env):
        if key.startswith("KEYSTONE_MCP_"):
            del env[key]


def generate_env_vars(src_root: Path) -> dict[str, str]:
    from support.env_vars import code_variables

    names = code_variables(root=src_root / "keystone_mcp")
    return {name: "" for name in sorted(names)}


def generate_policy_keys(_src_root: Path) -> dict[str, str]:
    from keystone_mcp.rbac.policy import POLICY_TOP_LEVEL_KEYS

    return {key: "" for key in sorted(POLICY_TOP_LEVEL_KEYS)}


def _subparsers_actions(parser: argparse.ArgumentParser) -> list[argparse._SubParsersAction]:
    return [action for action in parser._actions if isinstance(action, argparse._SubParsersAction)]


def _collect_cli_commands(parser: argparse.ArgumentParser, prefix: tuple[str, ...]) -> list[str]:
    subparser_actions = _subparsers_actions(parser)
    if not subparser_actions:
        return [" ".join(prefix)] if prefix else []
    commands: list[str] = []
    for action in subparser_actions:
        for name in sorted(action.choices):
            sub = action.choices[name]
            commands.extend(_collect_cli_commands(sub, prefix + (name,)))
    return commands


def build_cli_parser() -> argparse.ArgumentParser:
    from keystone_mcp.cli import _CATALOG_TIERS, _catalog_parent_parser
    from keystone_mcp.plugins_cli import add_plugins_commands
    from keystone_mcp.users.api_keys_cli import add_api_keys_commands
    from keystone_mcp.users.cli import add_users_commands
    from keystone_mcp.users.service_accounts_cli import add_service_accounts_commands

    parser = argparse.ArgumentParser(prog="keystone-mcp")
    subparsers = parser.add_subparsers(dest="command", required=True)

    catalog = subparsers.add_parser("catalog", help="RBAC catalog registry")
    catalog_sub = catalog.add_subparsers(dest="catalog_command", required=True)
    parent = _catalog_parent_parser()

    catalog_sub.add_parser("validate", parents=[parent], help="Validate policy")
    catalog_sub.add_parser("diff", parents=[parent], help="Diff policy")
    export = catalog_sub.add_parser("export", help="Export snapshot")
    export.add_argument("--live-file", type=Path, required=True)
    export.add_argument("--tier", choices=sorted(_CATALOG_TIERS), default="active")

    upstream = subparsers.add_parser("upstream", help="Upstream registry utilities")
    upstream_sub = upstream.add_subparsers(dest="upstream_command", required=True)
    upstream_validate = upstream_sub.add_parser("validate", help="Validate registry file")
    upstream_validate.add_argument("--path", required=True, type=Path)

    subparsers.add_parser("serve", help="Start the Keystone-MCP server")
    add_users_commands(subparsers)
    add_api_keys_commands(subparsers)
    add_service_accounts_commands(subparsers)
    add_plugins_commands(subparsers)
    return parser


def generate_cli_commands(_src_root: Path) -> dict[str, str]:
    parser = build_cli_parser()
    commands = _collect_cli_commands(parser, ())
    return {command: "" for command in sorted(commands)}


def _annotation_str(annotation: object) -> str:
    if annotation is inspect.Parameter.empty:
        return ""
    if isinstance(annotation, str):
        return annotation
    if hasattr(annotation, "__name__"):
        return str(annotation.__name__)
    return str(annotation).replace("typing.", "")


def _literal_values(annotation: object) -> tuple[str, ...] | None:
    origin = get_origin(annotation)
    if origin is typing.Literal:
        return tuple(str(value) for value in get_args(annotation))
    return None


def _class_kind(obj: type) -> str:
    if issubclass(obj, Exception):
        return "exception"
    if getattr(obj, "__dataclass_fields__", None) is not None:
        return "dataclass"
    if getattr(obj, "_is_protocol", False):
        return "protocol"
    return "class"


def _module_public_names(module: ModuleType) -> list[str]:
    if hasattr(module, "__all__"):
        return list(module.__all__)
    names: list[str] = []
    for name, obj in vars(module).items():
        if name.startswith("_"):
            continue
        if getattr(obj, "__module__", None) == module.__name__:
            names.append(name)
    return sorted(names)


def _qual(module_name: str, name: str) -> str:
    short = module_name.removeprefix("keystone_mcp.")
    return f"{short}.{name}"


def _member_rows(module_name: str, cls: type) -> dict[str, str]:
    rows: dict[str, str] = {}
    class_key = _qual(module_name, cls.__name__)
    rows[class_key] = _format_attrs({"kind": _class_kind(cls)})

    for name, member in sorted(vars(cls).items()):
        if name.startswith("_"):
            continue
        obj = member
        if isinstance(member, (classmethod, staticmethod)):
            obj = member.__func__
        if isinstance(obj, property):
            rows[f"{class_key}.{name}"] = _format_attrs(
                {
                    "kind": "property",
                    "returns": _annotation_str(obj.fget.__annotations__.get("return", "")),
                }
            )
            continue
        if not callable(obj):
            continue
        sig = inspect.signature(obj, eval_str=False)
        returns = _annotation_str(sig.return_annotation)
        is_async = inspect.iscoroutinefunction(obj)
        rows[f"{class_key}.{name}"] = _format_attrs(
            {
                "kind": "method",
                "async": "yes" if is_async else "no",
                "returns": returns,
            }
        )
        for param in sig.parameters.values():
            if param.name in ("self", "cls"):
                continue
            param_key = f"{class_key}.{name}({param.name})"
            default = param.default
            required = default is inspect.Parameter.empty
            rows[param_key] = _format_attrs(
                {
                    "kind": str(param.kind.name).lower(),
                    "required": "yes" if required else "no",
                    "annotation": _annotation_str(param.annotation),
                    "default": repr(default) if not required else "-",
                }
            )
    return rows


def generate_protocols(_src_root: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for module_name in PYTHON_SURFACE:
        try:
            module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            rows[f"# module {module_name} absent in source"] = ""
            continue
        for name in _module_public_names(module):
            obj = getattr(module, name)
            if inspect.isclass(obj):
                rows.update(_member_rows(module_name, obj))
                continue
            values = _literal_values(obj)
            if values is not None:
                key = _qual(module_name, name)
                rows[key] = _format_attrs({"values": ",".join(values)})
    return dict(sorted(rows.items()))


def _param_type_name(param_type: type) -> str:
    return getattr(param_type, "__name__", str(param_type))


def generate_builtin_tools(_src_root: Path) -> dict[str, str]:
    import tempfile

    from keystone_mcp.catalog.builtin import BUILTIN_TOOL_NAMES, register_catalog
    from keystone_mcp.config import Settings
    from keystone_mcp.rbac.loader import RbacPolicyManager
    from keystone_mcp.rbac.policy_store import PolicyStore
    from keystone_mcp.router.engine import RouterEngine
    from keystone_mcp.router.registry import Param, RouterRegistry
    from keystone_mcp.server import policy_role_source
    from keystone_mcp.user_directory.local import LocalUserDirectory
    from keystone_mcp.users.factory import build_users_store
    from support.test_env import UNUSED_REDIS_URL

    with tempfile.TemporaryDirectory() as tmp:
        policy = Path(tmp) / "rbac-policy.yaml"
        policy.write_text(
            'version: "1"\ndefault_deny: true\nroles:\n  administrator:\n    allow: ["*"]\n',
            encoding="utf-8",
        )
        settings = Settings(
            base_url="http://localhost:8080",
            rbac_mode="enforce",
            rbac_policy_path=str(policy),
            deployment_profile="local",
            users_backend="local",
            policy_tools="full",
            redis_url=UNUSED_REDIS_URL,
            rbac_audit_subject_salt="contract-snapshot-salt",
        )
        store = build_users_store(settings)
        engine = RouterEngine(settings)
        registry = RouterRegistry(engine)
        manager = RbacPolicyManager(settings)
        manager.load_initial(registry)
        directory = LocalUserDirectory(store)
        policy_store = PolicyStore(
            settings=settings,
            policy_manager=manager,
            registry=registry,
            directory=directory,
        )
        register_catalog(
            registry,
            settings,
            directory=directory,
            role_source=policy_role_source(manager),
            policy_store=policy_store,
        )
        manager.reload(registry)
        rows: dict[str, str] = {}
        for tool_name in sorted(BUILTIN_TOOL_NAMES):
            route = registry.get(tool_name)
            if route is None:
                continue
            rows[tool_name] = ""
            for param in route.params:
                assert isinstance(param, Param)
                rows[f"{tool_name}({param.name})"] = _format_attrs(
                    {
                        "type": _param_type_name(param.type),
                        "required": "yes" if param.required else "no",
                        "nullable": "yes" if param.allows_null else "no",
                    }
                )
        store.dispose()
    return rows


def generate_metrics(_src_root: Path) -> dict[str, str]:
    from prometheus_client.metrics import MetricWrapperBase

    import keystone_mcp.observability.metrics as metrics_module

    rows: dict[str, str] = {}
    for name, obj in sorted(vars(metrics_module).items()):
        if isinstance(obj, MetricWrapperBase):
            metric_type = getattr(obj, "_type", obj.__class__.__name__)
            export_name = obj._name
            if metric_type == "counter" and not export_name.endswith("_total"):
                export_name = f"{export_name}_total"
            rows[export_name] = _format_attrs({"type": metric_type})
            for label in obj._labelnames:
                rows[f"{export_name}{{{label}}}"] = ""
    return rows


_GENERATORS = {
    "env-vars": generate_env_vars,
    "policy-keys": generate_policy_keys,
    "cli-commands": generate_cli_commands,
    "protocols": generate_protocols,
    "builtin-tools": generate_builtin_tools,
    "metrics": generate_metrics,
}


def generate_section(section: str, src_root: Path) -> dict[str, str]:
    if section not in _GENERATORS:
        raise ValueError(f"unknown section: {section}")
    if str(src_root) not in sys.path:
        sys.path.insert(0, str(src_root))
    from support.test_env import UNUSED_REDIS_URL

    _strip_keystone_env(os.environ)
    os.environ.setdefault("KEYSTONE_MCP_REDIS_URL", UNUSED_REDIS_URL)
    return _GENERATORS[section](src_root)


def write_section(path: Path, section: str, source: str, rows: dict[str, str]) -> None:
    lines = [
        _header(section, source),
        *[_format_row(key, parse_row_attrs(rows[key])) for key in sorted(rows)],
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_row_attrs(raw: str) -> dict[str, str]:
    if not raw:
        return {}
    attrs: dict[str, str] = {}
    for token in raw.split():
        if "=" in token:
            key, value = token.split("=", 1)
            attrs[key] = value
    return attrs


def _run_section_subprocess(section: str, src_root: Path, source: str) -> dict[str, str]:
    env = _clean_env()
    env["PYTHONPATH"] = str(REPO_ROOT / "tests")
    cmd = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--src",
        str(src_root),
        "--section",
        section,
        "--source-label",
        source,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"snapshot section {section} failed:\n{proc.stdout}\n{proc.stderr}")
    rows: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        if "\t" in line:
            key, attrs = line.split("\t", 1)
        else:
            key, attrs = line, ""
        rows[key] = attrs
    return rows


def snapshot_from_src(src_root: Path, out_dir: Path, source: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for section in SECTIONS:
        rows = _run_section_subprocess(section, src_root, source)
        write_section(out_dir / f"{section}.txt", section, source, rows)


def snapshot_from_tag(tag: str, out_dir: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="keystone-freeze-") as tmp:
        worktree = Path(tmp) / "tree"
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(worktree), tag],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        try:
            snapshot_from_src(worktree / "src", out_dir, tag)
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(worktree)],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Contract snapshot generator")
    parser.add_argument("--src", type=Path, help="Path to src/ tree")
    parser.add_argument("--out", type=Path, help="Output directory for section files")
    parser.add_argument("--section", choices=SECTIONS, help="Emit one section to stdout")
    parser.add_argument("--from-tag", dest="from_tag", help="Generate from a git tag via worktree")
    parser.add_argument(
        "--source-label",
        default="worktree",
        help="Value for the snapshot header source= field",
    )
    args = parser.parse_args(argv)

    if args.from_tag:
        if not args.out:
            parser.error("--out is required with --from-tag")
        snapshot_from_tag(args.from_tag, args.out)
        return 0

    if args.section:
        if not args.src:
            parser.error("--src is required with --section")
        tests_dir = REPO_ROOT / "tests"
        if str(tests_dir) not in sys.path:
            sys.path.insert(0, str(tests_dir))
        rows = generate_section(args.section, args.src.resolve())
        for key in sorted(rows):
            attrs = parse_row_attrs(rows[key])
            print(_format_row(key, attrs))
        return 0

    if args.src and args.out:
        snapshot_from_src(args.src.resolve(), args.out, args.source_label)
        return 0

    parser.error("specify --from-tag --out, or --src with --out or --section")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
