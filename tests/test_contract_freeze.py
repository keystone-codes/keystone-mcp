"""CI contract freeze: public surface must stay compatible with the 0.5.0 baseline."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from keystone_mcp.catalog.builtin import BUILTIN_TOOL_NAMES
from keystone_mcp.cli import main as cli_main
from keystone_mcp.config import REMOVED_VARIABLES
from keystone_mcp.rbac.policy import POLICY_TOP_LEVEL_KEYS
from support.contract_freeze import (
    changelog_current_sections,
    findings,
    load_snapshot,
    project_major,
    violations,
)
from support.contract_snapshot import SECTIONS, _run_section_subprocess
from support.env_vars import (
    code_variables,
    env_literals,
    is_exempt_literal,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
COMPATIBILITY_PATH = REPO_ROOT / "docs" / "compatibility.md"
CHANGELOG_PATH = REPO_ROOT / "CHANGELOG.md"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
FROZEN_ENV_VARS_PATH = REPO_ROOT / "tests" / "data" / "frozen-env-vars.txt"
FROZEN_POLICY_KEYS_PATH = REPO_ROOT / "tests" / "data" / "frozen-policy-keys.txt"
FROZEN_CLI_COMMANDS_PATH = REPO_ROOT / "tests" / "data" / "frozen-cli-commands.txt"
BASELINE_DIR = REPO_ROOT / "tests" / "data" / "frozen-baseline-0.5.0"

_COMPAT_ENV_VAR_PATTERN = re.compile(
    r"^\|\s*`(KEYSTONE_MCP_[A-Z0-9_]+)`\s*\|",
    re.MULTILINE,
)
_COMPAT_DEPRECATED_ROW_PATTERN = re.compile(
    r"^\|\s*`(KEYSTONE_MCP_[A-Z0-9_]+)`\s*\|\s*[^|]+\|\s*deprecated\b",
    re.MULTILINE,
)
_REMOVED_VAR_NAME_PATTERN = re.compile(r"KEYSTONE_MCP_[A-Z0-9_]+")
_METRIC_ROW_PATTERN = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*(.+?)\s*\|", re.MULTILINE)
_BUILTIN_TOOL_PATTERN = re.compile(r"`([a-z_]+)`")
_CLI_COMMAND_PATTERN = re.compile(r"`keystone-mcp ([^`]+)`")

_FROZEN_REMOVAL_MESSAGE = (
    "{name} is frozen since 0.5.0 but the code no longer reads it. "
    "Removal is allowed only in major version 2.0 with a current '### Removed' "
    "changelog entry (see docs/compatibility.md#deprecation-rule)."
)


def _environment_variables_section(text: str) -> str:
    start = text.index("## Environment variables")
    end = text.index("## Policy file")
    return text[start:end]


def compatibility_doc_variables(path: Path = COMPATIBILITY_PATH) -> set[str]:
    text = path.read_text(encoding="utf-8")
    section = _environment_variables_section(text)
    return set(_COMPAT_ENV_VAR_PATTERN.findall(section))


def compatibility_doc_deprecated_variables(path: Path = COMPATIBILITY_PATH) -> set[str]:
    text = path.read_text(encoding="utf-8")
    section = _environment_variables_section(text)
    return set(_COMPAT_DEPRECATED_ROW_PATTERN.findall(section))


def changelog_removed_names(text: str) -> set[str]:
    names: set[str] = set()
    current_heading: str | None = None
    for line in text.splitlines():
        if line.startswith("### "):
            current_heading = line.removeprefix("### ").strip()
            continue
        if current_heading == "Removed":
            names.update(_REMOVED_VAR_NAME_PATTERN.findall(line))
    return names


def _changelog_removed_current() -> set[str]:
    version = _project_version()
    sections = changelog_current_sections(CHANGELOG_PATH.read_text(encoding="utf-8"), version)
    return set(_REMOVED_VAR_NAME_PATTERN.findall(sections.get("Removed", "")))


def _project_version() -> str:
    text = PYPROJECT_PATH.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "pyproject.toml version missing"
    return match.group(1)


def _load_frozen_names(path: Path) -> set[str]:
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        names.add(stripped)
    return names


def _load_frozen_commands(path: Path) -> list[str]:
    commands: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        commands.append(stripped)
    return commands


def _current_changelog_sections() -> dict[str, str]:
    return changelog_current_sections(
        CHANGELOG_PATH.read_text(encoding="utf-8"),
        _project_version(),
    )


def _violation_message(section: str, item) -> str:
    return (
        f"{section}: {item.key} {item.kind}. Frozen since 0.5.0 (docs/compatibility.md): "
        "restore compatibility; removal or breaking change is allowed only in 2.0 with "
        "the matching changelog entry."
    )


@pytest.mark.parametrize("section", SECTIONS)
def test_frozen_surface_still_present(section: str) -> None:
    baseline_path = BASELINE_DIR / f"{section}.txt"
    assert baseline_path.is_file(), f"missing baseline file for {section}"
    base = load_snapshot(baseline_path)
    current = _run_section_subprocess(section, SRC_ROOT, "worktree")
    found = findings(section, base, current)
    major = project_major(PYPROJECT_PATH.read_text(encoding="utf-8"))
    bad = violations(found, major, _current_changelog_sections())
    assert not bad, "\n".join(_violation_message(section, item) for item in bad)


def test_baseline_sections_are_complete() -> None:
    present = {path.stem for path in BASELINE_DIR.glob("*.txt")}
    assert present == set(SECTIONS)
    for section in SECTIONS:
        first = (BASELINE_DIR / f"{section}.txt").read_text(encoding="utf-8").splitlines()[0]
        assert first.startswith(f"# section={section} source=v0.5.0")


def test_changelog_parser_reads_only_removed_sections() -> None:
    sample = """\
## [1.0.0]

### Added

- New `KEYSTONE_MCP_ADDED_PROBE` setting.

### Removed

- `KEYSTONE_MCP_REMOVED_PROBE` is gone.

### Deprecated

- `KEYSTONE_MCP_DEPRECATED_PROBE` (use something else).

## [0.9.0]

### Removed

- Also drops `KEYSTONE_MCP_OLD_PROBE`.
"""
    assert changelog_removed_names(sample) == {
        "KEYSTONE_MCP_REMOVED_PROBE",
        "KEYSTONE_MCP_OLD_PROBE",
    }


def test_frozen_variable_is_read_or_properly_removed() -> None:
    frozen = _load_frozen_names(FROZEN_ENV_VARS_PATH)
    code = code_variables()
    removed_keys = set(REMOVED_VARIABLES)
    changelog_removed = _changelog_removed_current()
    major = project_major(PYPROJECT_PATH.read_text(encoding="utf-8"))

    failures: list[str] = []
    for name in sorted(frozen):
        if name in code:
            continue
        if major >= 2 and name in removed_keys and name in changelog_removed:
            continue
        failures.append(_FROZEN_REMOVAL_MESSAGE.format(name=name))

    assert not failures, "\n".join(failures)


def test_compatibility_doc_matches_code() -> None:
    doc_names = compatibility_doc_variables()
    code_names = code_variables()
    missing_in_doc = sorted(code_names - doc_names)
    listed_not_read = sorted(doc_names - code_names)
    assert not missing_in_doc and not listed_not_read, (
        f"read by code but missing in docs/compatibility.md: {missing_in_doc}; "
        f"listed but not read: {listed_not_read}"
    )


def test_snapshot_covers_compatibility_doc() -> None:
    frozen = _load_frozen_names(FROZEN_ENV_VARS_PATH)
    doc_names = compatibility_doc_variables()
    removed_keys = set(REMOVED_VARIABLES)

    missing_from_snapshot = sorted(doc_names - frozen)
    assert not missing_from_snapshot, (
        "listed in docs/compatibility.md but missing from tests/data/frozen-env-vars.txt: "
        f"{missing_from_snapshot}"
    )

    orphan_frozen = sorted(frozen - doc_names - removed_keys)
    assert not orphan_frozen, (
        f"frozen name is neither in docs/compatibility.md nor REMOVED_VARIABLES: {orphan_frozen}"
    )


def test_removed_variables_have_changelog_entry() -> None:
    changelog_removed = changelog_removed_names(CHANGELOG_PATH.read_text(encoding="utf-8"))
    missing = sorted(set(REMOVED_VARIABLES) - changelog_removed)
    assert not missing, (
        f"REMOVED_VARIABLES entry missing from a '### Removed' section in CHANGELOG.md: {missing}"
    )


def test_removed_and_frozen_do_not_overlap() -> None:
    overlap = sorted(code_variables() & set(REMOVED_VARIABLES))
    assert not overlap, f"code still reads removed variables: {overlap}"


def test_deprecated_variables_are_still_read() -> None:
    deprecated = compatibility_doc_deprecated_variables()
    code_names = code_variables()
    missing = sorted(deprecated - code_names)
    assert not missing, f"deprecated variable no longer read by code: {missing}"


def test_frozen_policy_keys_still_accepted() -> None:
    frozen = _load_frozen_names(FROZEN_POLICY_KEYS_PATH)
    missing = sorted(frozen - POLICY_TOP_LEVEL_KEYS)
    assert not missing, (
        "frozen policy top-level key no longer accepted: "
        f"{missing} (update POLICY_TOP_LEVEL_KEYS and docs/compatibility.md)"
    )


def test_frozen_cli_commands_exist() -> None:
    for command in _load_frozen_commands(FROZEN_CLI_COMMANDS_PATH):
        with pytest.raises(SystemExit) as exc_info:
            cli_main([*command.split(), "--help"])
        assert exc_info.value.code == 0, command


def test_frozen_lists_cover_baseline() -> None:
    mapping = {
        "env-vars": FROZEN_ENV_VARS_PATH,
        "policy-keys": FROZEN_POLICY_KEYS_PATH,
        "cli-commands": FROZEN_CLI_COMMANDS_PATH,
    }
    for section, list_path in mapping.items():
        baseline = load_snapshot(BASELINE_DIR / f"{section}.txt")
        frozen = _load_frozen_names(list_path)
        missing = sorted(baseline.keys() - frozen)
        assert not missing, f"baseline {section} name missing from {list_path.name}: {missing}"


def test_every_env_literal_is_read_or_exempt() -> None:
    root = SRC_ROOT / "keystone_mcp"
    reads = code_variables(root)
    removed = set(REMOVED_VARIABLES)
    failures: list[str] = []
    for path, line, name in env_literals(root):
        if name in reads or is_exempt_literal(name, removed_names=removed):
            continue
        failures.append(f"{path}:{line}: {name}")
    assert not failures, "\n".join(failures)


def _observability_section(text: str) -> str:
    start = text.index("## Observability")
    end = text.index("## Container image and distribution")
    return text[start:end]


def test_every_metric_is_documented() -> None:
    text = COMPATIBILITY_PATH.read_text(encoding="utf-8")
    section = _observability_section(text)
    documented: dict[str, set[str]] = {}
    for match in _METRIC_ROW_PATTERN.finditer(section):
        metric = match.group(1)
        labels_raw = match.group(2)
        if labels_raw.startswith("above +"):
            continue
        if labels_raw.startswith("("):
            documented[metric] = set()
        else:
            labels = {part.strip().strip("`") for part in labels_raw.split(",")}
            documented[metric] = labels

    current = _run_section_subprocess("metrics", SRC_ROOT, "worktree")
    for key in sorted(current):
        if "{" in key:
            metric, label_part = key.split("{", 1)
            label = label_part.rstrip("}")
            assert metric in documented, f"metric missing from compatibility.md: {metric}"
            assert label in documented[metric], f"label {label} missing for {metric}"
        else:
            assert key in documented, f"metric missing from compatibility.md: {key}"


def test_every_builtin_tool_is_documented() -> None:
    text = COMPATIBILITY_PATH.read_text(encoding="utf-8")
    start = text.index("### Built-in tools")
    end = text.index("## Headers sent to upstream services")
    section = text[start:end]
    documented = set(_BUILTIN_TOOL_PATTERN.findall(section))
    missing = sorted(BUILTIN_TOOL_NAMES - documented)
    assert not missing, f"built-in tool missing from compatibility.md: {missing}"


def test_every_cli_command_is_documented() -> None:
    text = COMPATIBILITY_PATH.read_text(encoding="utf-8")
    start = text.index("## CLI")
    end = text.index("## Users directory database")
    section = text[start:end]
    snapshot = _run_section_subprocess("cli-commands", SRC_ROOT, "worktree")
    missing = sorted(command for command in snapshot if command not in section)
    assert not missing, f"CLI command missing from compatibility.md: {missing}"


def _http_routes_section(text: str) -> str:
    start = text.index("## HTTP routes")
    end = text.index("## CLI")
    return text[start:end]


def _error_codes_section(text: str) -> str:
    start = text.index("### Built-in tools")
    end = text.index("## Headers sent to upstream services")
    return text[start:end]


def test_every_error_code_is_documented() -> None:
    text = COMPATIBILITY_PATH.read_text(encoding="utf-8")
    section = _error_codes_section(text)
    snapshot = _run_section_subprocess("error-codes", SRC_ROOT, "worktree")
    missing: list[str] = []
    for key in sorted(snapshot):
        _family, code = key.split(":", 1)
        if f"`{code}`" not in section and code not in section:
            missing.append(key)
    assert not missing, f"error code missing from compatibility.md: {missing}"


def test_every_route_is_documented() -> None:
    text = COMPATIBILITY_PATH.read_text(encoding="utf-8")
    section = _http_routes_section(text)
    snapshot = _run_section_subprocess("routes", SRC_ROOT, "worktree")
    missing: list[str] = []
    for key in sorted(snapshot):
        method, path = key.split(" ", 1)
        if path == "<KEYSTONE_MCP_HTTP_PATH>":
            needle = "KEYSTONE_MCP_HTTP_PATH"
        elif path == "<KEYSTONE_MCP_METRICS_PATH>":
            needle = "KEYSTONE_MCP_METRICS_PATH"
        elif "/login/<provider>" in path:
            needle = "/login/<provider>"
        else:
            needle = path
        if needle not in section and f"`{needle}`" not in section:
            missing.append(key)
    assert not missing, f"HTTP route missing from compatibility.md: {missing}"


def _documented_frozen_cli_flags(section: str) -> set[str]:
    """Flags compatibility.md explicitly freezes (doc promises must exist in code)."""
    flags: set[str] = set()
    catalog_parent_flags = ("--policy", "--snapshot", "--live-file", "--live-url")
    for command in ("catalog validate", "catalog diff"):
        for option in catalog_parent_flags:
            flags.add(f"{command} {option}")
    flags.add("catalog validate --strict-unreachable")
    flags.add("catalog export --live-file")
    flags.add("catalog export --tier")
    flags.add("catalog builtin --json")
    for option in ("--json", "--host", "--port", "--check-unique"):
        flags.add(f"catalog live {option}")
    for option in ("--from-url", "--token", "--policy", "--dry-run"):
        flags.add(f"users import {option}")
    flags.add("users grant-admin --role")
    flags.add("users admins --json")
    if "upstream validate --path" in section or "--path <file>" in section:
        flags.add("upstream validate --path")
    assert "--email" not in section.split("users import", 1)[-1].split("##", 1)[0], (
        "docs/compatibility.md must not freeze a removed users import --email flag"
    )
    return flags


def test_every_cli_flag_is_documented() -> None:
    text = COMPATIBILITY_PATH.read_text(encoding="utf-8")
    start = text.index("## CLI")
    end = text.index("## Users directory database")
    section = text[start:end]
    snapshot = _run_section_subprocess("cli-flags", SRC_ROOT, "worktree")
    promised = _documented_frozen_cli_flags(section)
    missing = sorted(flag for flag in promised if flag not in snapshot)
    assert not missing, f"documented CLI flag missing from snapshot: {missing}"
