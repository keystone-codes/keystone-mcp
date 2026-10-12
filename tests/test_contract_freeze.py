"""CI contract freeze: public names cannot disappear without a changelog entry.

Frozen lists live in ``tests/data/frozen-*.txt`` (append-only from 0.5.0).
See ``docs/compatibility.md`` and ``docs/CONTRIBUTING.md``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from keystone_mcp.cli import main as cli_main
from keystone_mcp.config import REMOVED_VARIABLES
from keystone_mcp.rbac.policy import POLICY_TOP_LEVEL_KEYS
from support.env_vars import code_variables

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPATIBILITY_PATH = REPO_ROOT / "docs" / "compatibility.md"
CHANGELOG_PATH = REPO_ROOT / "CHANGELOG.md"
FROZEN_ENV_VARS_PATH = REPO_ROOT / "tests" / "data" / "frozen-env-vars.txt"
FROZEN_POLICY_KEYS_PATH = REPO_ROOT / "tests" / "data" / "frozen-policy-keys.txt"
FROZEN_CLI_COMMANDS_PATH = REPO_ROOT / "tests" / "data" / "frozen-cli-commands.txt"

_COMPAT_ENV_VAR_PATTERN = re.compile(
    r"^\|\s*`(KEYSTONE_MCP_[A-Z0-9_]+)`\s*\|",
    re.MULTILINE,
)
_COMPAT_DEPRECATED_ROW_PATTERN = re.compile(
    r"^\|\s*`(KEYSTONE_MCP_[A-Z0-9_]+)`\s*\|\s*[^|]+\|\s*deprecated\b",
    re.MULTILINE,
)
_REMOVED_VAR_NAME_PATTERN = re.compile(r"KEYSTONE_MCP_[A-Z0-9_]+")

_FROZEN_REMOVAL_MESSAGE = (
    "{name} is frozen since 0.5.0 but the code no longer reads it. "
    "A frozen variable is removed only in a major release: add it to "
    "REMOVED_VARIABLES in config.py and to a '### Removed' section of "
    "CHANGELOG.md (see docs/compatibility.md#deprecation-rule)."
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
    """Collect ``KEYSTONE_MCP_*`` names mentioned only under ``### Removed``."""
    names: set[str] = set()
    current_heading: str | None = None
    for line in text.splitlines():
        if line.startswith("### "):
            current_heading = line.removeprefix("### ").strip()
            continue
        if current_heading == "Removed":
            names.update(_REMOVED_VAR_NAME_PATTERN.findall(line))
    return names


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
    changelog_removed = changelog_removed_names(CHANGELOG_PATH.read_text(encoding="utf-8"))

    failures: list[str] = []
    for name in sorted(frozen):
        if name in code:
            continue
        if name in removed_keys and name in changelog_removed:
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
