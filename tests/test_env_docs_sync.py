"""Keep ``config.py``, ``.env.example`` and ``docs/environment.md`` in sync.

Every ``KEYSTONE_MCP_*`` variable read by the code must be documented in
``docs/environment.md`` and listed in ``.env.example``. This module extracts
the three name sets with plain regexes (not by importing
``keystone_mcp.config`` or introspecting its dataclass, since names living
inside ``default_factory=lambda`` cannot be recovered that way) and compares
them.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src" / "keystone_mcp"
ENV_EXAMPLE_PATH = REPO_ROOT / ".env.example"
ENVIRONMENT_DOC_PATH = REPO_ROOT / "docs" / "environment.md"

# Matches every place the code reads a KEYSTONE_MCP_* variable: the _env*
# helpers in config.py, and direct os.environ/os.getenv reads anywhere else
# in src/ (e.g. a dedicated .env loader).
CODE_VARIABLE_PATTERN = re.compile(
    r"(?:_env(?:_int|_float|_bool)?\(|os\.environ\.get\(|os\.getenv\(|os\.environ\[)"
    r"\s*[\"'](KEYSTONE_MCP_[A-Z0-9_]+)[\"']"
)

# Matches a variable assignment line in .env.example, commented out or not.
# Repeated names (e.g. mentioned again in a later section) are fine, we only
# care about the resulting set.
ENV_EXAMPLE_VARIABLE_PATTERN = re.compile(
    r"^\s*#?\s*(KEYSTONE_MCP_[A-Z0-9_]+)=",
    re.MULTILINE,
)

# Matches the first column of a Markdown table row in docs/environment.md,
# e.g. "| `KEYSTONE_MCP_BASE_URL` | `http://localhost:8080` | ... |".
DOCS_VARIABLE_PATTERN = re.compile(
    r"^\|\s*`(KEYSTONE_MCP_[A-Z0-9_]+)`\s*\|",
    re.MULTILINE,
)


def _variables_read_by_code() -> set[str]:
    names: set[str] = set()
    for path in SRC_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        names.update(CODE_VARIABLE_PATTERN.findall(text))
    return names


def _variables_in_env_example() -> set[str]:
    text = ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
    return set(ENV_EXAMPLE_VARIABLE_PATTERN.findall(text))


def _variables_in_environment_doc() -> set[str]:
    text = ENVIRONMENT_DOC_PATH.read_text(encoding="utf-8")
    return set(DOCS_VARIABLE_PATTERN.findall(text))


def _format_diff(missing: set[str], extra: set[str], doc_label: str) -> str:
    return (
        f"missing in {doc_label}: {sorted(missing)}; "
        f"documented but not read by code: {sorted(extra)}"
    )


def test_code_variables_are_found() -> None:
    """Guard against a broken regex silently matching nothing."""
    code_names = _variables_read_by_code()
    assert code_names, "expected at least one KEYSTONE_MCP_* variable read by src/keystone_mcp"
    assert "KEYSTONE_MCP_REDIS_URL" in code_names


def test_environment_md_matches_code() -> None:
    code_names = _variables_read_by_code()
    doc_names = _variables_in_environment_doc()
    missing = code_names - doc_names
    extra = doc_names - code_names
    assert not missing and not extra, _format_diff(missing, extra, "docs/environment.md")


def test_env_example_matches_code() -> None:
    code_names = _variables_read_by_code()
    env_example_names = _variables_in_env_example()
    missing = code_names - env_example_names
    extra = env_example_names - code_names
    assert not missing and not extra, _format_diff(missing, extra, ".env.example")


def test_production_upstreams_example_does_not_claim_env_already_set() -> None:
    """``examples/production/upstreams.yaml``'s header comment must not claim
    ``KEYSTONE_MCP_UPSTREAMS_PATH`` is already pointed at it by ``.env``: the
    shipped ``.env.example`` ships that line commented out, so an operator
    who only uncomments section 2 (per docs/paths/production-docker.md) and
    never explicitly sets this one would silently run with no upstreams."""
    env_example_text = ENV_EXAMPLE_PATH.read_text(encoding="utf-8")
    assert re.search(r"^#\s*KEYSTONE_MCP_UPSTREAMS_PATH=", env_example_text, re.MULTILINE), (
        ".env.example is expected to ship KEYSTONE_MCP_UPSTREAMS_PATH commented out by default"
    )

    upstreams_example_path = REPO_ROOT / "examples" / "production" / "upstreams.yaml"
    upstreams_example_text = upstreams_example_path.read_text(encoding="utf-8")
    assert "already points there" not in upstreams_example_text
