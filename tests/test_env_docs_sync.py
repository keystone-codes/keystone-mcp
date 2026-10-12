"""Keep ``config.py``, ``.env.example`` and ``docs/environment.md`` in sync.

Every ``KEYSTONE_MCP_*`` variable read by the code must be documented in
``docs/environment.md`` and listed in ``.env.example``. The three name sets
are extracted with plain regexes in ``tests/support/env_vars.py`` (not by
importing ``keystone_mcp.config`` or introspecting its dataclass, since names
living inside ``default_factory=lambda`` cannot be recovered that way); this
module just compares them.
"""

from __future__ import annotations

import re
from pathlib import Path

from support.env_vars import (
    code_variables,
    contrib_doc_variables,
    contrib_variables,
    env_example_variables,
    environment_md_variables,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE_PATH = REPO_ROOT / ".env.example"
ENVIRONMENT_DOC_PATH = REPO_ROOT / "docs" / "environment.md"


def _variables_read_by_code() -> set[str]:
    return code_variables()


def _variables_in_env_example() -> set[str]:
    return env_example_variables(ENV_EXAMPLE_PATH)


def _variables_in_environment_doc() -> set[str]:
    return environment_md_variables(ENVIRONMENT_DOC_PATH)


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


def test_contrib_variables_documented() -> None:
    """Every KEYSTONE_MCP_CONTRIB_* variable is documented in docs/contrib/*.md,
    and nothing extra is documented there (core variables live in environment.md)."""
    code_names = contrib_variables()
    doc_names = contrib_doc_variables()
    missing = code_names - doc_names
    extra = doc_names - code_names
    assert not missing and not extra, _format_diff(missing, extra, "docs/contrib/*.md")


def test_contrib_variables_use_contrib_prefix() -> None:
    """A variable read under src/keystone_mcp/contrib/ must use the
    KEYSTONE_MCP_CONTRIB_ prefix: contrib settings are a separate namespace
    from the core ones in Settings."""
    for name in contrib_variables():
        assert name.startswith("KEYSTONE_MCP_CONTRIB_"), (
            f"{name} is read under contrib/ but does not use the KEYSTONE_MCP_CONTRIB_ prefix"
        )


def test_core_reads_no_contrib_variables() -> None:
    """Code outside contrib/ must never read a KEYSTONE_MCP_CONTRIB_* variable:
    contrib settings are read only by the contrib class itself."""
    core_names = code_variables()
    contrib_prefixed = {name for name in core_names if name.startswith("KEYSTONE_MCP_CONTRIB_")}
    assert not contrib_prefixed, (
        f"core code reads contrib-prefixed variables: {sorted(contrib_prefixed)}"
    )


def test_env_example_has_no_contrib_variables() -> None:
    """.env.example documents only core variables; contrib settings live in
    docs/contrib/*.md, not in the shipped example file."""
    env_example_names = _variables_in_env_example()
    contrib_prefixed = {
        name for name in env_example_names if name.startswith("KEYSTONE_MCP_CONTRIB_")
    }
    assert not contrib_prefixed, (
        f".env.example lists contrib-prefixed variables: {sorted(contrib_prefixed)}"
    )
