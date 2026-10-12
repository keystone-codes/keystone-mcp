"""Keystone-MCP refuses to silently ignore a removed KEYSTONE_MCP_* variable.

A variable moves into ``config.py::REMOVED_VARIABLES`` once its removal
ships. The variable itself is never read by regular code anymore (checked
against ``tests/support/env_vars.py::code_variables()``); the table exists
purely so an operator's stale ``.env`` is reported instead of ignored.

``KEYSTONE_MCP_RBAC_ENABLED`` is the only fatal entry introduced by this
card (Z01); it is marked fatal because silently ignoring it would leave RBAC
disabled while the operator believes it is enforced.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from keystone_mcp.config import REMOVED_VARIABLES, ConfigError, RemovedVariable, load_settings
from keystone_mcp.env_file import load_env_file
from support.env_vars import code_variables, environment_md_variables

REPO_ROOT = Path(__file__).resolve().parent.parent
ENVIRONMENT_DOC_PATH = REPO_ROOT / "docs" / "environment.md"


def test_rbac_enabled_is_refused_at_startup(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_ENABLED", "true")
    with pytest.raises(ConfigError) as exc_info:
        load_settings()
    message = str(exc_info.value)
    assert "KEYSTONE_MCP_RBAC_ENABLED" in message
    assert "KEYSTONE_MCP_RBAC_MODE" in message


def test_rbac_enabled_false_is_refused_too(monkeypatch):
    """The variable being set at all means the .env is stale, whatever the value."""
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_ENABLED", "false")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_RBAC_ENABLED"):
        load_settings()


def test_empty_removed_variable_is_ignored(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_ENABLED", "")
    load_settings()


def test_removed_non_fatal_variable_gives_startup_warning(monkeypatch):
    from keystone_mcp.config import startup_warnings

    probe = RemovedVariable(
        removed_in="0.5.0",
        replacement="Nothing to set.",
        fatal=False,
    )
    monkeypatch.setitem(REMOVED_VARIABLES, "KEYSTONE_MCP_Z01_PROBE", probe)
    settings = load_settings()
    warnings = startup_warnings(settings, environ={"KEYSTONE_MCP_Z01_PROBE": "x"})
    assert len(warnings) == 1
    assert "KEYSTONE_MCP_Z01_PROBE" in warnings[0]


def test_removed_internal_call_url_gives_startup_warning(monkeypatch):
    """KEYSTONE_MCP_DET_INTERNAL_URL (its placeholder adapter is gone) warns, not fails."""
    from keystone_mcp.config import startup_warnings

    monkeypatch.setenv("KEYSTONE_MCP_DET_INTERNAL_URL", "http://localhost:8000")
    settings = load_settings()
    warnings = startup_warnings(
        settings, environ={"KEYSTONE_MCP_DET_INTERNAL_URL": "http://localhost:8000"}
    )
    assert len(warnings) == 1
    assert "KEYSTONE_MCP_DET_INTERNAL_URL" in warnings[0]
    assert "removed" in warnings[0]


def test_several_fatal_variables_are_reported_together(monkeypatch):
    other = RemovedVariable(
        removed_in="0.5.0",
        replacement="Nothing to set.",
        fatal=True,
    )
    monkeypatch.setitem(REMOVED_VARIABLES, "KEYSTONE_MCP_Z01_PROBE", other)
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_ENABLED", "true")
    monkeypatch.setenv("KEYSTONE_MCP_Z01_PROBE", "x")
    with pytest.raises(ConfigError) as exc_info:
        load_settings()
    message = str(exc_info.value)
    assert "KEYSTONE_MCP_RBAC_ENABLED" in message
    assert "KEYSTONE_MCP_Z01_PROBE" in message


def test_file_api_url_is_refused_with_hint(monkeypatch):
    """The built-in file tools were removed (Z03): a stale .env is refused."""
    monkeypatch.setenv("KEYSTONE_MCP_FILE_API_URL", "http://x")
    with pytest.raises(ConfigError) as exc_info:
        load_settings()
    message = str(exc_info.value)
    assert "KEYSTONE_MCP_FILE_API_URL" in message
    assert "upstream MCP server" in message


def test_removed_fatal_variable_in_env_file_is_refused_at_startup(tmp_path, monkeypatch):
    """A stale `.env` is caught the same way a stale shell environment is.

    ``server.main()`` always calls ``load_env_file()`` before ``load_settings()``
    (see ``keystone_mcp.env_file``); a removed fatal variable left behind in an
    operator's env file must reach the same refusal, not just the same variable
    set directly in the shell.

    ``load_env_file()`` writes straight into the real ``os.environ`` (that is
    the point of it — ``KEYSTONE_MCP_RBAC_ENABLED`` has to be visible to the
    real ``load_settings()`` afterwards, the same way it would be for the real
    server). ``monkeypatch.delenv(..., raising=False)`` does not register an
    undo for a name that was not already set, so it would not clean up a value
    written later by code it does not know about; the explicit ``finally``
    guarantees the variable never leaks into another test.
    """
    assert "KEYSTONE_MCP_RBAC_ENABLED" not in os.environ
    env_file = tmp_path / "stale.env"
    env_file.write_text("KEYSTONE_MCP_RBAC_ENABLED=true\n", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_ENV_FILE", str(env_file))

    try:
        result = load_env_file()
        assert "KEYSTONE_MCP_RBAC_ENABLED" in result.loaded

        with pytest.raises(ConfigError) as exc_info:
            load_settings()
        message = str(exc_info.value)
        assert "KEYSTONE_MCP_RBAC_ENABLED" in message
        assert "KEYSTONE_MCP_RBAC_MODE" in message
    finally:
        os.environ.pop("KEYSTONE_MCP_RBAC_ENABLED", None)


def test_removed_variables_are_not_read_by_code():
    """A removed variable must not still be read somewhere in src/."""
    assert set(REMOVED_VARIABLES) & code_variables() == set()


def test_removed_variables_listed_in_environment_md():
    text = ENVIRONMENT_DOC_PATH.read_text(encoding="utf-8")
    start = text.index("## Removed variables")
    section = text[start:]
    import re

    listed = set(re.findall(r"^-\s*`(KEYSTONE_MCP_[A-Z0-9_]+)`", section, re.MULTILINE))
    assert listed == set(REMOVED_VARIABLES)
    # Sanity check: the bulleted list must not also be picked up as a table
    # by environment_md_variables() (it reads `## RBAC...` tables above).
    assert "KEYSTONE_MCP_RBAC_ENABLED" not in environment_md_variables(ENVIRONMENT_DOC_PATH)
