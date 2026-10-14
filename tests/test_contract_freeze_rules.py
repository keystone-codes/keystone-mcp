"""Synthetic checks for contract freeze rule helpers."""

from __future__ import annotations

from support.contract_freeze import (
    changelog_current_sections,
    findings,
    violations,
)


def test_removed_env_var_is_reported_even_if_docs_and_code_agree() -> None:
    base = {"KEYSTONE_MCP_PORT": ""}
    current: dict[str, str] = {}
    found = findings("env-vars", base, current)
    assert any(item.kind == "removed" and item.key == "KEYSTONE_MCP_PORT" for item in found)


def test_removal_is_reported_below_2_0_even_with_changelog() -> None:
    base = {"KEYSTONE_MCP_PORT": ""}
    current: dict[str, str] = {}
    found = findings("env-vars", base, current)
    sections = changelog_current_sections(
        "## [Unreleased]\n\n### Removed\n\n- Drop KEYSTONE_MCP_PORT.\n",
        "0.5.0",
    )
    assert violations(found, major=0, sections=sections)


def test_removal_allowed_in_2_0_with_removed_entry() -> None:
    base = {"KEYSTONE_MCP_PORT": ""}
    current: dict[str, str] = {}
    found = findings("env-vars", base, current)
    sections = changelog_current_sections(
        "## [Unreleased]\n\n### Removed\n\n- KEYSTONE_MCP_PORT removed.\n",
        "2.0.0",
    )
    assert not violations(found, major=2, sections=sections)


def test_removal_in_2_0_needs_current_section() -> None:
    base = {"KEYSTONE_MCP_PORT": ""}
    current: dict[str, str] = {}
    found = findings("env-vars", base, current)
    sections = changelog_current_sections(
        "## [0.5.0]\n\n### Removed\n\n- KEYSTONE_MCP_PORT removed.\n",
        "2.0.0",
    )
    assert violations(found, major=2, sections=sections)


def test_renamed_metric_label_is_reported() -> None:
    base = {"keystone_mcp_rbac_decisions_total{reason}": ""}
    current = {"keystone_mcp_rbac_decisions_total{cause}": ""}
    found = findings("metrics", base, current)
    assert any(item.kind == "removed" for item in found)
    assert any(item.kind == "addition" for item in found)


def test_renamed_protocol_parameter_is_reported() -> None:
    member = "user_directory.protocol.UserDirectory.list_users"
    base = {
        "user_directory.protocol.UserDirectory": "kind=protocol",
        f"{member}": "kind=method async=yes returns=list",
        f"{member}(email_contains)": "kind=parameter required=no annotation=str default=None",
    }
    current = {
        "user_directory.protocol.UserDirectory": "kind=protocol",
        f"{member}": "kind=method async=yes returns=list",
    }
    found = findings("protocols", base, current)
    assert any(item.kind == "removed" and "email_contains" in item.key for item in found)


def test_new_protocol_member_is_reported() -> None:
    base = {"user_directory.protocol.UserDirectory": "kind=protocol"}
    current = {
        "user_directory.protocol.UserDirectory": "kind=protocol",
        "user_directory.protocol.UserDirectory.describe": "kind=method async=yes returns=str",
    }
    found = findings("protocols", base, current)
    assert any(item.kind == "breaking_addition" for item in found)


def test_new_required_tool_argument_is_reported() -> None:
    base = {"users_add": "", "users_add(email)": "type=str required=yes nullable=no"}
    current = {
        "users_add": "",
        "users_add(email)": "type=str required=yes nullable=no",
        "users_add(team)": "type=str required=yes nullable=no",
    }
    found = findings("builtin-tools", base, current)
    assert any(item.kind == "breaking_addition" and item.key == "users_add(team)" for item in found)


def test_new_optional_argument_is_allowed() -> None:
    base = {"users_add": "", "users_add(email)": "type=str required=yes nullable=no"}
    current = {
        "users_add": "",
        "users_add(email)": "type=str required=yes nullable=no",
        "users_add(team)": "type=str required=no nullable=no",
    }
    found = findings("builtin-tools", base, current)
    assert not violations(found, major=0, sections={})


def test_required_to_optional_is_allowed() -> None:
    base = {"users_add(email)": "type=str required=yes nullable=no"}
    current = {"users_add(email)": "type=str required=no nullable=no"}
    found = findings("builtin-tools", base, current)
    assert not any(item.kind == "changed" for item in found)


def test_changed_default_allowed_only_as_security_fix() -> None:
    base = {"KEYSTONE_MCP_PORT": "default=8080"}
    current = {"KEYSTONE_MCP_PORT": "default=80"}
    found = findings("env-vars", base, current)
    item = next(item for item in found if item.kind == "changed")
    security_only = changelog_current_sections(
        "## [Unreleased]\n\n### Security\n\n- KEYSTONE_MCP_PORT\n",
        "0.5.0",
    )
    assert violations(found, major=0, sections=security_only)
    both = changelog_current_sections(
        "## [Unreleased]\n\n### Security\n\n- KEYSTONE_MCP_PORT\n\n### Migration\n\n- KEYSTONE_MCP_PORT\n",
        "0.5.0",
    )
    assert not violations([item], major=0, sections=both)
    changed_only = changelog_current_sections(
        "## [Unreleased]\n\n### Changed\n\n- KEYSTONE_MCP_PORT\n",
        "0.5.0",
    )
    assert violations([item], major=0, sections=changed_only)


def test_current_sections_follow_pyproject_version() -> None:
    text = "## [Unreleased]\n\n### Added\n\n- note\n\n## [0.4.0]\n\n### Removed\n\n- old\n"
    sections = changelog_current_sections(text, "0.5.0")
    assert "Added" in sections
    assert "Removed" not in sections
