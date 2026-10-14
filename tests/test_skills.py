"""Static checks on agent SKILL.md files shipped with the repository."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from keystone_mcp.adapters.api_keys_admin import API_KEYS_ADMIN_ERROR_CODES
from keystone_mcp.adapters.policy_admin import POLICY_ADMIN_ERROR_CODES
from keystone_mcp.adapters.service_accounts_admin import SERVICE_ACCOUNTS_ADMIN_ERROR_CODES
from keystone_mcp.adapters.users_admin import USERS_ADMIN_ERROR_CODES
from keystone_mcp.catalog.builtin import BUILTIN_TOOL_NAMES
from support.admin_error_codes import adapter_error_codes

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_SKILL = REPO_ROOT / "skills" / "keystone-policy-admin" / "SKILL.md"
USER_SKILL = REPO_ROOT / "skills" / "keystone-user-admin" / "SKILL.md"

_ERROR_TABLE_ROW_RE = re.compile(r"^\|\s*`([^`]+)`\s*\|", re.MULTILINE)


def _error_table_codes(skill_text: str) -> list[str]:
    if "## Errors" not in skill_text:
        return []
    section = skill_text.split("## Errors", 1)[1]
    section = section.split("\n## ", 1)[0]
    codes: list[str] = []
    for match in _ERROR_TABLE_ROW_RE.finditer(section):
        cell = match.group(1)
        for part in cell.split(","):
            code = part.strip().strip("`").strip()
            if code and code != "Code":
                codes.append(code)
    return codes


def test_policy_admin_skill_documents_tools_and_errors() -> None:
    text = POLICY_SKILL.read_text(encoding="utf-8")
    policy_tools = sorted(name for name in BUILTIN_TOOL_NAMES if name.startswith("policy_"))
    assert len(policy_tools) == 9

    missing_tools = [name for name in policy_tools if f"`{name}`" not in text]
    assert not missing_tools, f"keystone-policy-admin SKILL.md omits tools: {missing_tools}"

    missing_codes = [code for code in sorted(POLICY_ADMIN_ERROR_CODES) if code not in text]
    assert not missing_codes, f"keystone-policy-admin SKILL.md omits error codes: {missing_codes}"


def test_user_admin_skill_documents_tools_and_errors() -> None:
    text = USER_SKILL.read_text(encoding="utf-8")
    families = ("users_", "service_accounts_", "api_keys_")
    admin_tools = sorted(name for name in BUILTIN_TOOL_NAMES if name.startswith(families))
    assert admin_tools

    missing_tools = [name for name in admin_tools if f"`{name}`" not in text]
    assert not missing_tools, f"keystone-user-admin SKILL.md omits tools: {missing_tools}"

    expected_codes = (
        USERS_ADMIN_ERROR_CODES
        | SERVICE_ACCOUNTS_ADMIN_ERROR_CODES
        | API_KEYS_ADMIN_ERROR_CODES
    )
    missing_codes = [code for code in sorted(expected_codes) if code not in text]
    assert not missing_codes, f"keystone-user-admin SKILL.md omits error codes: {missing_codes}"


@pytest.mark.parametrize(
    ("skill_path", "family"),
    [
        (USER_SKILL, "users"),
        (POLICY_SKILL, "policy"),
    ],
)
def test_skill_error_tables_list_only_real_codes(skill_path: Path, family: str) -> None:
    text = skill_path.read_text(encoding="utf-8")
    allowed = adapter_error_codes(family)
    if family == "users":
        allowed = (
            USERS_ADMIN_ERROR_CODES
            | SERVICE_ACCOUNTS_ADMIN_ERROR_CODES
            | API_KEYS_ADMIN_ERROR_CODES
        )
    listed = _error_table_codes(text)
    assert listed, f"{skill_path.name} has no error table codes"
    unknown = sorted(set(listed) - set(allowed))
    assert not unknown, f"{skill_path.name} lists codes the tools do not return: {unknown}"
