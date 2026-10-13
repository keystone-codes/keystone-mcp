"""Static checks on agent SKILL.md files shipped with the repository."""

from __future__ import annotations

from pathlib import Path

from keystone_mcp.adapters.policy_admin import POLICY_ADMIN_ERROR_CODES
from keystone_mcp.catalog.builtin import BUILTIN_TOOL_NAMES

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_SKILL = REPO_ROOT / "skills" / "keystone-policy-admin" / "SKILL.md"


def test_policy_admin_skill_documents_tools_and_errors() -> None:
    text = POLICY_SKILL.read_text(encoding="utf-8")
    policy_tools = sorted(name for name in BUILTIN_TOOL_NAMES if name.startswith("policy_"))
    assert len(policy_tools) == 9

    missing_tools = [name for name in policy_tools if f"`{name}`" not in text]
    assert not missing_tools, f"keystone-policy-admin SKILL.md omits tools: {missing_tools}"

    missing_codes = [code for code in sorted(POLICY_ADMIN_ERROR_CODES) if code not in text]
    assert not missing_codes, f"keystone-policy-admin SKILL.md omits error codes: {missing_codes}"
