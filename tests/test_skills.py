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
        USERS_ADMIN_ERROR_CODES | SERVICE_ACCOUNTS_ADMIN_ERROR_CODES | API_KEYS_ADMIN_ERROR_CODES
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


SKILLS_DIR = REPO_ROOT / "skills"
BOOTSTRAP_SKILL = SKILLS_DIR / "keystone-gateway-bootstrap" / "SKILL.md"
DOCS_README = REPO_ROOT / "docs" / "README.md"
ENVIRONMENT_DOC = REPO_ROOT / "docs" / "environment.md"

_FRONTMATTER_NAME_RE = re.compile(r"\A---\n(?:.*\n)*?name:\s*(\S+)\s*\n(?:.*\n)*?---\n")
_MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
_KEYSTONE_VAR_RE = re.compile(r"\bKEYSTONE_MCP_[A-Z0-9_]*[A-Z0-9]")
_SECRET_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,}")
_URL_PASSWORD_RE = re.compile(
    r"\b(?:postgres(?:ql)?|redis|rediss)(?:\+\w+)?://[^/\s:@]*:([^/\s@]*)@"
)
_PLACEHOLDER_PREFIXES = ("<", "%", "$", "CHANGE_ME")


def _skill_paths() -> list[Path]:
    paths = sorted(SKILLS_DIR.glob("*/SKILL.md"))
    assert paths, "no skills found under skills/"
    return paths


def _looks_random(token: str) -> bool:
    if token.startswith("KEYSTONE_"):
        return False
    return (
        any(char.islower() for char in token)
        and any(char.isupper() for char in token)
        and any(char.isdigit() for char in token)
    )


@pytest.mark.parametrize("skill_path", _skill_paths(), ids=lambda p: p.parent.name)
def test_skill_frontmatter_name_matches_folder(skill_path: Path) -> None:
    text = skill_path.read_text(encoding="utf-8")
    match = _FRONTMATTER_NAME_RE.match(text)
    assert match, f"{skill_path} has no frontmatter with a name"
    assert match.group(1) == skill_path.parent.name


@pytest.mark.parametrize("skill_path", _skill_paths(), ids=lambda p: p.parent.name)
def test_skill_is_listed_in_docs_readme(skill_path: Path) -> None:
    readme = DOCS_README.read_text(encoding="utf-8")
    assert f"skills/{skill_path.parent.name}/SKILL.md" in readme


@pytest.mark.parametrize("skill_path", _skill_paths(), ids=lambda p: p.parent.name)
def test_skill_relative_links_resolve(skill_path: Path) -> None:
    text = skill_path.read_text(encoding="utf-8")
    broken: list[str] = []
    for target in _MARKDOWN_LINK_RE.findall(text):
        if "://" in target or target.startswith(("#", "mailto:")):
            continue
        path_part = target.split("#", 1)[0]
        if not (skill_path.parent / path_part).resolve().exists():
            broken.append(target)
    assert not broken, f"{skill_path} links to missing files: {broken}"


@pytest.mark.parametrize("skill_path", _skill_paths(), ids=lambda p: p.parent.name)
def test_skill_keystone_variables_are_documented(skill_path: Path) -> None:
    text = skill_path.read_text(encoding="utf-8")
    environment = ENVIRONMENT_DOC.read_text(encoding="utf-8")
    documented = set(_KEYSTONE_VAR_RE.findall(environment))
    mentioned = set(_KEYSTONE_VAR_RE.findall(text))
    missing = sorted(mentioned - documented)
    assert not missing, f"{skill_path} names variables missing from environment.md: {missing}"


@pytest.mark.parametrize("skill_path", _skill_paths(), ids=lambda p: p.parent.name)
def test_skill_has_no_secret_like_values(skill_path: Path) -> None:
    text = skill_path.read_text(encoding="utf-8")
    assert "ksk_" not in text
    assert "BEGIN PRIVATE KEY" not in text
    for password in _URL_PASSWORD_RE.findall(text):
        assert not password or password.startswith(_PLACEHOLDER_PREFIXES), (
            f"{skill_path} has a URL with a literal password"
        )
    for token in _SECRET_TOKEN_RE.findall(text):
        assert not _looks_random(token), f"{skill_path}: {token}"


def test_bootstrap_skill_requires_live_sign_in() -> None:
    text = BOOTSTRAP_SKILL.read_text(encoding="utf-8")
    for needle in (
        "production-checklist",
        "login/google/callback",
        "KEYSTONE_MCP_SUPERADMIN_EMAIL",
    ):
        assert needle in text, f"keystone-gateway-bootstrap SKILL.md omits {needle!r}"
    assert re.search(r"`?readyz`? does not check sign-in", text), (
        "keystone-gateway-bootstrap SKILL.md must say readyz does not check sign-in"
    )


def test_bootstrap_skill_never_reads_env_file() -> None:
    text = BOOTSTRAP_SKILL.read_text(encoding="utf-8")
    forbidden = re.compile(
        r"(?:\bcat|\bless|\bmore|\bhead|\btail|\bgrep|\bsource|\bsed)\s+[^\n|>]*\.env\b|"
        r"(?:^|\s)\.\s+\.env\b|<\s*\.env\b",
        re.MULTILINE,
    )
    hits = [match.group(0) for match in forbidden.finditer(text)]
    assert not hits, f"keystone-gateway-bootstrap SKILL.md reads .env: {hits}"
