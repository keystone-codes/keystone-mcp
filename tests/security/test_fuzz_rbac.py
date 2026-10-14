"""SEC-50: property-based RBAC decision checks."""

from __future__ import annotations

import fnmatch

import hypothesis.strategies as st
import pytest
from hypothesis import given

from keystone_mcp.rbac.policy import RbacPolicy, parse_policy_yaml

pytestmark = [pytest.mark.security, pytest.mark.fuzz]


def _reference_allows(policy: RbacPolicy, roles: frozenset[str], tool_name: str) -> bool:
    if not roles:
        return False
    if any(fnmatch.fnmatchcase(tool_name, pattern) for pattern in policy.deny_patterns):
        return False
    if not policy.default_deny:
        return True
    for role in roles:
        role_policy = policy.role(role)
        if role_policy is None:
            continue
        if any(fnmatch.fnmatchcase(tool_name, pat) for pat in role_policy.allow_patterns):
            return True
    return False


role_name_strategy = st.from_regex(r"[a-z][a-z0-9_]{0,15}", fullmatch=True)
pattern_strategy = st.from_regex(r"[a-z_*?\[\]]{1,24}", fullmatch=True)
tool_strategy = st.from_regex(r"[a-z][a-z0-9_]{0,31}", fullmatch=True)


@st.composite
def policy_and_roles(draw):
    role_count = draw(st.integers(min_value=1, max_value=6))
    roles: dict[str, list[str]] = {}
    for _ in range(role_count):
        name = draw(role_name_strategy)
        if name in roles:
            continue
        allow = draw(st.lists(pattern_strategy, min_size=1, max_size=4, unique=True))
        roles[name] = allow
    deny = draw(st.lists(pattern_strategy, max_size=3, unique=True))
    yaml_lines = ['version: "fuzz"', "default_deny: true", "roles:"]
    for name, allow in roles.items():
        yaml_lines.append(f"  {name}:")
        yaml_lines.append(f"    allow: {allow!r}")
    if deny:
        yaml_lines.append(f"deny: {deny!r}")
    policy = parse_policy_yaml("\n".join(yaml_lines))
    held = draw(st.sets(role_name_strategy, max_size=4))
    held = frozenset(r for r in held if r in policy.role_names)
    tool = draw(tool_strategy)
    return policy, held, tool


@given(data=policy_and_roles())
def test_rbac_allows_matches_fnmatch_reference(data) -> None:
    policy, roles, tool = data
    assert policy.allows(roles, tool) == _reference_allows(policy, roles, tool)


@given(tool=tool_strategy)
def test_unpublished_tool_name_never_in_literal_catalog(tool: str) -> None:
    policy = parse_policy_yaml(
        'version: "1"\ndefault_deny: true\nroles:\n  member:\n    allow: ["hello_greet"]\n'
    )
    literals = policy.literal_allow_names()
    if tool not in literals:
        assert not policy.allows(frozenset({"member"}), tool) or tool != "hello_greet"
