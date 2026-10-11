"""RBAC policy file contract: parsing, validation and matrix generation."""

from __future__ import annotations

from pathlib import Path

import pytest

from keystone_mcp.rbac.matrix_doc import (
    generate_per_tool_matrix_markdown,
    policy_tool_universe,
    tool_disposition,
)
from keystone_mcp.rbac.policy import (
    FALLBACK_DISPOSITION,
    POLICY_TOP_LEVEL_KEYS,
    PolicyContractError,
    assert_catalog_validation,
    default_policy_path,
    load_policy,
    load_policy_file,
    parse_policy_yaml,
    policy_content_hash,
    validate_policy_against_catalog,
    validate_policy_structure,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PER_TOOL_MATRIX = _REPO_ROOT / "docs" / "rbac-role-matrix-per-tool.md"
_FULL_EXAMPLE = _REPO_ROOT / "examples" / "rbac-policy.full-example.yaml"

MINIMAL_POLICY = """
version: "1.2.3"
default_deny: true
roles:
  viewer:
    allow: ["reports_read"]
  editor:
    allow: ["reports_*"]
"""


@pytest.fixture
def default_policy():
    return load_policy()


@pytest.fixture
def minimal_policy():
    return parse_policy_yaml(MINIMAL_POLICY)


# --- shipped default -----------------------------------------------------------


def test_default_policy_path_points_to_shipped_yaml():
    path = default_policy_path()
    assert path.name == "rbac-policy.yaml"
    assert path.parent.name == "config"
    assert path.is_file()


def test_default_policy_is_generic_v2(default_policy):
    assert default_policy.version == "2.0.0"
    assert default_policy.default_deny is True
    assert default_policy.role_names == frozenset({"administrator"})
    assert default_policy.human_identity_patterns == ()
    assert default_policy.critical_tool_patterns == ()
    assert default_policy.reserved_allow_patterns == ()


def test_default_policy_administrator_allows_user_administration(default_policy):
    assert default_policy.allows_role("administrator", "users_list") is True


def test_default_policy_has_no_member_role(default_policy):
    assert "member" not in default_policy.role_names


def test_default_policy_validates_against_its_own_tool_universe(default_policy):
    result = assert_catalog_validation(
        default_policy,
        policy_tool_universe(default_policy),
    )
    assert result.ok
    assert result.unreachable_tools == frozenset()


def test_shipped_full_example_loads_and_validates():
    policy = load_policy_file(_FULL_EXAMPLE)
    validate_policy_structure(policy)
    assert "reports_approve_*" in policy.reserved_allow_patterns
    assert policy.requires_human_identity("ledger_commit") is True
    assert policy.is_critical_tool("ledger_read") is True


# --- free-form roles -----------------------------------------------------------


def test_free_form_role_names_load(minimal_policy):
    assert minimal_policy.role_names == frozenset({"viewer", "editor"})
    validate_policy_structure(minimal_policy)


def test_policy_with_two_arbitrary_roles_is_accepted():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  viewer:
    allow: ["reports_read"]
  editor:
    allow: ["reports_write"]
"""
    )
    validate_policy_structure(policy)
    assert sorted(policy.role_names) == ["editor", "viewer"]
    assert policy.allows_role("viewer", "reports_read") is True
    assert policy.allows_role("viewer", "reports_write") is False
    assert policy.allows_role("nonexistent_role", "reports_read") is False


def test_single_role_policy_is_accepted():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  solo:
    allow: ["*"]
"""
    )
    validate_policy_structure(policy)
    assert policy.role_names == frozenset({"solo"})


def test_policy_without_any_role_is_refused():
    policy = parse_policy_yaml('version: "0.1"\ndefault_deny: true\nroles: {}\n')
    with pytest.raises(PolicyContractError, match="at least one role"):
        validate_policy_structure(policy)


def test_role_with_empty_allow_list_is_refused():
    with pytest.raises(PolicyContractError, match="non-empty list"):
        parse_policy_yaml('version: "0.1"\ndefault_deny: true\nroles:\n  viewer:\n    allow: []\n')


def test_role_with_blank_allow_pattern_is_refused():
    policy = parse_policy_yaml(
        'version: "0.1"\ndefault_deny: true\nroles:\n  viewer:\n    allow: ["  "]\n'
    )
    with pytest.raises(PolicyContractError, match="empty allow pattern"):
        validate_policy_structure(policy)


def test_decisions_for_tool_covers_declared_roles(minimal_policy):
    decisions = minimal_policy.decisions_for_tool("reports_read")
    assert set(decisions) == {"viewer", "editor"}
    assert all(isinstance(value, bool) for value in decisions.values())


# --- structural invariants ------------------------------------------------------


def test_default_deny_false_is_refused():
    policy = parse_policy_yaml(
        'version: "0.1"\ndefault_deny: false\nroles:\n  viewer:\n    allow: ["*"]\n'
    )
    with pytest.raises(PolicyContractError, match="default_deny"):
        validate_policy_structure(policy)


def test_default_deny_rejects_string_values():
    with pytest.raises(PolicyContractError, match="default_deny must be a boolean"):
        parse_policy_yaml(
            'version: "0.1"\ndefault_deny: "false"\nroles:\n  viewer:\n    allow: ["*"]\n'
        )


def test_blank_version_is_refused():
    policy = parse_policy_yaml(
        'version: "  "\ndefault_deny: true\nroles:\n  viewer:\n    allow: ["*"]\n'
    )
    with pytest.raises(PolicyContractError, match="version"):
        validate_policy_structure(policy)


def test_unknown_top_level_key_is_refused():
    with pytest.raises(PolicyContractError, match="unknown top-level keys"):
        parse_policy_yaml(
            """
version: "0.1"
default_deny: true
canonical_roles: ["viewer"]
roles:
  viewer:
    allow: ["*"]
"""
        )


def test_v1_style_file_with_unknown_keys_names_every_offender():
    with pytest.raises(PolicyContractError) as excinfo:
        parse_policy_yaml(
            """
version: "1.0.0"
default_deny: true
human_identity_required_tools: ["ledger_commit"]
published_catalog: ["reports_read"]
roles:
  viewer:
    allow: ["reports_read"]
"""
        )
    message = str(excinfo.value)
    assert "human_identity_required_tools" in message
    assert "published_catalog" in message
    assert "requires_human_identity" in message  # allowed-keys hint


def test_allowed_top_level_keys_are_exactly_the_documented_set():
    assert POLICY_TOP_LEVEL_KEYS == frozenset(
        {
            "version",
            "default_deny",
            "roles",
            "deny",
            "requires_human_identity",
            "critical_tools",
            "reserved_allow_patterns",
            "tool_dispositions",
        }
    )


def test_non_mapping_root_is_refused():
    with pytest.raises(PolicyContractError, match="mapping"):
        parse_policy_yaml("- not-a-mapping\n")


def test_invalid_yaml_is_refused():
    with pytest.raises(PolicyContractError, match="invalid YAML"):
        parse_policy_yaml("roles: [unclosed\n")


def test_scalar_sections_are_refused():
    with pytest.raises(PolicyContractError, match="critical_tools must be a list"):
        parse_policy_yaml(
            'version: "0.1"\ndefault_deny: true\ncritical_tools: ledger_read\n'
            'roles:\n  viewer:\n    allow: ["*"]\n'
        )
    with pytest.raises(PolicyContractError, match="tool_dispositions must be a mapping"):
        parse_policy_yaml(
            'version: "0.1"\ndefault_deny: true\ntool_dispositions: ["R"]\n'
            'roles:\n  viewer:\n    allow: ["*"]\n'
        )


# --- matching semantics ---------------------------------------------------------


def test_glob_and_literal_matching(minimal_policy):
    assert minimal_policy.allows_role("editor", "reports_write") is True
    assert minimal_policy.allows_role("editor", "documents_write") is False
    assert minimal_policy.allows_role("viewer", "reports_read") is True
    assert minimal_policy.allows_role("viewer", "reports_write") is False


def test_multi_role_union():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  editor:
    allow: ["documents_*"]
  reviewer:
    allow: ["reports_approve_release"]
"""
    )
    roles = frozenset({"editor", "reviewer"})
    assert policy.allows(roles, "documents_write") is True
    assert policy.allows(roles, "reports_approve_release") is True
    assert policy.allows(frozenset({"editor"}), "reports_approve_release") is False


def test_empty_role_set_is_always_denied(minimal_policy):
    assert minimal_policy.allows(frozenset(), "reports_read") is False


def test_deny_list_overrides_wildcard_allow():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
deny: ["documents_purge"]
roles:
  administrator:
    allow: ["*"]
"""
    )
    assert policy.is_globally_denied("documents_purge") is True
    assert policy.allows_role("administrator", "documents_purge") is False
    assert policy.allows_role("administrator", "documents_read") is True


def test_unknown_future_tool_is_denied_unless_wildcard(minimal_policy):
    assert minimal_policy.allows_role("editor", "brand_new_future_tool") is False


def test_allowed_by_any_role(minimal_policy):
    assert minimal_policy.allowed_by_any_role("reports_read") is True
    assert minimal_policy.allowed_by_any_role("documents_read") is False


# --- catalog validation ---------------------------------------------------------


def test_unmatched_allow_pattern_is_a_typo_refusal(minimal_policy):
    with pytest.raises(PolicyContractError, match="unmatched allow patterns"):
        assert_catalog_validation(minimal_policy, frozenset({"documents_read"}))


def test_wildcard_needs_a_non_empty_catalog():
    policy = parse_policy_yaml(
        'version: "0.1"\ndefault_deny: true\nroles:\n  administrator:\n    allow: ["*"]\n'
    )
    with pytest.raises(PolicyContractError, match="unmatched allow patterns"):
        assert_catalog_validation(policy, frozenset())
    assert assert_catalog_validation(policy, frozenset({"reports_read"})).ok


def test_reserved_allow_pattern_may_match_only_reserved_or_wip_names():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
reserved_allow_patterns: ["reports_approve_*"]
roles:
  reviewer:
    allow: ["reports_approve_*", "reports_read"]
"""
    )
    result = assert_catalog_validation(
        policy,
        frozenset({"reports_read"}),
        wip_tool_names=frozenset({"reports_approve_run"}),
    )
    assert result.ok
    # Same pattern with nothing reserved or WIP to satisfy it is a typo.
    with pytest.raises(PolicyContractError, match="unmatched allow patterns"):
        assert_catalog_validation(policy, frozenset({"reports_read"}))


def test_reserved_allow_pattern_is_not_satisfied_by_an_active_name_alone():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
reserved_allow_patterns: ["reports_approve_*"]
roles:
  reviewer:
    allow: ["reports_approve_*"]
"""
    )
    with pytest.raises(PolicyContractError, match="unmatched allow patterns"):
        assert_catalog_validation(policy, frozenset({"reports_approve_run"}))


def test_reserved_tier_counts_as_a_known_name(minimal_policy):
    result = assert_catalog_validation(
        minimal_policy,
        frozenset(),
        reserved_tool_names=frozenset({"reports_read", "reports_write"}),
    )
    assert result.ok
    assert result.tool_names == frozenset({"reports_read", "reports_write"})


def test_unreachable_tools_are_reported_but_not_fatal(caplog):
    policy = parse_policy_yaml(
        'version: "0.1"\ndefault_deny: true\nroles:\n  viewer:\n    allow: ["reports_read"]\n'
    )
    with caplog.at_level("WARNING"):
        result = assert_catalog_validation(
            policy,
            frozenset({"reports_read", "documents_write"}),
        )
    assert result.ok
    assert result.unreachable_tools == frozenset({"documents_write"})
    assert "unreachable by any role" in caplog.text
    assert "documents_write" in caplog.text


def test_denied_tools_are_not_counted_as_unreachable():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
deny: ["documents_purge"]
roles:
  administrator:
    allow: ["*"]
"""
    )
    result = validate_policy_against_catalog(
        policy,
        frozenset({"documents_purge", "reports_read"}),
    )
    assert result.unreachable_tools == frozenset()


# --- hashing / round-trip -------------------------------------------------------


def test_policy_content_hash_is_stable():
    path = default_policy_path()
    first = policy_content_hash(path)
    assert first == policy_content_hash(path)
    assert len(first) == 64


def test_load_policy_file_roundtrip(tmp_path: Path):
    copy = tmp_path / "policy.yaml"
    copy.write_text(default_policy_path().read_text(encoding="utf-8"), encoding="utf-8")
    loaded = load_policy_file(copy)
    assert loaded.version == "2.0.0"
    assert loaded.role_names == frozenset({"administrator"})
    assert loaded.source_path == copy


# --- dispositions / matrix generation -------------------------------------------


def test_dispositions_come_from_the_policy_file():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  administrator:
    allow: ["*"]
tool_dispositions:
  D:
    - ledger_commit
  R:
    - reports_read
    - "*_read"
  W:
    - reports_*
"""
    )
    assert tool_disposition("ledger_commit", policy) == "D"
    assert tool_disposition("reports_read", policy) == "R"
    assert tool_disposition("documents_read", policy) == "R"
    assert tool_disposition("reports_write", policy) == "W"


def test_first_matching_disposition_in_file_order_wins():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  administrator:
    allow: ["*"]
tool_dispositions:
  D:
    - ledger_*
  R:
    - ledger_read
"""
    )
    assert tool_disposition("ledger_read", policy) == "D"


def test_unmatched_tool_falls_back_to_write():
    policy = parse_policy_yaml(
        'version: "0.1"\ndefault_deny: true\nroles:\n  administrator:\n    allow: ["*"]\n'
    )
    assert tool_disposition("anything_at_all", policy) == FALLBACK_DISPOSITION
    assert FALLBACK_DISPOSITION == "W"


def test_arbitrary_disposition_labels_are_allowed():
    policy = parse_policy_yaml(
        """
version: "0.1"
default_deny: true
roles:
  administrator:
    allow: ["*"]
tool_dispositions:
  P:
    - mcp_auth
"""
    )
    assert tool_disposition("mcp_auth", policy) == "P"


def test_policy_tool_universe_uses_literals_and_snapshot(minimal_policy):
    assert policy_tool_universe(minimal_policy) == frozenset({"reports_read"})


def test_generated_matrix_columns_are_the_policy_roles(minimal_policy):
    markdown = generate_per_tool_matrix_markdown(
        minimal_policy,
        frozenset({"reports_read", "reports_write"}),
    )
    assert "| Tool | Disp. | editor | viewer |" in markdown
    assert "| `reports_read` | W | allow | allow |" in markdown
    assert "| `reports_write` | W | allow | deny |" in markdown


def test_generated_per_tool_matrix_matches_committed_file(default_policy):
    expected = generate_per_tool_matrix_markdown(
        default_policy,
        policy_tool_universe(default_policy),
    )
    assert _PER_TOOL_MATRIX.is_file(), "run scripts/generate_role_matrix.py"
    assert _PER_TOOL_MATRIX.read_text(encoding="utf-8") == expected
