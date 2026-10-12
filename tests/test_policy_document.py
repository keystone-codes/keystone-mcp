"""Tests for the editable PolicyDocument model and its PolicyChange union."""

from __future__ import annotations

from pathlib import Path

import pytest

from keystone_mcp.rbac.policy import PolicyContractError
from keystone_mcp.rbac.policy_document import (
    AllowAdd,
    AllowRemove,
    ListSet,
    PolicyChangeError,
    PolicyDocument,
    RoleBody,
    RoleDelete,
    RoleSet,
    VersionSet,
    describe_change,
    describe_changes,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _strip_date_line(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.startswith("# Managed"))


@pytest.mark.parametrize(
    "policy_file",
    [
        REPO_ROOT / "config" / "rbac-policy.yaml",
        REPO_ROOT / "examples" / "rbac-policy.full-example.yaml",
    ],
)
def test_from_yaml_to_yaml_round_trip_is_semantically_idempotent(policy_file: Path) -> None:
    raw = policy_file.read_text(encoding="utf-8")
    doc = PolicyDocument.from_yaml(raw)

    rendered = doc.to_yaml(actor="tester")
    doc_again = PolicyDocument.from_yaml(rendered)

    assert doc_again.to_policy() == doc.to_policy()


@pytest.mark.parametrize(
    "policy_file",
    [
        REPO_ROOT / "config" / "rbac-policy.yaml",
        REPO_ROOT / "examples" / "rbac-policy.full-example.yaml",
    ],
)
def test_to_yaml_is_deterministic_except_the_date_line(policy_file: Path) -> None:
    doc = PolicyDocument.from_yaml(policy_file.read_text(encoding="utf-8"))

    first = doc.to_yaml(actor="alice@example.com")
    second = doc.to_yaml(actor="alice@example.com")

    # Only the header's "last change" timestamp line may differ between runs.
    assert _strip_date_line(first) == _strip_date_line(second)


def test_to_yaml_role_and_key_order_is_deterministic() -> None:
    doc = PolicyDocument(
        version="1.0.0",
        roles={
            "zebra": RoleBody(description="", allow=["z_*"]),
            "alpha": RoleBody(description="", allow=["a_*"]),
        },
    )
    rendered = doc.to_yaml(actor="a")
    lines = [line for line in rendered.splitlines() if line and not line.startswith("#")]
    # Top-level keys appear in POLICY_TOP_LEVEL_KEYS order.
    top_level = [line.split(":")[0] for line in lines if not line.startswith((" ", "-"))]
    assert top_level == [
        "version",
        "default_deny",
        "roles",
        "deny",
        "requires_human_identity",
        "critical_tools",
        "reserved_allow_patterns",
        "tool_dispositions",
    ]
    # Roles are alphabetical.
    role_index = top_level.index("roles")
    assert rendered.index("alpha") < rendered.index("zebra")
    assert role_index >= 0


def test_header_comment_present() -> None:
    doc = PolicyDocument(version="1.0.0", roles={"admin": RoleBody(description="", allow=["*"])})
    rendered = doc.to_yaml(actor="bob@example.com")
    assert rendered.startswith("# Managed by keystone-mcp policy tools (last change ")
    assert "by bob@example.com" in rendered.splitlines()[0]
    assert "Hand-written comments are not preserved" in rendered.splitlines()[1]


def test_from_yaml_rejects_unknown_top_level_key() -> None:
    raw = """\
version: "1.0.0"
default_deny: true
roles:
  admin:
    allow: ["*"]
bogus_key: true
"""
    with pytest.raises(PolicyContractError, match="unknown top-level keys"):
        PolicyDocument.from_yaml(raw)


@pytest.fixture
def document() -> PolicyDocument:
    return PolicyDocument(
        version="1.0.0",
        roles={
            "administrator": RoleBody(description="admin", allow=["*"]),
            "editor": RoleBody(description="editor", allow=["documents_read", "documents_write"]),
        },
    )


# ── RoleSet ──────────────────────────────────────────────────────────────────


def test_role_set_creates_new_role(document: PolicyDocument) -> None:
    updated = document.apply(RoleSet("viewer", ["reports_read"], "read only"))
    assert updated.roles["viewer"].allow == ["reports_read"]
    assert updated.roles["viewer"].description == "read only"
    assert updated != document


def test_role_set_replaces_existing_role(document: PolicyDocument) -> None:
    updated = document.apply(RoleSet("editor", ["documents_*"], "broader"))
    assert updated.roles["editor"].allow == ["documents_*"]


def test_role_set_rejects_invalid_role_name(document: PolicyDocument) -> None:
    with pytest.raises(PolicyChangeError) as exc_info:
        document.apply(RoleSet("bad name!", ["x_*"]))
    assert exc_info.value.code == "validation_error"


def test_role_set_rejects_empty_allow(document: PolicyDocument) -> None:
    with pytest.raises(PolicyChangeError) as exc_info:
        document.apply(RoleSet("viewer", []))
    assert exc_info.value.code == "validation_error"


def test_role_set_rejects_empty_pattern(document: PolicyDocument) -> None:
    with pytest.raises(PolicyChangeError) as exc_info:
        document.apply(RoleSet("viewer", ["  "]))
    assert exc_info.value.code == "validation_error"


# ── RoleDelete ───────────────────────────────────────────────────────────────


def test_role_delete_removes_role(document: PolicyDocument) -> None:
    updated = document.apply(RoleDelete("editor"))
    assert "editor" not in updated.roles


def test_role_delete_unknown_role_is_role_not_found(document: PolicyDocument) -> None:
    with pytest.raises(PolicyChangeError) as exc_info:
        document.apply(RoleDelete("nope"))
    assert exc_info.value.code == "role_not_found"


# ── AllowAdd ─────────────────────────────────────────────────────────────────


def test_allow_add_appends_new_patterns(document: PolicyDocument) -> None:
    updated = document.apply(AllowAdd("editor", ["reports_read"]))
    assert updated.roles["editor"].allow == ["documents_read", "documents_write", "reports_read"]


def test_allow_add_unknown_role_is_role_not_found(document: PolicyDocument) -> None:
    with pytest.raises(PolicyChangeError) as exc_info:
        document.apply(AllowAdd("nope", ["x_*"]))
    assert exc_info.value.code == "role_not_found"


def test_allow_add_existing_pattern_is_a_noop(document: PolicyDocument) -> None:
    updated = document.apply(AllowAdd("editor", ["documents_read"]))
    assert updated == document


def test_allow_add_rejects_empty_pattern(document: PolicyDocument) -> None:
    with pytest.raises(PolicyChangeError) as exc_info:
        document.apply(AllowAdd("editor", [""]))
    assert exc_info.value.code == "validation_error"


# ── AllowRemove ──────────────────────────────────────────────────────────────


def test_allow_remove_drops_pattern(document: PolicyDocument) -> None:
    updated = document.apply(AllowRemove("editor", ["documents_write"]))
    assert updated.roles["editor"].allow == ["documents_read"]


def test_allow_remove_unknown_role_is_role_not_found(document: PolicyDocument) -> None:
    with pytest.raises(PolicyChangeError) as exc_info:
        document.apply(AllowRemove("nope", ["x_*"]))
    assert exc_info.value.code == "role_not_found"


def test_allow_remove_absent_pattern_is_a_noop(document: PolicyDocument) -> None:
    updated = document.apply(AllowRemove("editor", ["reports_read"]))
    assert updated == document


def test_allow_remove_last_pattern_is_validation_error(document: PolicyDocument) -> None:
    with pytest.raises(PolicyChangeError) as exc_info:
        document.apply(AllowRemove("administrator", ["*"]))
    assert exc_info.value.code == "validation_error"
    assert "delete the role instead" in str(exc_info.value)


# ── ListSet ──────────────────────────────────────────────────────────────────


def test_list_set_replaces_section(document: PolicyDocument) -> None:
    updated = document.apply(ListSet("deny", ["documents_purge"]))
    assert updated.deny == ["documents_purge"]


def test_list_set_unknown_name_is_validation_error(document: PolicyDocument) -> None:
    with pytest.raises(PolicyChangeError) as exc_info:
        document.apply(ListSet("not_a_real_list", ["x"]))
    assert exc_info.value.code == "validation_error"


# ── VersionSet ───────────────────────────────────────────────────────────────


def test_version_set_updates_version(document: PolicyDocument) -> None:
    updated = document.apply(VersionSet("2.0.1"))
    assert updated.version == "2.0.1"


def test_version_set_rejects_empty_version(document: PolicyDocument) -> None:
    with pytest.raises(PolicyChangeError) as exc_info:
        document.apply(VersionSet("  "))
    assert exc_info.value.code == "validation_error"


# ── describe_change: no pattern text ever leaks ─────────────────────────────


def test_describe_change_never_includes_pattern_text() -> None:
    changes = [
        RoleSet("files_user", ["files_secret_tool"]),
        AllowAdd("files_user", ["files_a", "files_b"]),
        AllowRemove("files_user", ["files_a"]),
        RoleDelete("files_user"),
        ListSet("critical_tools", ["files_secret_tool"]),
        VersionSet("3.0.0"),
    ]
    described = describe_changes(changes)
    assert described == (
        "role_set:files_user",
        "allow_add:files_user:+2",
        "allow_remove:files_user:-1",
        "role_delete:files_user",
        "list_set:critical_tools",
        "version_set",
    )
    for text in described:
        assert "files_secret_tool" not in text


def test_describe_change_single() -> None:
    assert describe_change(VersionSet("1.2.3")) == "version_set"
