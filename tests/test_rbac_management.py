"""Unit tests for management role helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from keystone_mcp.rbac.management import (
    AdminsReport,
    ManagementView,
    build_admins_report,
    full_administrator_roles,
    is_full_administrator,
    is_management_role,
)
from keystone_mcp.rbac.policy import parse_policy_yaml
from keystone_mcp.user_directory.types import ServiceAccountRecord, UserRecord

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _policy(yaml: str) -> str:
    return yaml


def test_role_reaching_any_admin_tool_is_management() -> None:
    policy = parse_policy_yaml(
        _policy(
            """\
version: "t"
default_deny: true
roles:
  hr: {allow: ["users_*"]}
  ops: {allow: ["us*"]}
  blocker: {allow: ["users_block"]}
  viewer: {allow: ["users_list"]}
  auditor: {allow: ["policy_read", "api_keys_list"]}
  member: {allow: ["docs_read"]}
"""
        )
    )
    assert is_management_role(policy, "hr")
    assert is_management_role(policy, "ops")
    assert is_management_role(policy, "blocker")
    assert not is_management_role(policy, "viewer")
    assert not is_management_role(policy, "auditor")
    assert not is_management_role(policy, "member")


def test_full_administrator_needs_every_admin_tool() -> None:
    full = parse_policy_yaml(
        _policy(
            """\
version: "t"
default_deny: true
roles:
  all: {allow: ["*"]}
"""
        )
    )
    assert is_full_administrator(full, ["all"])

    partial = parse_policy_yaml(
        _policy(
            """\
version: "t"
default_deny: true
roles:
  u: {allow: ["users_*", "policy_*"]}
"""
        )
    )
    assert not is_full_administrator(partial, ["u"])

    split = parse_policy_yaml(
        _policy(
            """\
version: "t"
default_deny: true
roles:
  a: {allow: ["users_*", "service_accounts_*"]}
  b: {allow: ["api_keys_*", "policy_*"]}
"""
        )
    )
    assert is_full_administrator(split, ["a", "b"])


def test_globally_denied_admin_tool_is_not_required() -> None:
    policy = parse_policy_yaml(
        _policy(
            """\
version: "t"
default_deny: true
deny: ["api_keys_issue"]
roles:
  all: {allow: ["*"]}
"""
        )
    )
    assert is_full_administrator(policy, ["all"])


def test_view_is_strict_across_snapshot_and_file() -> None:
    snap = parse_policy_yaml(
        _policy(
            """\
version: "t"
default_deny: true
roles:
  hr: {allow: ["docs_read"]}
  admin: {allow: ["*"]}
"""
        )
    )
    disk = parse_policy_yaml(
        _policy(
            """\
version: "t"
default_deny: true
roles:
  hr: {allow: ["users_block"]}
  admin: {allow: ["users_*"]}
"""
        )
    )
    view = ManagementView((snap, disk))
    assert view.is_management_role("hr")
    assert not view.is_full_administrator(["admin"])


def test_full_administrator_roles_picks_single_roles_only() -> None:
    policy = parse_policy_yaml(
        _policy(
            """\
version: "t"
default_deny: true
roles:
  owner: {allow: ["*"]}
  pair_a: {allow: ["users_*", "service_accounts_*"]}
  pair_b: {allow: ["api_keys_*", "policy_*"]}
"""
        )
    )
    assert full_administrator_roles(policy) == frozenset({"owner"})


def test_build_admins_report_is_pure() -> None:
    policy = parse_policy_yaml(
        _policy(
            """\
version: "t"
default_deny: true
roles:
  administrator: {allow: ["*"]}
  hr: {allow: ["users_*"]}
"""
        )
    )
    people = [
        UserRecord(
            email="admin@example.com",
            full_name="Admin",
            roles=("administrator",),
            is_blocked=False,
            created_at=_NOW,
            updated_at=_NOW,
            created_by=None,
            note=None,
        ),
        UserRecord(
            email="hr@example.com",
            full_name="HR",
            roles=("hr",),
            is_blocked=True,
            created_at=_NOW,
            updated_at=_NOW,
            created_by=None,
            note=None,
        ),
    ]
    services = [
        ServiceAccountRecord(
            name="ci",
            subject="svc:ci",
            description=None,
            roles=("hr",),
            is_blocked=False,
            created_at=_NOW,
            updated_at=_NOW,
            created_by=None,
        )
    ]
    report = build_admins_report(policy, people, services)
    assert isinstance(report, AdminsReport)
    assert report.full_administrators == ("admin@example.com",)
    assert "hr" in report.management_roles
    assert "hr@example.com (blocked)" in report.holders["hr"]
    assert "svc:ci" in report.holders["hr"]
