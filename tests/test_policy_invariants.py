"""Tests for the PolicyStore write-path invariants.

These run on an already catalog-validated candidate ``RbacPolicy`` (or, for
``check_role_in_use``, against a ``PolicyChange``), independent of
``PolicyStore`` itself.
"""

from __future__ import annotations

import pytest

from keystone_mcp.rbac.policy import parse_policy_yaml
from keystone_mcp.rbac.policy_document import PolicyChangeError, RoleDelete, VersionSet
from keystone_mcp.rbac.policy_invariants import (
    check_no_role_can_administer,
    check_role_in_use,
    check_self_lockout_forbidden,
)
from keystone_mcp.user_directory.errors import UsersStoreUnavailableError
from keystone_mcp.user_directory.memory import InMemoryUserDirectory

LIVE_TOOLS = frozenset({"users_list", "users_add", "policy_read", "policy_role_set", "docs_search"})


def _policy(yaml_text: str):
    return parse_policy_yaml(yaml_text, source_path=None)


# ── no_role_can_administer ──────────────────────────────────────────────────


def test_no_role_can_administer_passes_when_one_role_allows_everything() -> None:
    policy = _policy(
        """
        version: "1"
        default_deny: true
        roles:
          administrator:
            allow: ["*"]
        """
    )
    check_no_role_can_administer(policy, LIVE_TOOLS)  # does not raise


def test_no_role_can_administer_raises_when_nobody_can_reach_users_or_policy_tools() -> None:
    policy = _policy(
        """
        version: "1"
        default_deny: true
        roles:
          viewer:
            allow: ["docs_search"]
        """
    )
    with pytest.raises(PolicyChangeError) as exc_info:
        check_no_role_can_administer(policy, LIVE_TOOLS)
    assert exc_info.value.code == "policy_invariant"


def test_no_role_can_administer_ignores_tools_outside_the_live_catalog() -> None:
    # No live users_*/policy_* tool at all: nothing to administer, so there is
    # nothing this invariant can refuse.
    policy = _policy(
        """
        version: "1"
        default_deny: true
        roles:
          viewer:
            allow: ["docs_search"]
        """
    )
    check_no_role_can_administer(policy, frozenset({"docs_search", "docs_read"}))


# ── self_lockout_forbidden ───────────────────────────────────────────────────


def test_self_lockout_forbidden_passes_when_actor_keeps_policy_access() -> None:
    policy = _policy(
        """
        version: "1"
        default_deny: true
        roles:
          administrator:
            allow: ["*"]
          editor:
            allow: ["docs_search", "policy_*"]
        """
    )
    check_self_lockout_forbidden(policy, frozenset({"editor"}), LIVE_TOOLS)


def test_self_lockout_forbidden_raises_when_actor_loses_all_policy_tools() -> None:
    policy = _policy(
        """
        version: "1"
        default_deny: true
        roles:
          administrator:
            allow: ["*"]
          editor:
            allow: ["docs_search"]
        """
    )
    with pytest.raises(PolicyChangeError) as exc_info:
        check_self_lockout_forbidden(policy, frozenset({"editor"}), LIVE_TOOLS)
    assert exc_info.value.code == "self_lockout_forbidden"


def test_self_lockout_forbidden_ignores_other_administrators() -> None:
    # The acting administrator's OWN roles keep policy_* access; a different
    # role losing it is not this actor's problem.
    policy = _policy(
        """
        version: "1"
        default_deny: true
        roles:
          administrator:
            allow: ["*"]
          editor:
            allow: ["docs_search"]
        """
    )
    check_self_lockout_forbidden(policy, frozenset({"administrator"}), LIVE_TOOLS)


# ── role_in_use ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_role_in_use_allows_deleting_an_unassigned_role() -> None:
    directory = InMemoryUserDirectory()
    directory.seed("admin@example.com", roles=("administrator",))
    await check_role_in_use(RoleDelete("editor"), directory)  # does not raise


@pytest.mark.asyncio
async def test_role_in_use_refuses_deleting_a_role_held_by_an_active_account() -> None:
    directory = InMemoryUserDirectory()
    directory.seed("editor@example.com", roles=("editor",), is_blocked=False)
    with pytest.raises(PolicyChangeError) as exc_info:
        await check_role_in_use(RoleDelete("editor"), directory)
    assert exc_info.value.code == "role_in_use"
    assert "editor" in str(exc_info.value)


@pytest.mark.asyncio
async def test_role_in_use_ignores_a_blocked_holder() -> None:
    directory = InMemoryUserDirectory()
    directory.seed("editor@example.com", roles=("editor",), is_blocked=True)
    await check_role_in_use(RoleDelete("editor"), directory)  # does not raise


@pytest.mark.asyncio
async def test_role_in_use_is_a_noop_for_non_delete_changes() -> None:
    directory = InMemoryUserDirectory()
    directory.seed("editor@example.com", roles=("editor",))
    await check_role_in_use(VersionSet("2.0.0"), directory)  # does not raise


@pytest.mark.asyncio
async def test_role_in_use_without_a_directory_is_service_unavailable() -> None:
    with pytest.raises(PolicyChangeError) as exc_info:
        await check_role_in_use(RoleDelete("editor"), None)
    assert exc_info.value.code == "service_unavailable"


@pytest.mark.asyncio
async def test_role_in_use_directory_error_is_service_unavailable() -> None:
    class _BrokenDirectory(InMemoryUserDirectory):
        async def list_users(self, **_kwargs):
            raise UsersStoreUnavailableError("database is down")

    with pytest.raises(PolicyChangeError) as exc_info:
        await check_role_in_use(RoleDelete("editor"), _BrokenDirectory())
    assert exc_info.value.code == "service_unavailable"
