"""Invariants a :class:`~keystone_mcp.rbac.policy_store.PolicyStore` change must keep.

These run on the *candidate* policy -- after catalog validation passed, before
the file is written -- so a policy change can never (a) leave every
administering tool unreachable by any role, (b) strip the acting
administrator's own access to the policy tools, or (c) delete a role that is
still assigned to someone. Each violation is reported as a
:class:`~keystone_mcp.rbac.policy_document.PolicyChangeError` with a stable
``code`` (see that class's docstring for the full list).
"""

from __future__ import annotations

from collections.abc import Collection
from fnmatch import fnmatch
from typing import TYPE_CHECKING

from keystone_mcp.rbac.policy_document import PolicyChangeError, RoleDelete
from keystone_mcp.user_directory.errors import UserDirectoryError, UsersError

if TYPE_CHECKING:
    from keystone_mcp.rbac.policy import RbacPolicy
    from keystone_mcp.rbac.policy_document import PolicyChange
    from keystone_mcp.user_directory.protocol import UserDirectory

#: Published-name globs that administer this server: whoever cannot reach
#: these cannot manage people or policy at all. ``policy_*`` is reserved by
#: this release even though V01 ships no ``policy_*`` tool yet (V02 does) --
#: checking it now means a V01-era change cannot accidentally create a
#: deployment no future ``policy_*`` tool could recover from.
_ADMINISTERING_PATTERNS: tuple[str, ...] = ("users_*", "policy_*")


def check_no_role_can_administer(candidate: RbacPolicy, live_tool_names: Collection[str]) -> None:
    """Refuse a change that leaves an administering tool unreachable by every role."""
    administering = sorted(
        name
        for name in set(live_tool_names)
        if any(fnmatch(name, pattern) for pattern in _ADMINISTERING_PATTERNS)
    )
    for tool in administering:
        if not candidate.allowed_by_any_role(tool):
            raise PolicyChangeError(
                "policy_invariant",
                f"no role would be able to call {tool}; keep at least one administering role",
            )


def check_self_lockout_forbidden(
    candidate: RbacPolicy, actor_roles: frozenset[str], live_tool_names: Collection[str]
) -> None:
    """Refuse a change that would remove the acting administrator's own ``policy_*`` access."""
    policy_tools = sorted(name for name in set(live_tool_names) if fnmatch(name, "policy_*"))
    for tool in policy_tools:
        if not candidate.allows(actor_roles, tool):
            raise PolicyChangeError(
                "self_lockout_forbidden",
                "this change would remove your own access to policy tools; "
                "another administrator must make it",
            )


async def check_role_in_use(change: PolicyChange, directory: UserDirectory | None) -> None:
    """Refuse deleting a role still assigned to an active human or service account.

    Only :class:`~keystone_mcp.rbac.policy_document.RoleDelete` is checked;
    every other change kind is a no-op here. A blocked holder does not block
    the deletion. ``directory is None`` or an unreachable directory is
    ``service_unavailable`` -- the change is not applied rather than risking
    an orphaned role assignment.
    """
    if not isinstance(change, RoleDelete):
        return
    role = change.role.strip()
    if directory is None:
        raise PolicyChangeError(
            "service_unavailable", "user directory is not configured; cannot check role usage"
        )
    try:
        holders = await directory.list_users(is_blocked=False, role=role)
    except (UserDirectoryError, UsersError) as exc:
        raise PolicyChangeError("service_unavailable", str(exc)) from exc

    service_account_count = 0
    list_service_accounts = getattr(directory, "list_service_accounts", None)
    if callable(list_service_accounts) and "service_accounts" in directory.capabilities:
        try:
            service_accounts = await list_service_accounts(is_blocked=False)
        except (UserDirectoryError, UsersError) as exc:
            raise PolicyChangeError("service_unavailable", str(exc)) from exc
        service_account_count = sum(1 for account in service_accounts if role in account.roles)

    total = len(holders) + service_account_count
    if total:
        raise PolicyChangeError(
            "role_in_use",
            f"role {role!r} is assigned to {total} active account(s); reassign them first",
        )
