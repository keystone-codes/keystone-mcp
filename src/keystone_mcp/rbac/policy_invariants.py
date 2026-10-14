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

from keystone_mcp.rbac.management import is_full_administrator
from keystone_mcp.rbac.policy_document import PolicyChangeError, RoleDelete
from keystone_mcp.user_directory.errors import UserDirectoryError, UsersError

if TYPE_CHECKING:
    from keystone_mcp.rbac.policy import RbacPolicy
    from keystone_mcp.rbac.policy_document import PolicyChange
    from keystone_mcp.user_directory.protocol import UserDirectory

#: Published-name globs that administer this server: whoever cannot reach
#: these cannot manage people or policy at all. ``policy_*`` is included so
#: that no policy change can leave a deployment that nobody can administer
#: through the tools.
_ADMINISTERING_PATTERNS: tuple[str, ...] = ("users_*", "policy_*")


def _role_can_reach_tool(
    candidate: RbacPolicy, tool: str, *, interactive_login_available: bool
) -> bool:
    if not candidate.allowed_by_any_role(tool):
        return False
    if candidate.requires_human_identity(tool) and not interactive_login_available:
        return False
    return True


def check_no_role_can_administer(
    candidate: RbacPolicy,
    live_tool_names: Collection[str],
    *,
    interactive_login_available: bool = True,
) -> None:
    """Refuse a change that leaves an administering tool unreachable by every role."""
    administering = sorted(
        name
        for name in set(live_tool_names)
        if any(fnmatch(name, pattern) for pattern in _ADMINISTERING_PATTERNS)
    )
    for tool in administering:
        if _role_can_reach_tool(
            candidate, tool, interactive_login_available=interactive_login_available
        ):
            continue
        message = f"no role would be able to call {tool}; keep at least one administering role"
        if candidate.requires_human_identity(tool) and not interactive_login_available:
            message += (
                ": it would require an interactive sign-in and no interactive "
                "login provider is configured"
            )
        raise PolicyChangeError("policy_invariant", message)


def check_self_lockout_forbidden(
    candidate: RbacPolicy,
    actor_roles: frozenset[str],
    live_tool_names: Collection[str],
    *,
    actor_interactive: bool = True,
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
        if candidate.requires_human_identity(tool) and not actor_interactive:
            raise PolicyChangeError(
                "self_lockout_forbidden",
                "this change would remove your own access to policy tools; "
                "another administrator must make it (you are not signed in interactively)",
            )


async def check_full_administrator_remains(
    before: RbacPolicy,
    candidate: RbacPolicy,
    directory: UserDirectory | None,
) -> None:
    """Refuse a change that would leave no active person with full administration."""
    if directory is None:
        return
    try:
        people = await directory.list_users(is_blocked=False)
    except (UserDirectoryError, UsersError) as exc:
        raise PolicyChangeError("service_unavailable", str(exc)) from exc

    before_count = sum(1 for person in people if is_full_administrator(before, person.roles))
    if before_count == 0:
        return
    after_count = sum(1 for person in people if is_full_administrator(candidate, person.roles))
    if after_count == 0:
        raise PolicyChangeError(
            "policy_invariant",
            "this change would leave no active person with full administration",
        )


async def check_role_in_use(change: PolicyChange, directory: UserDirectory | None) -> None:
    """Refuse deleting a role still assigned to a human or service account.

    Only :class:`~keystone_mcp.rbac.policy_document.RoleDelete` is checked;
    every other change kind is a no-op here. A blocked holder blocks the
    deletion too: deleting and recreating a role must not silently hand new
    permissions to a blocked person on unblock. ``directory is None`` or an
    unreachable directory is ``service_unavailable`` -- the change is not
    applied rather than risking an orphaned role assignment.
    """
    if not isinstance(change, RoleDelete):
        return
    role = change.role.strip()
    if directory is None:
        raise PolicyChangeError(
            "service_unavailable", "user directory is not configured; cannot check role usage"
        )
    try:
        holders = await directory.list_users(is_blocked=None, role=role)
    except (UserDirectoryError, UsersError) as exc:
        raise PolicyChangeError("service_unavailable", str(exc)) from exc

    service_account_count = 0
    list_service_accounts = getattr(directory, "list_service_accounts", None)
    if callable(list_service_accounts) and "service_accounts" in directory.capabilities:
        try:
            service_accounts = await list_service_accounts(is_blocked=None)
        except (UserDirectoryError, UsersError) as exc:
            raise PolicyChangeError("service_unavailable", str(exc)) from exc
        service_account_count = sum(1 for account in service_accounts if role in account.roles)

    total = len(holders) + service_account_count
    if total:
        raise PolicyChangeError(
            "role_in_use",
            f"role {role!r} is assigned to {total} account(s), including blocked ones; "
            "revoke it from them first",
        )
