"""Role-name normalization and validation.

Role names themselves come from the deployment's RBAC policy file, not from
any constant in this package. ``administrator`` is the one name the users
directory needs to know on its own: it governs seeding and emergency access
recovery, and is always accepted regardless of the active policy.
"""

from __future__ import annotations

from collections.abc import Sequence

from keystone_mcp.users.errors import InvalidRoleError

ROLE_ADMINISTRATOR = "administrator"
MAX_ROLE_LENGTH = 64


def check_role_name(role: str) -> str:
    """Validate the format of a single role name, regardless of policy.

    Used where a role must be accepted even if it is no longer part of the
    active policy: revoking a role, or filtering ``list_users`` by role.
    """
    role_name = role.strip()
    if not role_name or len(role_name) > MAX_ROLE_LENGTH:
        raise InvalidRoleError(role_name, reason="format")
    return role_name


def normalize_roles(
    roles: Sequence[str],
    *,
    allowed: frozenset[str] | None,
) -> list[str]:
    """Validate and deduplicate a sequence of role names.

    ``allowed`` is the set of role names known to the active RBAC policy.
    ``administrator`` is always accepted, policy or not. ``allowed=None``
    means "no policy is loaded, skip the policy check" (format is still
    checked). Order of first appearance is preserved; duplicates are dropped.
    """
    normalized: list[str] = []
    for role in roles:
        role_name = check_role_name(role)
        if allowed is not None and role_name != ROLE_ADMINISTRATOR and role_name not in allowed:
            raise InvalidRoleError(role_name, reason="unknown")
        if role_name not in normalized:
            normalized.append(role_name)
    return normalized
