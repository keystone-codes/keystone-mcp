"""Management roles and full administrators derived from the active RBAC policy."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from keystone_mcp.catalog.names import BUILTIN_TOOL_NAMES, MUTATING_ADMIN_TOOL_NAMES
from keystone_mcp.rbac.loader import PolicyLoadError, RbacPolicyManager
from keystone_mcp.rbac.policy import PolicyContractError, RbacPolicy, load_policy_file_with_hash
from keystone_mcp.user_directory.types import ServiceAccountRecord, UserRecord

logger = logging.getLogger(__name__)

ADMIN_TOOL_NAMES: frozenset[str] = BUILTIN_TOOL_NAMES
MANAGEMENT_TOOL_NAMES: frozenset[str] = MUTATING_ADMIN_TOOL_NAMES


def is_management_role(policy: RbacPolicy, role: str) -> bool:
    return any(policy.allows_role(role, name) for name in MANAGEMENT_TOOL_NAMES)


def management_role_names(policy: RbacPolicy) -> frozenset[str]:
    return frozenset(role.name for role in policy.roles if is_management_role(policy, role.name))


def is_full_administrator(policy: RbacPolicy, roles: Iterable[str]) -> bool:
    role_set = frozenset(roles)
    names = [n for n in ADMIN_TOOL_NAMES if not policy.is_globally_denied(n)]
    return bool(names) and all(policy.allows(role_set, n) for n in names)


def full_administrator_roles(policy: RbacPolicy) -> frozenset[str]:
    return frozenset(
        role.name for role in policy.roles if is_full_administrator(policy, (role.name,))
    )


@dataclass(frozen=True, slots=True)
class ManagementView:
    """The policies a management check must satisfy: snapshot and optional on-disk file."""

    policies: tuple[RbacPolicy, ...]

    def is_management_role(self, role: str) -> bool:
        return any(is_management_role(policy, role) for policy in self.policies)

    def management_roles(self, roles: Iterable[str]) -> frozenset[str]:
        return frozenset(role for role in roles if self.is_management_role(role))

    def is_full_administrator(self, roles: Iterable[str]) -> bool:
        role_set = tuple(roles)
        return all(is_full_administrator(policy, role_set) for policy in self.policies)


ManagementSource = Callable[[], Awaitable[ManagementView]]


def snapshot_and_file_management_source(policy_manager: RbacPolicyManager) -> ManagementSource:
    async def _load() -> ManagementView:
        snapshot = policy_manager.snapshot
        if snapshot is None:
            raise PolicyLoadError("RBAC policy has not been loaded")
        try:
            path = policy_manager.policy_path()
            fresh_policy, content_hash = await asyncio.to_thread(load_policy_file_with_hash, path)
        except (PolicyLoadError, PolicyContractError, OSError) as exc:
            logger.warning("management check uses the loaded policy only: %s", exc)
            return ManagementView((snapshot.policy,))
        if content_hash == snapshot.identity.content_hash:
            return ManagementView((snapshot.policy,))
        return ManagementView((snapshot.policy, fresh_policy))

    return _load


def file_management_source(policy_path: str) -> ManagementSource:
    async def _load() -> ManagementView:
        policy, _content_hash = await asyncio.to_thread(
            load_policy_file_with_hash, Path(policy_path)
        )
        return ManagementView((policy,))

    return _load


@dataclass(frozen=True, slots=True)
class AdminsReport:
    management_roles: tuple[str, ...]
    full_administrator_roles: tuple[str, ...]
    full_administrators: tuple[str, ...]
    holders: dict[str, tuple[str, ...]]


def _holder_label(subject: str, *, is_blocked: bool) -> str:
    if is_blocked:
        return f"{subject} (blocked)"
    return subject


def _mutating_admin_tools_for_role(policy: RbacPolicy, role: str) -> frozenset[str]:
    if role not in policy.role_names:
        return frozenset()
    return frozenset(tool for tool in MANAGEMENT_TOOL_NAMES if policy.allows_role(role, tool))


def management_change_reasons(before: RbacPolicy, after: RbacPolicy) -> tuple[str, ...]:
    """Why a policy change touches administration; empty when it does not."""
    reasons: list[str] = []
    all_roles = before.role_names | after.role_names
    for role in sorted(all_roles):
        if _mutating_admin_tools_for_role(before, role) != _mutating_admin_tools_for_role(
            after, role
        ):
            reasons.append(
                f"role '{role}' changes which administration tools that change state it reaches"
            )
    for role in sorted(all_roles):
        if not (is_management_role(before, role) or is_management_role(after, role)):
            continue
        before_role = before.role(role)
        after_role = after.role(role)
        before_patterns = before_role.allow_patterns if before_role is not None else ()
        after_patterns = after_role.allow_patterns if after_role is not None else ()
        if before_patterns != after_patterns:
            reasons.append(f"management role '{role}' changes its allow patterns")
    if any(
        before.requires_human_identity(tool) != after.requires_human_identity(tool)
        for tool in MANAGEMENT_TOOL_NAMES
    ):
        reasons.append("requires_human_identity changes for administration tools")
    if before.deny_patterns != after.deny_patterns:
        reasons.append("deny list changes")
    return tuple(sorted(reasons))


def build_admins_report(
    policy: RbacPolicy,
    people: Sequence[UserRecord],
    services: Sequence[ServiceAccountRecord],
) -> AdminsReport:
    mgmt_roles = tuple(sorted(management_role_names(policy)))
    full_roles = tuple(sorted(full_administrator_roles(policy)))
    full_admins = tuple(
        sorted(
            person.email
            for person in people
            if not person.is_blocked and is_full_administrator(policy, person.roles)
        )
    )
    holders: dict[str, list[str]] = {role: [] for role in mgmt_roles}
    for person in people:
        for role in person.roles:
            if role in holders:
                holders[role].append(_holder_label(person.email, is_blocked=person.is_blocked))
    for account in services:
        for role in account.roles:
            if role in holders:
                holders[role].append(_holder_label(account.subject, is_blocked=account.is_blocked))
    holders_sorted = {role: tuple(sorted(holders[role])) for role in mgmt_roles}
    return AdminsReport(
        management_roles=mgmt_roles,
        full_administrator_roles=full_roles,
        full_administrators=full_admins,
        holders=holders_sorted,
    )
