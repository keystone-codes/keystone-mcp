"""The routes every keystone-mcp deployment publishes.

These are the domain-neutral tools the server owns itself, as opposed to the
tools it proxies from configured upstreams (see
:mod:`keystone_mcp.router.upstream`).

User administration — administration of the users directory, used to manage
who may reach this server and with which roles: ``users_list``,
``users_add``, ``users_update``, ``users_block``, ``users_unblock``,
``users_set_roles``, ``users_grant_role``, ``users_revoke_role``. These routes
are registered only when ``KEYSTONE_MCP_RBAC_MODE=enforce``; authorization is
RBAC policy plus the RBAC middleware. The ``admin=True`` flag is catalog
metadata only and enforces nothing. ``users_list`` is published whenever a
directory is configured; the other seven (administration) are published only
when that directory declares the ``"admin"`` capability -- a read-only
directory publishes ``users_list`` alone.

Every route here is registered ``mode="live"`` — its adapter is wired and
serving. Add a route with ``registry.add_route`` when a new built-in target is
ready.
"""

from __future__ import annotations

import logging

from keystone_mcp.adapters.api_keys_admin import ApiKeysAdminAdapter
from keystone_mcp.adapters.base import Pattern
from keystone_mcp.adapters.policy_admin import PolicyAdminAdapter
from keystone_mcp.adapters.service_accounts_admin import ServiceAccountsAdminAdapter
from keystone_mcp.adapters.users_admin import RoleSource, UsersAdminAdapter
from keystone_mcp.catalog.names import BUILTIN_TOOL_NAMES  # noqa: F401 — re-export
from keystone_mcp.config import Settings
from keystone_mcp.rbac.management import ManagementSource, file_management_source
from keystone_mcp.router.registry import Param, RouterRegistry
from keystone_mcp.user_directory.protocol import UserDirectory

logger = logging.getLogger(__name__)

#: Re-exported from :mod:`keystone_mcp.catalog.names` for upstream validation (P09).


def register_catalog(
    registry: RouterRegistry,
    settings: Settings,
    *,
    observability: object | None = None,
    directory: UserDirectory | None = None,
    role_source: RoleSource | None = None,
    management_source: ManagementSource | None = None,
    policy_store: object | None = None,
    session_revoker: object | None = None,
) -> None:
    """``policy_store``, when given, is a ``keystone_mcp.rbac.policy_store.PolicyStore``."""
    resolved_management = management_source
    if resolved_management is None:
        policy_path = settings.rbac_policy_path.strip()
        if policy_path:
            resolved_management = file_management_source(policy_path)
        else:
            logger.warning("management-role checks are off: no RBAC policy path")
    users_admin = UsersAdminAdapter(
        directory=directory,
        observability=observability,
        role_source=role_source,
        management_source=resolved_management,
        session_revoker=session_revoker,
    )
    service_accounts_admin = ServiceAccountsAdminAdapter(
        directory=directory,
        observability=observability,
        role_source=role_source,
        management_source=resolved_management,
    )
    api_keys_admin = ApiKeysAdminAdapter(
        directory=directory,
        observability=observability,
        management_source=resolved_management,
        session_revoker=session_revoker,
    )

    P = Param  # noqa: N806 — local alias for brevity

    if not settings.rbac_enforcing:
        return
    if directory is None:
        return

    # ── ADMIN — user administration over whichever UserDirectory the server
    # was built with. Who may call these tools is decided by the policy file.
    # ``admin=True`` is catalog metadata only. ``users_list`` is published for
    # any directory; the other seven only when it declares "admin".
    _read_only_tools: list[tuple[str, str, list[Param]]] = [
        (
            "users_list",
            "List workspace users with optional filters (default: not blocked).",
            [
                P("is_blocked", bool, required=False, default=False),
                P("role", str, required=False, default=None),
                P("email_contains", str, required=False, default=None),
            ],
        ),
    ]
    _admin_tools: list[tuple[str, str, list[Param]]] = [
        (
            "users_add",
            "Create a workspace user with an initial role set.",
            [
                P("email", str),
                P("full_name", str),
                P("roles", list, required=False, default=None),
                P("note", str, required=False, default=None),
            ],
        ),
        (
            "users_update",
            "Update a user profile (full_name and/or note).",
            [
                P("email", str),
                P("full_name", str, required=False, default=None),
                P("note", str, required=False, default=None),
            ],
        ),
        (
            "users_block",
            "Block a user account (requires verified administrator actor).",
            [P("email", str)],
        ),
        (
            "users_unblock",
            "Unblock a previously blocked user account.",
            [P("email", str)],
        ),
        (
            "users_logout",
            "End all sessions of a user: every access and refresh token is revoked; "
            "the user can sign in again.",
            [P("email", str)],
        ),
        (
            "users_set_roles",
            "Replace the full role set for a user (multi-role model).",
            [
                P("email", str),
                P("roles", list),
            ],
        ),
        (
            "users_grant_role",
            "Grant a single role to a user.",
            [
                P("email", str),
                P("role", str),
            ],
        ),
        (
            "users_revoke_role",
            "Revoke a single role from a user.",
            [
                P("email", str),
                P("role", str),
            ],
        ),
    ]
    for tool_name, description, params in _read_only_tools:
        registry.add_route(
            tool_name,
            users_admin,
            pattern=Pattern.SYNC,
            params=params,
            description=description,
            mode="live",
            admin=True,
        )
    if "admin" in directory.capabilities:
        for tool_name, description, params in _admin_tools:
            registry.add_route(
                tool_name,
                users_admin,
                pattern=Pattern.SYNC,
                params=params,
                description=description,
                mode="live",
                admin=True,
            )
    else:
        logger.warning(
            "users directory %s is read-only: users_* administration tools are not published",
            directory.name,
        )

    if "service_accounts" in directory.capabilities:
        _service_tools: list[tuple[str, str, list[Param]]] = [
            (
                "service_accounts_list",
                "List service accounts (machine identities) with their roles.",
                [P("is_blocked", bool, required=False, default=False)],
            ),
            (
                "service_accounts_add",
                "Create a service account for a machine caller (CI, scheduler, agent). "
                "Service accounts are never treated as an interactive human and cannot "
                "hold the administrator role.",
                [
                    P("name", str),
                    P("roles", list, required=False, default=None),
                    P("description", str, required=False, default=None),
                ],
            ),
            (
                "service_accounts_update",
                "Change a service account's description, replace its roles, or block/unblock it.",
                [
                    P("name", str),
                    P("description", str, required=False, default=None),
                    P("roles", list, required=False, default=None),
                    P("is_blocked", bool, required=False, default=None),
                ],
            ),
        ]
        for tool_name, description, params in _service_tools:
            registry.add_route(
                tool_name,
                service_accounts_admin,
                pattern=Pattern.SYNC,
                params=params,
                description=description,
                mode="live",
                admin=True,
            )

    if "api_keys" in directory.capabilities:
        publish_issue = settings.deployment_profile != "production"
        _api_key_tools: list[tuple[str, str, list[Param]]] = []
        if publish_issue:
            _api_key_tools.append(
                (
                    "api_keys_issue",
                    "Issue an API key for a person (sign-in page) or a service account "
                    "(Bearer header). The key is returned once.",
                    [
                        P("subject", str),
                        P("label", str, required=False, default=None),
                        P("expires_in_days", int, required=False, default=90),
                    ],
                )
            )
        _api_key_tools.extend(
            [
                (
                    "api_keys_list",
                    "List API keys without their secrets.",
                    [
                        P("subject", str, required=False, default=None),
                        P("include_revoked", bool, required=False, default=False),
                    ],
                ),
                (
                    "api_keys_revoke",
                    "Revoke an API key; Bearer calls with it and sign-in sessions opened with it stop at once.",
                    [P("key_id", str)],
                ),
            ]
        )
        for tool_name, description, params in _api_key_tools:
            registry.add_route(
                tool_name,
                api_keys_admin,
                pattern=Pattern.SYNC,
                params=params,
                description=description,
                mode="live",
                admin=True,
            )

    if settings.policy_tools != "off" and policy_store is not None:
        policy_admin = PolicyAdminAdapter(
            store=policy_store,
            directory=directory,
            observability=observability,
        )
        _policy_read_tools: list[tuple[str, str, list[Param]]] = [
            (
                "policy_read",
                "Read the RBAC policy file, its hashes, and catalog validation hints.",
                [],
            ),
            (
                "policy_catalog",
                "List published tool names from the live catalog and optional snapshot, "
                "with per-role allow decisions.",
                [
                    P("namespace", str, required=False, default=None),
                    P("role", str, required=False, default=None),
                ],
            ),
            (
                "policy_validate",
                "Dry-run structural and catalog validation on the current file or a candidate.",
                [P("policy", dict, required=False, default=None)],
            ),
        ]
        _policy_write_tools: list[tuple[str, str, list[Param]]] = [
            (
                "policy_role_set",
                "Create or replace a role's allow patterns and description. "
                "Validated against the live catalog and applied immediately.",
                [
                    P("role", str),
                    P("allow", list),
                    P("description", str, required=False, default=None),
                    P("expected_hash", str, required=False, default=None),
                ],
            ),
            (
                "policy_role_delete",
                "Delete a role that is not assigned to any active account.",
                [
                    P("role", str),
                    P("expected_hash", str, required=False, default=None),
                ],
            ),
            (
                "policy_allow_add",
                "Add allow patterns to a role. Patterns are globs over published tool names "
                "(namespace prefix included), e.g. files_*. The change is validated against the "
                "live catalog and applied immediately.",
                [
                    P("role", str),
                    P("patterns", list),
                    P("expected_hash", str, required=False, default=None),
                ],
            ),
            (
                "policy_allow_remove",
                "Remove allow patterns from a role. The role must keep at least one pattern.",
                [
                    P("role", str),
                    P("patterns", list),
                    P("expected_hash", str, required=False, default=None),
                ],
            ),
            (
                "policy_list_set",
                "Replace a global policy list (deny, requires_human_identity, critical_tools, "
                "or reserved_allow_patterns) wholesale.",
                [
                    P("list", str),
                    P("patterns", list),
                    P("expected_hash", str, required=False, default=None),
                ],
            ),
            (
                "policy_rollback",
                "Restore the previous policy file generation from the one-step backup. "
                "Pass expected_hash (file_hash from policy_read) to refuse when someone "
                "else changed the file since you read it.",
                [P("expected_hash", str, required=False, default=None)],
            ),
        ]
        for tool_name, description, params in _policy_read_tools:
            registry.add_route(
                tool_name,
                policy_admin,
                pattern=Pattern.SYNC,
                params=params,
                description=description,
                mode="live",
                admin=True,
            )
        if settings.policy_tools == "full":
            for tool_name, description, params in _policy_write_tools:
                registry.add_route(
                    tool_name,
                    policy_admin,
                    pattern=Pattern.SYNC,
                    params=params,
                    description=description,
                    mode="live",
                    admin=True,
                )
