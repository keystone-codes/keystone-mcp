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

from keystone_mcp.adapters.base import Pattern
from keystone_mcp.adapters.service_accounts_admin import ServiceAccountsAdminAdapter
from keystone_mcp.adapters.users_admin import RoleSource, UsersAdminAdapter
from keystone_mcp.config import Settings
from keystone_mcp.router.registry import Param, RouterRegistry
from keystone_mcp.user_directory.protocol import UserDirectory

logger = logging.getLogger(__name__)

#: Every tool name the built-in catalog can register, whatever the settings.
#: Used by upstream namespace validation (P09) to reject namespaces that
#: would publish a colliding ``<namespace>_<tool>`` name.
BUILTIN_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "users_list",
        "users_add",
        "users_update",
        "users_block",
        "users_unblock",
        "users_set_roles",
        "users_grant_role",
        "users_revoke_role",
        "users_logout",
        "service_accounts_list",
        "service_accounts_add",
        "service_accounts_update",
    }
)


def register_catalog(
    registry: RouterRegistry,
    settings: Settings,
    *,
    observability: object | None = None,
    directory: UserDirectory | None = None,
    role_source: RoleSource | None = None,
    policy_store: object | None = None,
    session_revoker: object | None = None,
) -> None:
    """``policy_store``, when given, is a ``keystone_mcp.rbac.policy_store.PolicyStore``.

    Accepted here (but not yet used) so the server wiring that builds it does
    not have to change again when a later card registers the ``policy_*``
    tools over it; typed as ``object`` to avoid importing the RBAC policy
    package from the catalog module for a parameter nothing here reads yet.
    """
    users_admin = UsersAdminAdapter(
        directory=directory,
        observability=observability,
        role_source=role_source,
        session_revoker=session_revoker,
    )
    service_accounts_admin = ServiceAccountsAdminAdapter(
        directory=directory, observability=observability, role_source=role_source
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
            pattern=Pattern.M_B,
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
                pattern=Pattern.M_B,
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
                pattern=Pattern.M_B,
                params=params,
                description=description,
                mode="live",
                admin=True,
            )
