"""Shared guards for built-in administration adapters."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from keystone_mcp.catalog.names import MUTATING_ADMIN_TOOL_NAMES
from keystone_mcp.rbac.management import ManagementView
from keystone_mcp.user_directory.util import normalize_email

if TYPE_CHECKING:
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.rbac.management import ManagementSource
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route
    from keystone_mcp.user_directory.protocol import UserDirectory

logger = logging.getLogger(__name__)

CatalogNamesSource = Callable[[], frozenset[str]]

HUMAN_ACTOR_REQUIRED_MESSAGE = (
    "this change requires a human administrator; service accounts can only read"
)

MANAGEMENT_FORBIDDEN_MESSAGE = (
    "only a full administrator can grant or remove a management role "
    "or change an account that holds one"
)

DELEGATION_FORBIDDEN_MESSAGE = "you can grant only roles whose permissions you already have: {role}"

SELF_DEMOTION_FORBIDDEN_MESSAGE = (
    "you cannot remove your own full administration; another full administrator must do it"
)


@dataclass(frozen=True, slots=True)
class AdminCall:
    view: ManagementView
    actor_roles: frozenset[str]
    target_roles: frozenset[str]


def require_human_actor(
    route: Route,
    ctx: RouteContext,
    *,
    observability: RbacObservability | None,
    message: str = HUMAN_ACTOR_REQUIRED_MESSAGE,
) -> dict[str, Any] | None:
    """Return a ``forbidden`` envelope when a service account calls a mutating admin tool."""
    if route.name not in MUTATING_ADMIN_TOOL_NAMES:
        return None
    if ctx.verified_identity.subject_type != "service":
        return None
    if observability is not None:
        try:
            observability.record_admin_refusal(operation=route.name, reason="service_account")
        except Exception:
            logger.warning("admin refusal metric failed", exc_info=True)
    return {
        "state": "error",
        "tool": route.name,
        "task_id": ctx.task_id,
        "code": "forbidden",
        "message": message,
    }


async def _actor_roles(directory: UserDirectory, subject: str) -> tuple[str, ...]:
    resolved = await directory.resolve_user(subject)
    if not resolved.exists or resolved.is_blocked:
        return ()
    return resolved.roles


async def _holder_roles(directory: UserDirectory, subject: str) -> tuple[str, ...]:
    resolved = await directory.resolve_user(subject)
    if not resolved.exists:
        return ()
    return resolved.roles


def _service_unavailable(
    route: Route,
    ctx: RouteContext,
    *,
    message: str,
) -> dict[str, Any]:
    return {
        "state": "error",
        "tool": route.name,
        "task_id": ctx.task_id,
        "code": "service_unavailable",
        "message": message,
    }


async def resolve_admin_call(
    route: Route,
    ctx: RouteContext,
    *,
    directory: UserDirectory,
    management_source: ManagementSource | None,
    target_subject: str | None,
) -> AdminCall | dict[str, Any]:
    if management_source is None:
        view = ManagementView(())
    else:
        try:
            view = await management_source()
        except Exception:  # noqa: BLE001
            return _service_unavailable(route, ctx, message="role catalog is not loaded")

    actor = normalize_email(ctx.verified_identity.subject)
    try:
        actor_role_tuple = await _actor_roles(directory, actor)
    except Exception:  # noqa: BLE001
        return _service_unavailable(route, ctx, message="users directory is unavailable")

    target_roles: tuple[str, ...] = ()
    if target_subject is not None:
        try:
            target_roles = await _holder_roles(directory, target_subject)
        except Exception:  # noqa: BLE001
            return _service_unavailable(route, ctx, message="users directory is unavailable")

    return AdminCall(
        view=view,
        actor_roles=frozenset(actor_role_tuple),
        target_roles=frozenset(target_roles),
    )


def check_management_authority(
    route: Route,
    ctx: RouteContext,
    *,
    call: AdminCall,
    observability: RbacObservability | None,
    roles_touched: Sequence[str] = (),
) -> dict[str, Any] | None:
    if not call.view.policies:
        return None

    if call.view.is_full_administrator(call.actor_roles):
        return None

    touched = call.view.management_roles(r.strip() for r in roles_touched if r.strip())
    if call.view.management_roles(call.target_roles) or touched:
        if observability is not None:
            try:
                observability.record_admin_refusal(operation=route.name, reason="management_role")
            except Exception:
                logger.warning("admin refusal metric failed", exc_info=True)
        return {
            "state": "error",
            "tool": route.name,
            "task_id": ctx.task_id,
            "code": "forbidden",
            "message": MANAGEMENT_FORBIDDEN_MESSAGE,
        }
    return None


def delegation_roles_granted(
    tool_name: str,
    spec: dict[str, Any],
    *,
    target_roles: frozenset[str],
) -> tuple[str, ...]:
    if tool_name == "users_revoke_role":
        return ()
    if tool_name == "users_grant_role":
        return (str(spec["role"]).strip(),)
    if tool_name in ("users_add", "service_accounts_add"):
        raw = spec.get("roles") or []
        if not isinstance(raw, list):
            return ()
        return tuple(item.strip() for item in raw if isinstance(item, str) and item.strip())
    if tool_name == "users_set_roles":
        raw = spec.get("roles") or []
        if not isinstance(raw, list):
            return ()
        new_roles = {item.strip() for item in raw if isinstance(item, str) and item.strip()}
        return tuple(sorted(new_roles - target_roles))
    if tool_name == "service_accounts_update":
        raw = spec.get("roles")
        if raw is None or not isinstance(raw, list):
            return ()
        new_roles = {item.strip() for item in raw if isinstance(item, str) and item.strip()}
        return tuple(sorted(new_roles - target_roles))
    return ()


def check_delegation(
    route: Route,
    ctx: RouteContext,
    *,
    call: AdminCall,
    roles_granted: Sequence[str],
    catalog_names_source: CatalogNamesSource | None,
    observability: RbacObservability | None,
) -> dict[str, Any] | None:
    if catalog_names_source is None:
        return None
    if call.view.is_full_administrator(call.actor_roles):
        return None
    try:
        catalog_names = catalog_names_source()
    except Exception:  # noqa: BLE001
        return _service_unavailable(route, ctx, message="role catalog is not loaded")

    for role in roles_granted:
        role_name = role.strip()
        if not role_name:
            continue
        if call.view.role_exceeds_actor(role_name, call.actor_roles, catalog_names):
            if observability is not None:
                try:
                    observability.record_admin_refusal(operation=route.name, reason="delegation")
                except Exception:
                    logger.warning("admin refusal metric failed", exc_info=True)
            return {
                "state": "error",
                "tool": route.name,
                "task_id": ctx.task_id,
                "code": "forbidden",
                "message": DELEGATION_FORBIDDEN_MESSAGE.format(role=role_name),
            }
    return None


def check_self_demotion(
    route: Route,
    ctx: RouteContext,
    *,
    admin_call: AdminCall,
    spec: dict[str, Any],
) -> dict[str, Any] | None:
    """Refuse when a full administrator removes their own full administration.

    A separate ``last full administrator`` guard for ``users_*`` is not needed:
    after A02 only an active full administrator can change holders of management
    roles, and this rule blocks self-demotion — so any successful mutation leaves
    at least the acting administrator in place. Built-in ``users/service.py``
    checks against the literal ``administrator`` role name remain a second line
    for the local directory only.
    """
    tool_name = route.name
    if tool_name not in ("users_block", "users_set_roles", "users_revoke_role"):
        return None
    if not admin_call.view.policies:
        return None

    actor = normalize_email(ctx.verified_identity.subject)
    target_email = normalize_email(str(spec["email"]))
    if actor != target_email:
        return None
    if not admin_call.view.is_full_administrator(admin_call.actor_roles):
        return None

    if tool_name == "users_block":
        still_full = False
    elif tool_name == "users_set_roles":
        raw = spec.get("roles") or []
        roles_after = frozenset(
            item.strip() for item in raw if isinstance(item, str) and item.strip()
        )
        still_full = admin_call.view.is_full_administrator(roles_after)
    else:
        role = str(spec["role"]).strip()
        roles_after = frozenset(admin_call.target_roles - {role})
        still_full = admin_call.view.is_full_administrator(roles_after)

    if still_full:
        return None
    return {
        "state": "error",
        "tool": route.name,
        "task_id": ctx.task_id,
        "code": "self_admin_mutation_forbidden",
        "message": SELF_DEMOTION_FORBIDDEN_MESSAGE,
    }
