"""Shared guards for built-in administration adapters."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from keystone_mcp.catalog.names import MUTATING_ADMIN_TOOL_NAMES
from keystone_mcp.user_directory.util import normalize_email

if TYPE_CHECKING:
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.rbac.management import ManagementSource
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route
    from keystone_mcp.user_directory.protocol import UserDirectory

logger = logging.getLogger(__name__)

HUMAN_ACTOR_REQUIRED_MESSAGE = (
    "this change requires a human administrator; service accounts can only read"
)

MANAGEMENT_FORBIDDEN_MESSAGE = (
    "only a full administrator can grant or remove a management role "
    "or change an account that holds one"
)


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


async def check_management_authority(
    route: Route,
    ctx: RouteContext,
    *,
    directory: UserDirectory,
    management_source: ManagementSource | None,
    observability: RbacObservability | None,
    target_subject: str | None,
    roles_touched: Sequence[str] = (),
) -> dict[str, Any] | None:
    if management_source is None:
        return None
    try:
        view = await management_source()
    except Exception:  # noqa: BLE001
        return {
            "state": "error",
            "tool": route.name,
            "task_id": ctx.task_id,
            "code": "service_unavailable",
            "message": "role catalog is not loaded",
        }

    actor = normalize_email(ctx.verified_identity.subject)
    try:
        actor_roles = await _actor_roles(directory, actor)
    except Exception:  # noqa: BLE001
        return {
            "state": "error",
            "tool": route.name,
            "task_id": ctx.task_id,
            "code": "service_unavailable",
            "message": "users directory is unavailable",
        }

    if view.is_full_administrator(actor_roles):
        return None

    target_roles: tuple[str, ...] = ()
    if target_subject is not None:
        try:
            target_roles = await _holder_roles(directory, target_subject)
        except Exception:  # noqa: BLE001
            return {
                "state": "error",
                "tool": route.name,
                "task_id": ctx.task_id,
                "code": "service_unavailable",
                "message": "users directory is unavailable",
            }

    touched = view.management_roles(r.strip() for r in roles_touched if r.strip())
    if view.management_roles(target_roles) or touched:
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
