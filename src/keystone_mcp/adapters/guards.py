"""Shared guards for built-in administration adapters."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from keystone_mcp.catalog.names import MUTATING_ADMIN_TOOL_NAMES

if TYPE_CHECKING:
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route

logger = logging.getLogger(__name__)

HUMAN_ACTOR_REQUIRED_MESSAGE = (
    "this change requires a human administrator; service accounts can only read"
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
