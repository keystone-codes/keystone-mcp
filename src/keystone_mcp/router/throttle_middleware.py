"""The single per-identity throttle enforcement point for tool calls.

One tool call must consume exactly one slot of an identity's rate-limit budget,
in every RBAC mode. That is only true if exactly one component records the hit,
so this middleware owns throttling outright: neither the router engine nor the
RBAC middleware counts calls.

It is installed on the root server unconditionally (RBAC off, observe or
enforce) and runs outermost, before authorization, so a throttled identity is
rejected without touching the user directory. A call with no verified identity
is passed through untouched — authentication and authorization decide that case,
and an unauthenticated caller has no identity to aggregate on.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext

from keystone_mcp.auth.throttle import PerIdentityThrottle
from keystone_mcp.identity import resolve_verified_identity
from keystone_mcp.observability.subject import hash_subject

if TYPE_CHECKING:
    from mcp.types import CallToolRequestParams

    from keystone_mcp.observability.service import RbacObservability

logger = logging.getLogger(__name__)

THROTTLE_MESSAGE = "rate limit exceeded"


class ThrottleMiddleware(Middleware):
    """Reject a tool call once its identity is over the sliding-window limit."""

    def __init__(
        self,
        throttle: PerIdentityThrottle,
        *,
        observability: RbacObservability | None = None,
    ) -> None:
        self._throttle = throttle
        self._observability = observability

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next,
    ):
        if self._observability is not None:
            self._observability.record_tool_call_attempt(
                tool_name=context.message.name,
            )
        identity = resolve_verified_identity()
        if identity is None:
            return await call_next(context)

        if self._throttle.check(identity.email):
            return await call_next(context)

        self._record_throttled(context.message.name, identity.email)
        raise ToolError(THROTTLE_MESSAGE)

    def _record_throttled(self, tool_name: str, email: str) -> None:
        # Imported here: rbac_middleware owns the denial-reason vocabulary and
        # importing it at module scope would couple throttling to RBAC loading.
        from keystone_mcp.router.rbac_middleware import (
            RbacDenialReason,
            _request_correlation_id,
        )

        if self._observability is not None:
            self._observability.record_authz_decision(
                tool_name=tool_name,
                email=email,
                allowed=False,
                reason=RbacDenialReason.THROTTLED,
                roles=frozenset(),
                cache_hit=None,
                operation="call_tool",
                request_id=_request_correlation_id(),
            )
            return
        logger.info(
            "throttled tool=%s subject=%s",
            tool_name,
            hash_subject(email),
        )
