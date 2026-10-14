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

List handlers raise :class:`mcp.shared.exceptions.MCPError` on refusal. FastMCP
4.1 maps ``ToolError`` / ``PromptError`` / ``ResourceError`` from list
middleware to a generic internal error on the modern protocol path, so the wire
response carries ``THROTTLE_MESSAGE`` only when ``MCPError`` is raised.
``on_call_tool``, ``on_get_prompt``, and ``on_read_resource`` keep the typed
FastMCP exceptions.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastmcp.exceptions import PromptError, ResourceError, ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp.shared.exceptions import MCPError
from mcp_types import INTERNAL_ERROR

from keystone_mcp.auth.throttle import PerIdentityThrottle
from keystone_mcp.identity import resolve_verified_identity
from keystone_mcp.observability.subject import subject_pseudonym

if TYPE_CHECKING:
    from mcp.types import (
        CallToolRequestParams,
        GetPromptRequestParams,
        ListPromptsRequest,
        ListResourcesRequest,
        ListResourceTemplatesRequest,
        ListToolsRequest,
        ReadResourceRequestParams,
    )

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

        if self._throttle.check(identity.subject):
            return await call_next(context)

        self._record_throttled(
            context.message.name,
            identity.subject,
            operation="call_tool",
            subject_type=identity.subject_type,
        )
        raise ToolError(THROTTLE_MESSAGE)

    async def on_list_tools(
        self,
        context: MiddlewareContext[ListToolsRequest],
        call_next,
    ):
        identity = resolve_verified_identity()
        if identity is None:
            return await call_next(context)

        if self._throttle.check(identity.subject):
            return await call_next(context)

        self._record_throttled(
            "", identity.subject, operation="list_tools", subject_type=identity.subject_type
        )
        raise MCPError(code=INTERNAL_ERROR, message=THROTTLE_MESSAGE)

    async def on_list_prompts(
        self,
        context: MiddlewareContext[ListPromptsRequest],
        call_next,
    ):
        identity = resolve_verified_identity()
        if identity is None:
            return await call_next(context)

        if self._throttle.check(identity.subject):
            return await call_next(context)

        self._record_throttled(
            "", identity.subject, operation="list_prompts", subject_type=identity.subject_type
        )
        raise MCPError(code=INTERNAL_ERROR, message=THROTTLE_MESSAGE)

    async def on_list_resources(
        self,
        context: MiddlewareContext[ListResourcesRequest],
        call_next,
    ):
        identity = resolve_verified_identity()
        if identity is None:
            return await call_next(context)

        if self._throttle.check(identity.subject):
            return await call_next(context)

        self._record_throttled(
            "", identity.subject, operation="list_resources", subject_type=identity.subject_type
        )
        raise MCPError(code=INTERNAL_ERROR, message=THROTTLE_MESSAGE)

    async def on_list_resource_templates(
        self,
        context: MiddlewareContext[ListResourceTemplatesRequest],
        call_next,
    ):
        identity = resolve_verified_identity()
        if identity is None:
            return await call_next(context)

        if self._throttle.check(identity.subject):
            return await call_next(context)

        self._record_throttled(
            "",
            identity.subject,
            operation="list_resource_templates",
            subject_type=identity.subject_type,
        )
        raise MCPError(code=INTERNAL_ERROR, message=THROTTLE_MESSAGE)

    async def on_get_prompt(
        self,
        context: MiddlewareContext[GetPromptRequestParams],
        call_next,
    ):
        identity = resolve_verified_identity()
        if identity is None:
            return await call_next(context)

        if self._throttle.check(identity.subject):
            return await call_next(context)

        self._record_throttled(
            context.message.name,
            identity.subject,
            operation="get_prompt",
            subject_type=identity.subject_type,
        )
        raise PromptError(THROTTLE_MESSAGE)

    async def on_read_resource(
        self,
        context: MiddlewareContext[ReadResourceRequestParams],
        call_next,
    ):
        identity = resolve_verified_identity()
        if identity is None:
            return await call_next(context)

        if self._throttle.check(identity.subject):
            return await call_next(context)

        self._record_throttled(
            str(context.message.uri),
            identity.subject,
            operation="read_resource",
            subject_type=identity.subject_type,
        )
        raise ResourceError(THROTTLE_MESSAGE)

    def _record_throttled(
        self,
        tool_name: str,
        email: str,
        *,
        operation: str,
        subject_type: str | None = None,
    ) -> None:
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
                operation=operation,
                request_id=_request_correlation_id(),
                subject_type=subject_type,
            )
            return
        logger.info(
            "throttled tool=%s subject=%s",
            tool_name,
            subject_pseudonym(email),
        )
