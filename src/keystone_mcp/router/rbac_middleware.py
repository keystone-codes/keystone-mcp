"""Server-side RBAC enforcement middleware.

FastMCP middleware with an ``on_list_tools`` visibility filter (UX) and an
``on_call_tool`` mandatory gate (security boundary). Effective permissions =
verified identity ∩ active user state ∩ union(role allow patterns) ∩ policy
contract.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext

from keystone_mcp.config import Settings
from keystone_mcp.identity import resolve_verified_identity
from keystone_mcp.observability.logging.context import get_request_id
from keystone_mcp.observability.subject import hash_subject
from keystone_mcp.rbac.call_decision import current_call_decision
from keystone_mcp.rbac.human_identity import (
    has_interactive_human_identity,
    requires_human_identity,
)
from keystone_mcp.rbac.loader import PolicyLoadError, RbacPolicyManager
from keystone_mcp.rbac.policy import RbacPolicy
from keystone_mcp.user_directory.critical import is_critical_tool
from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.models import UserResolveResult
from keystone_mcp.user_directory.protocol import UserDirectoryResolver

if TYPE_CHECKING:
    from fastmcp.tools.base import Tool
    from mcp.types import CallToolRequestParams, ListToolsRequest

    from keystone_mcp.observability.service import RbacObservability

logger = logging.getLogger(__name__)

CLIENT_DENIAL_MESSAGE = "access denied"


class RbacDenialReason(str, Enum):
    """Distinct denial causes for observability.

    ``THROTTLED`` is recorded by
    :class:`~keystone_mcp.router.throttle_middleware.ThrottleMiddleware`, which
    owns rate limiting; every other reason is decided here.
    """

    NO_IDENTITY = "no_identity"
    THROTTLED = "throttled"
    USER_BLOCKED = "user_blocked"
    NO_ROLES = "no_roles"
    NOT_PERMITTED = "not_permitted"
    HUMAN_IDENTITY_REQUIRED = "human_identity_required"
    ROLES_UNAVAILABLE = "roles_unavailable"
    POLICY_UNAVAILABLE = "policy_unavailable"


@dataclass(frozen=True, slots=True)
class RbacDecision:
    """Outcome of an RBAC evaluation (observable audit point)."""

    tool_name: str
    email: str | None
    allowed: bool
    reason: RbacDenialReason | None = None
    roles: frozenset[str] = frozenset()
    cache_hit: bool | None = None


def _request_correlation_id() -> str | None:
    """Best-effort request correlation id (header/context, then OAuth session)."""
    context_id = get_request_id()
    if context_id:
        return context_id
    try:
        from fastmcp.server.dependencies import get_access_token
    except Exception:
        return None
    token = get_access_token()
    if token is None:
        return None
    claims = token.claims or {}
    return str(claims.get("jti") or claims.get("sid") or token.subject or "") or None


class RbacMiddleware(Middleware):
    """Enforce RBAC policy at list-tools (UX) and call-tool (security boundary)."""

    def __init__(
        self,
        policy_manager: RbacPolicyManager,
        user_resolver: UserDirectoryResolver,
        *,
        settings: Settings | None = None,
        observability: RbacObservability | None = None,
        enforce: bool | None = None,
    ) -> None:
        self._policy_manager = policy_manager
        self._user_resolver = user_resolver
        self._observability = observability
        if enforce is not None:
            self._enforce = enforce
        elif settings is not None:
            self._enforce = settings.rbac_enforcing
        else:
            self._enforce = True

    async def on_list_tools(
        self,
        context: MiddlewareContext[ListToolsRequest],
        call_next,
    ) -> list[Tool]:
        tools = list(await call_next(context))
        decision = await self._evaluate(
            context,
            tool_name=None,
            roles_only=True,
            operation="list_tools",
        )
        if not self._enforce:
            return tools
        if not decision.allowed:
            return []
        policy = self._load_policy(operation="list_tools")
        if policy is None:
            return []
        return [tool for tool in tools if policy.allows(decision.roles, tool.name)]

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next,
    ):
        tool_name = context.message.name
        decision = await self._evaluate(
            context,
            tool_name=tool_name,
            roles_only=False,
            operation="call_tool",
        )
        if not decision.allowed and self._enforce:
            raise ToolError(CLIENT_DENIAL_MESSAGE)
        # Published for the duration of this call only (reset in `finally`,
        # not left for the next call on a reused task) so a signer further
        # down the same call (keystone_mcp.identity_assertion) can read
        # exactly the roles RBAC used to allow it. Not set at all when the
        # decision denied the call in enforce mode, since execution never
        # reaches `call_next`.
        token = current_call_decision.set(decision)
        try:
            return await call_next(context)
        finally:
            current_call_decision.reset(token)

    def _active_policy(self) -> RbacPolicy | None:
        """Active policy without recording a decision (None when not loaded)."""
        return self._policy_manager.active_policy

    def _load_policy(self, *, operation: str) -> RbacPolicy | None:
        try:
            return self._policy_manager.policy
        except PolicyLoadError as exc:
            decision = RbacDecision(
                tool_name="",
                email=None,
                allowed=False,
                reason=RbacDenialReason.POLICY_UNAVAILABLE,
            )
            self._record_decision(decision, operation=operation)
            logger.warning("rbac policy is not active: %s", exc)
            return None

    async def _resolve_user(
        self,
        email: str,
        *,
        critical: bool,
    ) -> UserResolveResult:
        outcome_holder = {"outcome": "miss"}
        started = time.perf_counter()
        try:
            user = await self._user_resolver.resolve(email, critical=critical)
        except UserDirectoryUnavailableError:
            outcome_holder["outcome"] = "unavailable"
            raise
        except Exception:
            outcome_holder["outcome"] = "error"
            raise
        else:
            outcome_holder["outcome"] = (
                "cache_hit" if getattr(user, "from_cache", False) else "miss"
            )
            return user
        finally:
            if self._observability is not None:
                self._observability.record_directory_resolve(
                    outcome=outcome_holder["outcome"],
                    duration_seconds=time.perf_counter() - started,
                )

    async def _evaluate(
        self,
        context: MiddlewareContext,
        *,
        tool_name: str | None,
        roles_only: bool,
        operation: str,
    ) -> RbacDecision:
        identity = resolve_verified_identity()
        if identity is None:
            decision = RbacDecision(
                tool_name=tool_name or "",
                email=None,
                allowed=False,
                reason=RbacDenialReason.NO_IDENTITY,
            )
            self._record_decision(decision, operation=operation)
            return decision

        critical = False
        if tool_name:
            # Critical-tool globs live in the active policy; the core built-ins
            # apply even before a policy is loaded.
            active_policy = self._active_policy()
            critical = is_critical_tool(
                tool_name,
                active_policy.critical_tool_patterns if active_policy is not None else (),
            )
        try:
            user = await self._resolve_user(identity.email, critical=critical)
        except UserDirectoryUnavailableError:
            decision = RbacDecision(
                tool_name=tool_name or "",
                email=identity.email,
                allowed=False,
                reason=RbacDenialReason.ROLES_UNAVAILABLE,
            )
            self._record_decision(decision, operation=operation)
            return decision
        except Exception as exc:
            logger.warning(
                "rbac user directory resolve failed for %s: %s",
                hash_subject(identity.email),
                exc,
                exc_info=True,
            )
            decision = RbacDecision(
                tool_name=tool_name or "",
                email=identity.email,
                allowed=False,
                reason=RbacDenialReason.ROLES_UNAVAILABLE,
            )
            self._record_decision(decision, operation=operation)
            return decision

        roles = frozenset(user.roles)
        if user.is_blocked:
            decision = RbacDecision(
                tool_name=tool_name or "",
                email=identity.email,
                allowed=False,
                reason=RbacDenialReason.USER_BLOCKED,
                roles=roles,
                cache_hit=getattr(user, "from_cache", False),
            )
            self._record_decision(decision, operation=operation)
            return decision

        if not _user_may_access_tools(user):
            decision = RbacDecision(
                tool_name=tool_name or "",
                email=identity.email,
                allowed=False,
                reason=RbacDenialReason.NO_ROLES,
                roles=roles,
                cache_hit=getattr(user, "from_cache", False),
            )
            self._record_decision(decision, operation=operation)
            return decision

        if roles_only or tool_name is None:
            decision = RbacDecision(
                tool_name="",
                email=identity.email,
                allowed=True,
                roles=roles,
                cache_hit=getattr(user, "from_cache", False),
            )
            self._record_decision(decision, operation=operation)
            return decision

        policy = self._load_policy(operation=operation)
        if policy is None:
            decision = RbacDecision(
                tool_name=tool_name,
                email=identity.email,
                allowed=False,
                reason=RbacDenialReason.POLICY_UNAVAILABLE,
                cache_hit=getattr(user, "from_cache", False),
            )
            self._record_decision(decision, operation=operation)
            return decision

        if policy.allows(roles, tool_name):
            if requires_human_identity(tool_name, policy) and not has_interactive_human_identity(
                identity
            ):
                decision = RbacDecision(
                    tool_name=tool_name,
                    email=identity.email,
                    allowed=False,
                    reason=RbacDenialReason.HUMAN_IDENTITY_REQUIRED,
                    roles=roles,
                    cache_hit=getattr(user, "from_cache", False),
                )
                self._record_decision(decision, operation=operation)
                return decision
            decision = RbacDecision(
                tool_name=tool_name,
                email=identity.email,
                allowed=True,
                roles=roles,
                cache_hit=getattr(user, "from_cache", False),
            )
            self._record_decision(decision, operation=operation)
            return decision

        decision = RbacDecision(
            tool_name=tool_name,
            email=identity.email,
            allowed=False,
            reason=RbacDenialReason.NOT_PERMITTED,
            roles=roles,
            cache_hit=getattr(user, "from_cache", False),
        )
        self._record_decision(decision, operation=operation)
        return decision

    def _record_decision(self, decision: RbacDecision, *, operation: str) -> None:
        if self._observability is not None:
            self._observability.record_authz_decision(
                tool_name=decision.tool_name,
                email=decision.email,
                allowed=decision.allowed,
                reason=decision.reason,
                roles=decision.roles,
                cache_hit=decision.cache_hit,
                operation=operation,
                request_id=_request_correlation_id(),
            )
            return
        logger.info(
            "rbac decision tool=%s subject=%s allowed=%s reason=%s roles=%s",
            decision.tool_name or "*",
            hash_subject(decision.email),
            decision.allowed,
            decision.reason.value if decision.reason else None,
            sorted(decision.roles),
        )


def _user_may_access_tools(user: UserResolveResult) -> bool:
    return user.exists and not user.is_blocked and bool(user.roles)
