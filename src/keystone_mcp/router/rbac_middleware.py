"""Server-side RBAC enforcement middleware.

FastMCP middleware with an ``on_list_tools`` visibility filter (UX) and an
``on_call_tool`` mandatory gate (security boundary). Effective permissions =
verified identity ∩ active user state ∩ union(role allow patterns) ∩ policy
contract.
"""

from __future__ import annotations

import dataclasses
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

from fastmcp.exceptions import PromptError, ResourceError, ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext

from keystone_mcp.catalog.names import MUTATING_ADMIN_TOOL_NAMES
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity, make_task_id, resolve_verified_identity
from keystone_mcp.observability.logging.context import get_request_id
from keystone_mcp.observability.subject import subject_pseudonym
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
    from keystone_mcp.rbac.policy_revision import PolicyRevisionWatcher
    from keystone_mcp.router.route import Route
    from keystone_mcp.router.upstream_content import UpstreamContentCatalog

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
    SUBJECT_TYPE_MISMATCH = "subject_type_mismatch"


@dataclass(frozen=True, slots=True)
class RbacDecision:
    """Outcome of an RBAC evaluation (observable audit point)."""

    tool_name: str
    email: str | None
    allowed: bool
    reason: RbacDenialReason | None = None
    roles: frozenset[str] = frozenset()
    cache_hit: bool | None = None
    # The sign-in method's name (``claims["auth_method"]``), so an operator
    # reading the audit log can see *why* a HUMAN_IDENTITY_REQUIRED denial
    # happened ("signed in with api_key") without cross-referencing the
    # token store. ``None`` when there is no verified identity at all.
    login_provider: str | None = None
    subject_type: str | None = None
    task_id: str | None = None


def _decision_for_signing(decision: RbacDecision) -> RbacDecision:
    """What a signer may see: a denied decision carries no roles."""
    return decision if decision.allowed else dataclasses.replace(decision, roles=frozenset())


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
        content_catalog: UpstreamContentCatalog | None = None,
        policy_revision_watcher: PolicyRevisionWatcher | None = None,
        route_lookup: Callable[[str], Route | None] | None = None,
    ) -> None:
        self._policy_manager = policy_manager
        self._user_resolver = user_resolver
        self._content_catalog = content_catalog
        self._observability = observability
        self._policy_revision_watcher = policy_revision_watcher
        self._route_lookup = route_lookup
        self._rbac_mode = "off"
        if enforce is not None:
            self._enforce = enforce
        elif settings is not None:
            self._enforce = settings.rbac_enforcing
            self._rbac_mode = settings.rbac_mode
        else:
            self._enforce = True
            self._rbac_mode = "off"
    @staticmethod
    def _visible(
        policy: RbacPolicy,
        roles: frozenset[str],
        identity: VerifiedIdentity | None,
        name: str,
    ) -> bool:
        if not policy.allows(roles, name):
            return False
        if (
            identity is not None
            and identity.subject_type == "service"
            and name in MUTATING_ADMIN_TOOL_NAMES
        ):
            return False
        if requires_human_identity(name, policy) and not has_interactive_human_identity(identity):
            return False
        return True

    async def on_list_tools(
        self,
        context: MiddlewareContext[ListToolsRequest],
        call_next,
    ) -> list[Tool]:
        tools = list(await call_next(context))
        decision = await self._evaluate(
            context,
            name=None,
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
        identity = resolve_verified_identity()
        return [
            tool for tool in tools if self._visible(policy, decision.roles, identity, tool.name)
        ]

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next,
    ):
        tool_name = context.message.name
        decision = await self._evaluate(
            context,
            name=tool_name,
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
        token = current_call_decision.set(_decision_for_signing(decision))
        try:
            return await call_next(context)
        finally:
            current_call_decision.reset(token)

    async def on_list_prompts(
        self,
        context: MiddlewareContext[ListPromptsRequest],
        call_next,
    ):
        prompts = list(await call_next(context))
        decision = await self._evaluate(
            context,
            name=None,
            roles_only=True,
            operation="list_prompts",
        )
        if not self._enforce:
            return prompts
        if not decision.allowed:
            return []
        policy = self._load_policy(operation="list_prompts")
        if policy is None:
            return []
        identity = resolve_verified_identity()
        return [
            prompt
            for prompt in prompts
            if self._visible(policy, decision.roles, identity, prompt.name)
        ]

    async def on_get_prompt(
        self,
        context: MiddlewareContext[GetPromptRequestParams],
        call_next,
    ):
        prompt_name = context.message.name
        decision = await self._evaluate(
            context,
            name=prompt_name,
            roles_only=False,
            operation="get_prompt",
        )
        if not decision.allowed and self._enforce:
            raise PromptError(CLIENT_DENIAL_MESSAGE)
        token = current_call_decision.set(_decision_for_signing(decision))
        try:
            return await call_next(context)
        finally:
            current_call_decision.reset(token)

    async def on_list_resources(
        self,
        context: MiddlewareContext[ListResourcesRequest],
        call_next,
    ):
        resources = list(await call_next(context))
        decision = await self._evaluate(
            context,
            name=None,
            roles_only=True,
            operation="list_resources",
        )
        if not self._enforce:
            return resources
        if not decision.allowed:
            return []
        policy = self._load_policy(operation="list_resources")
        if policy is None:
            return []
        catalog = self._content_catalog
        filtered = []
        for resource in resources:
            rbac_names: tuple[str, ...] = ()
            if catalog is not None:
                rbac_names = catalog.rbac_names_for_uri(str(resource.uri))
            if not rbac_names:
                continue
            if all(policy.allows(decision.roles, name) for name in rbac_names):
                filtered.append(resource)
        return filtered

    async def on_list_resource_templates(
        self,
        context: MiddlewareContext[ListResourceTemplatesRequest],
        call_next,
    ):
        templates = list(await call_next(context))
        decision = await self._evaluate(
            context,
            name=None,
            roles_only=True,
            operation="list_resource_templates",
        )
        if not self._enforce:
            return templates
        if not decision.allowed:
            return []
        policy = self._load_policy(operation="list_resource_templates")
        if policy is None:
            return []
        catalog = self._content_catalog
        filtered = []
        for template in templates:
            rbac_name = None
            if catalog is not None:
                rbac_name = catalog.rbac_name_for_template_listing(template.uri_template)
            if rbac_name is None:
                continue
            if policy.allows(decision.roles, rbac_name):
                filtered.append(template)
        return filtered

    async def on_read_resource(
        self,
        context: MiddlewareContext[ReadResourceRequestParams],
        call_next,
    ):
        published_uri = str(context.message.uri)
        rbac_names: tuple[str, ...] = ()
        if self._content_catalog is not None:
            rbac_names = self._content_catalog.rbac_names_for_uri(published_uri)

        if not rbac_names:
            identity = resolve_verified_identity()
            decision = RbacDecision(
                tool_name=published_uri,
                email=identity.subject if identity else None,
                allowed=False,
                reason=RbacDenialReason.NOT_PERMITTED,
                subject_type=identity.subject_type if identity else None,
            )
            self._record_decision(decision, operation="read_resource")
            if self._enforce:
                raise ResourceError(CLIENT_DENIAL_MESSAGE)
            token = current_call_decision.set(_decision_for_signing(decision))
            try:
                return await call_next(context)
            finally:
                current_call_decision.reset(token)

        last_decision = None
        for rbac_name in rbac_names:
            decision = await self._evaluate(
                context,
                name=rbac_name,
                roles_only=False,
                operation="read_resource",
            )
            if not decision.allowed and self._enforce:
                raise ResourceError(CLIENT_DENIAL_MESSAGE)
            last_decision = decision
        assert last_decision is not None
        token = current_call_decision.set(_decision_for_signing(last_decision))
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
        subject: str,
        *,
        critical: bool,
    ) -> UserResolveResult:
        outcome_holder = {"outcome": "miss"}
        started = time.perf_counter()
        try:
            user = await self._user_resolver.resolve(subject, critical=critical)
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
        name: str | None,
        roles_only: bool,
        operation: str,
    ) -> RbacDecision:
        from keystone_mcp.observability.tracing import traced

        with traced(
            "keystone.rbac.decide",
            keystone_rbac_mode=self._rbac_mode,
            keystone_mcp_operation=operation,
        ):
            decision = await self._evaluate_inner(
                context,
                name=name,
                roles_only=roles_only,
                operation=operation,
            )
            self._annotate_rbac_span(decision, name=name, operation=operation)
            return decision

    async def _evaluate_inner(
        self,
        context: MiddlewareContext,
        *,
        name: str | None,
        roles_only: bool,
        operation: str,
    ) -> RbacDecision:
        if self._policy_revision_watcher is not None:
            try:
                await self._policy_revision_watcher.ensure_current()
            except Exception:
                logger.warning(
                    "rbac policy revision check failed; continuing with current snapshot",
                    exc_info=True,
                )
        identity = resolve_verified_identity()
        if identity is None:
            decision = RbacDecision(
                tool_name=name or "",
                email=None,
                allowed=False,
                reason=RbacDenialReason.NO_IDENTITY,
            )
            self._record_decision(decision, operation=operation)
            return decision

        task_id = self._task_id_for_tool_call(
            context,
            operation=operation,
            published_name=name,
            identity=identity,
        )

        login_provider = (identity.claims or {}).get("auth_method")

        critical = False
        if name:
            # Critical-tool globs live in the active policy; the core built-ins
            # apply even before a policy is loaded.
            active_policy = self._active_policy()
            critical = is_critical_tool(
                name,
                active_policy.critical_tool_patterns if active_policy is not None else (),
            )
        try:
            user = await self._resolve_user(identity.subject, critical=critical)
        except UserDirectoryUnavailableError:
            decision = RbacDecision(
                tool_name=name or "",
                email=identity.subject,
                login_provider=login_provider,
                allowed=False,
                reason=RbacDenialReason.ROLES_UNAVAILABLE,
                subject_type=identity.subject_type,
                task_id=task_id,
            )
            self._record_decision(decision, operation=operation)
            return decision
        except Exception as exc:
            logger.warning(
                "rbac user directory resolve failed for %s: %s",
                subject_pseudonym(identity.subject),
                exc,
                exc_info=True,
            )
            decision = RbacDecision(
                tool_name=name or "",
                email=identity.subject,
                login_provider=login_provider,
                allowed=False,
                reason=RbacDenialReason.ROLES_UNAVAILABLE,
                subject_type=identity.subject_type,
                task_id=task_id,
            )
            self._record_decision(decision, operation=operation)
            return decision

        if getattr(user, "subject_type", "human") != identity.subject_type:
            decision = RbacDecision(
                tool_name=name or "",
                email=identity.subject,
                login_provider=login_provider,
                allowed=False,
                reason=RbacDenialReason.SUBJECT_TYPE_MISMATCH,
                roles=frozenset(user.roles),
                cache_hit=getattr(user, "from_cache", False),
                subject_type=identity.subject_type,
                task_id=task_id,
            )
            self._record_decision(decision, operation=operation)
            return decision

        roles = frozenset(user.roles)
        if user.is_blocked:
            decision = RbacDecision(
                tool_name=name or "",
                email=identity.subject,
                subject_type=identity.subject_type,
                login_provider=login_provider,
                allowed=False,
                reason=RbacDenialReason.USER_BLOCKED,
                roles=roles,
                cache_hit=getattr(user, "from_cache", False),
                task_id=task_id,
            )
            self._record_decision(decision, operation=operation)
            return decision

        if not _user_may_access_tools(user):
            decision = RbacDecision(
                tool_name=name or "",
                email=identity.subject,
                subject_type=identity.subject_type,
                login_provider=login_provider,
                allowed=False,
                reason=RbacDenialReason.NO_ROLES,
                roles=roles,
                cache_hit=getattr(user, "from_cache", False),
                task_id=task_id,
            )
            self._record_decision(decision, operation=operation)
            return decision

        if roles_only or name is None:
            decision = RbacDecision(
                tool_name="",
                email=identity.subject,
                subject_type=identity.subject_type,
                login_provider=login_provider,
                allowed=True,
                roles=roles,
                cache_hit=getattr(user, "from_cache", False),
                task_id=task_id,
            )
            self._record_decision(decision, operation=operation)
            return decision

        policy = self._load_policy(operation=operation)
        if policy is None:
            decision = RbacDecision(
                tool_name=name,
                email=identity.subject,
                subject_type=identity.subject_type,
                login_provider=login_provider,
                allowed=False,
                reason=RbacDenialReason.POLICY_UNAVAILABLE,
                cache_hit=getattr(user, "from_cache", False),
                task_id=task_id,
            )
            self._record_decision(decision, operation=operation)
            return decision

        if policy.allows(roles, name):
            if requires_human_identity(name, policy) and not has_interactive_human_identity(
                identity
            ):
                decision = RbacDecision(
                    tool_name=name,
                    email=identity.subject,
                    subject_type=identity.subject_type,
                    login_provider=login_provider,
                    allowed=False,
                    reason=RbacDenialReason.HUMAN_IDENTITY_REQUIRED,
                    roles=roles,
                    cache_hit=getattr(user, "from_cache", False),
                    task_id=task_id,
                )
                self._record_decision(decision, operation=operation)
                return decision
            decision = RbacDecision(
                tool_name=name,
                email=identity.subject,
                subject_type=identity.subject_type,
                login_provider=login_provider,
                allowed=True,
                roles=roles,
                cache_hit=getattr(user, "from_cache", False),
                task_id=task_id,
            )
            self._record_decision(decision, operation=operation)
            return decision

        decision = RbacDecision(
            tool_name=name,
            email=identity.subject,
            login_provider=login_provider,
            allowed=False,
            reason=RbacDenialReason.NOT_PERMITTED,
            roles=roles,
            cache_hit=getattr(user, "from_cache", False),
            subject_type=identity.subject_type,
            task_id=task_id,
        )
        self._record_decision(decision, operation=operation)
        return decision

    def _task_id_for_tool_call(
        self,
        context: MiddlewareContext,
        *,
        operation: str,
        published_name: str | None,
        identity: VerifiedIdentity,
    ) -> str | None:
        if operation != "call_tool" or not published_name or self._route_lookup is None:
            return None
        route = self._route_lookup(published_name)
        if route is None:
            return None
        message = context.message
        args: dict[str, Any] = getattr(message, "arguments", None) or {}
        return make_task_id(identity, route.name, args, namespace=route.namespace)

    def _annotate_rbac_span(
        self,
        decision: RbacDecision,
        *,
        name: str | None,
        operation: str,
    ) -> None:
        from keystone_mcp.observability.tracing import is_tracing_active

        if not is_tracing_active():
            return
        from opentelemetry import trace

        span = trace.get_current_span()
        if not span.is_recording():
            return
        tool_name = name or decision.tool_name or ""
        if operation == "call_tool" and tool_name and self._route_lookup is not None:
            tool_attr = tool_name if self._route_lookup(tool_name) is not None else "unknown"
        else:
            tool_attr = tool_name or "unknown"
        span.set_attribute("keystone.rbac.decision", "allow" if decision.allowed else "deny")
        span.set_attribute(
            "keystone.rbac.reason",
            decision.reason.value if decision.reason is not None else "",
        )
        span.set_attribute("keystone.tool", tool_attr)

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
                login_provider=decision.login_provider,
                subject_type=decision.subject_type,
                task_id=decision.task_id,
            )
            return
        logger.info(
            "rbac decision tool=%s subject=%s allowed=%s reason=%s roles=%s",
            decision.tool_name or "*",
            subject_pseudonym(decision.email),
            decision.allowed,
            decision.reason.value if decision.reason else None,
            sorted(decision.roles),
        )


def _user_may_access_tools(user: UserResolveResult) -> bool:
    return user.exists and not user.is_blocked and bool(user.roles)
