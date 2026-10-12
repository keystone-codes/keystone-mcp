"""Facade wiring audit events and Prometheus metrics."""

from __future__ import annotations

from typing import TYPE_CHECKING

from keystone_mcp.observability.audit import (
    AuthzAuditRecorder,
    PolicyAuditFields,
    UsersMutationAuditRecorder,
    policy_fields,
)
from keystone_mcp.observability.metrics import RbacMetrics
from keystone_mcp.observability.tool_family import tool_family
from keystone_mcp.user_directory.critical import is_critical_tool

if TYPE_CHECKING:
    from keystone_mcp.config import Settings
    from keystone_mcp.rbac.loader import PolicyIdentity, RbacPolicyManager
    from keystone_mcp.router.rbac_middleware import RbacDenialReason


class RbacObservability:
    """Coordinates structured audit logging and Prometheus metrics."""

    def __init__(
        self,
        settings: Settings,
        *,
        policy_manager: RbacPolicyManager | None = None,
    ) -> None:
        self._policy_manager = policy_manager
        self.authz_audit = AuthzAuditRecorder(
            enabled=settings.rbac_audit_enabled,
            list_tools_allow_sample_rate=settings.rbac_audit_list_tools_sample_rate,
            subject_salt=settings.rbac_audit_subject_salt,
        )
        self.users_audit = UsersMutationAuditRecorder(
            enabled=settings.rbac_audit_enabled,
            subject_salt=settings.rbac_audit_subject_salt,
        )
        self.metrics = RbacMetrics(
            enabled=settings.metrics_enabled,
            tool_name_mode=settings.metrics_tool_name,
            oauth_client_id_limit=settings.metrics_oauth_client_id_limit,
        )

    def active_policy_fields(self) -> PolicyAuditFields:
        identity: PolicyIdentity | None = None
        if self._policy_manager is not None:
            identity = self._policy_manager.identity
        return policy_fields(identity)

    def critical_tool_patterns(self) -> tuple[str, ...]:
        """Critical-tool globs from the active policy (empty when none loaded)."""
        if self._policy_manager is None:
            return ()
        policy = self._policy_manager.active_policy
        return policy.critical_tool_patterns if policy is not None else ()

    def record_authz_decision(
        self,
        *,
        tool_name: str,
        email: str | None,
        allowed: bool,
        reason: RbacDenialReason | None,
        roles: frozenset[str],
        cache_hit: bool | None,
        operation: str,
        request_id: str | None,
        login_provider: str | None = None,
    ) -> None:
        policy = self.active_policy_fields()
        family = tool_family(tool_name)
        critical = (
            is_critical_tool(tool_name, self.critical_tool_patterns()) if tool_name else False
        )
        try:
            self.authz_audit.record_decision(
                tool_name=tool_name,
                email=email,
                allowed=allowed,
                reason=reason,
                roles=roles,
                policy=policy,
                cache_hit=cache_hit,
                operation=operation,
                request_id=request_id,
                critical=critical,
                login_provider=login_provider,
            )
            self.metrics.record_decision(
                allowed=allowed,
                reason=reason,
                tool_family_label=family,
                operation=operation,
            )
        except Exception:
            # Audit must never affect authorization verdict or request handling.
            import logging

            logging.getLogger(__name__).warning("rbac observability record failed", exc_info=True)

    def record_directory_resolve(
        self, *, outcome: str, duration_seconds: float | None = None
    ) -> None:
        try:
            self.metrics.record_directory_resolve(
                outcome=outcome, duration_seconds=duration_seconds
            )
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "rbac directory resolve metric failed",
                exc_info=True,
            )

    def record_policy_reload(self, *, success: bool) -> None:
        try:
            self.metrics.record_policy_reload(success=success)
        except Exception:
            import logging

            logging.getLogger(__name__).warning("rbac policy reload metric failed", exc_info=True)

    def record_catalog_refresh(
        self,
        *,
        unchanged: bool = False,
        held: bool = False,
        applied: bool = False,
        added: int = 0,
        removed: int = 0,
    ) -> None:
        try:
            self.metrics.record_catalog_refresh(
                unchanged=unchanged,
                held=held,
                applied=applied,
                added=added,
                removed=removed,
            )
        except Exception:
            import logging

            logging.getLogger(__name__).warning("catalog refresh metric failed", exc_info=True)

    def record_list_changed(self, *, kind: str, sessions: int) -> None:
        try:
            self.metrics.record_list_changed(kind=kind, sessions=sessions)
        except Exception:
            import logging

            logging.getLogger(__name__).warning("list_changed metric failed", exc_info=True)

    def record_upstream_available(self, *, namespace: str, available: bool) -> None:
        try:
            self.metrics.set_upstream_available(namespace=namespace, available=available)
        except Exception:
            import logging

            logging.getLogger(__name__).warning("upstream available metric failed", exc_info=True)

    def record_users_mutation(
        self,
        *,
        operation: str,
        actor_email: str,
        target_email: str | None,
        outcome: str,
        code: str | None,
        task_id: str,
        before_roles: tuple[str, ...] | None = None,
        after_roles: tuple[str, ...] | None = None,
        blocked_before: bool | None = None,
        blocked_after: bool | None = None,
        role: str | None = None,
    ) -> None:
        policy = self.active_policy_fields()
        try:
            self.users_audit.record_mutation(
                operation=operation,
                actor_email=actor_email,
                target_email=target_email,
                outcome=outcome,
                code=code,
                task_id=task_id,
                policy=policy,
                before_roles=before_roles,
                after_roles=after_roles,
                blocked_before=blocked_before,
                blocked_after=blocked_after,
                role=role,
            )
            self.metrics.record_users_mutation(operation=operation, outcome=outcome)
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "rbac users mutation observability failed", exc_info=True
            )

    def record_tool_call_attempt(self, *, tool_name: str) -> None:
        try:
            self.metrics.record_tool_call_attempt(tool_name=tool_name)
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "tool call attempt metric failed",
                exc_info=True,
            )

    def record_tool_invocation(
        self,
        *,
        tool_name: str,
        outcome: str,
        duration_seconds: float,
    ) -> None:
        try:
            self.metrics.record_tool_invocation(
                tool_name=tool_name,
                outcome=outcome,
                duration_seconds=duration_seconds,
            )
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "tool invocation metric failed",
                exc_info=True,
            )

    def record_oauth_client_registration(
        self, *, outcome: str, client_count: int | None = None
    ) -> None:
        try:
            self.metrics.record_oauth_client_registration(outcome=outcome)
            if client_count is not None:
                self.metrics.set_oauth_clients_gauge(client_count)
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "oauth client registration metric failed",
                exc_info=True,
            )

    def metrics_response(self) -> tuple[bytes, str]:
        return self.metrics.scrape()
