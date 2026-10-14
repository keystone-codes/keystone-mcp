"""Facade wiring audit events and Prometheus metrics."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from keystone_mcp.observability.audit import (
    AuthzAuditRecorder,
    PolicyAuditFields,
    PolicyMutationAuditRecorder,
    SessionAuditRecorder,
    UsersMutationAuditRecorder,
    policy_fields,
)
from keystone_mcp.observability.metrics import RbacMetrics
from keystone_mcp.observability.subject import configure_subject_salt
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
        configure_subject_salt(settings.rbac_audit_subject_salt)
        self.authz_audit = AuthzAuditRecorder(
            enabled=settings.rbac_audit_enabled,
            list_tools_allow_sample_rate=settings.rbac_audit_list_tools_sample_rate,
            subject_salt=settings.rbac_audit_subject_salt,
        )
        self.users_audit = UsersMutationAuditRecorder(
            enabled=settings.rbac_audit_enabled,
            subject_salt=settings.rbac_audit_subject_salt,
        )
        self.session_audit = SessionAuditRecorder(
            enabled=settings.rbac_audit_enabled,
            subject_salt=settings.rbac_audit_subject_salt,
        )
        self.policy_audit = PolicyMutationAuditRecorder(
            enabled=settings.rbac_audit_enabled,
            subject_salt=settings.rbac_audit_subject_salt,
        )
        self.metrics = RbacMetrics(
            enabled=settings.metrics_enabled,
            tool_name_mode=settings.metrics_tool_name,
            oauth_client_id_limit=settings.metrics_oauth_client_id_limit,
        )
        self._known_name_check: Callable[[str, str], bool] | None = None

    def set_known_name_check(self, check: Callable[[str, str], bool] | None) -> None:
        self._known_name_check = check

    def _tool_is_known(self, tool_name: str) -> bool:
        if self._known_name_check is None:
            return True
        return self._known_name_check("tool", tool_name)

    def _authz_tool_family_label(self, tool_name: str, operation: str) -> str:
        if not tool_name:
            return tool_family(tool_name)
        if self._known_name_check is None:
            return tool_family(tool_name)
        kind_by_operation = {
            "call_tool": "tool",
            "get_prompt": "prompt",
            "read_resource": "resource",
        }
        kind = kind_by_operation.get(operation, "tool")
        if self._known_name_check(kind, tool_name):
            return tool_family(tool_name)
        return "unknown"

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
        subject_type: str | None = None,
        task_id: str | None = None,
    ) -> None:
        policy = self.active_policy_fields()
        family = self._authz_tool_family_label(tool_name, operation)
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
                subject_type=subject_type,
                task_id=task_id,
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

    def record_policy_identity(self, identity: PolicyIdentity) -> None:
        try:
            self.metrics.record_policy_identity(content_hash=identity.content_hash)
        except Exception:
            import logging

            logging.getLogger(__name__).warning("rbac policy info metric failed", exc_info=True)

    def set_policy_in_sync(self, value: bool | None) -> None:
        try:
            self.metrics.set_policy_in_sync(value)
        except Exception:
            import logging

            logging.getLogger(__name__).warning("rbac policy in_sync metric failed", exc_info=True)

    def record_policy_revision_check(self, *, outcome: str) -> None:
        try:
            self.metrics.record_policy_revision_check(outcome=outcome)
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "rbac policy revision check metric failed", exc_info=True
            )

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

    def record_upstream_process_restart(self, *, namespace: str) -> None:
        try:
            self.metrics.record_upstream_process_restart(namespace=namespace)
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "upstream process restart metric failed", exc_info=True
            )

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
        actor_subject_type: str | None = None,
        key_id: str | None = None,
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
                actor_subject_type=actor_subject_type,
                key_id=key_id,
            )
            self.metrics.record_users_mutation(operation=operation, outcome=outcome)
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "rbac users mutation observability failed", exc_info=True
            )

    def record_policy_mutation(
        self,
        *,
        operation: str,
        actor_email: str,
        outcome: str,
        code: str | None,
        task_id: str,
        policy_version_before: str | None = None,
        policy_version_after: str | None = None,
        content_hash_before: str | None = None,
        content_hash_after: str | None = None,
        changes: tuple[str, ...] = (),
        warnings_count: int = 0,
        actor_subject_type: str | None = None,
    ) -> None:
        try:
            self.policy_audit.record_mutation(
                operation=operation,
                actor_email=actor_email,
                outcome=outcome,
                code=code,
                task_id=task_id,
                policy_version_before=policy_version_before,
                policy_version_after=policy_version_after,
                content_hash_before=content_hash_before,
                content_hash_after=content_hash_after,
                changes=changes,
                warnings_count=warnings_count,
                actor_subject_type=actor_subject_type,
            )
            self.metrics.record_policy_mutation(operation=operation, outcome=outcome)
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "rbac policy mutation observability failed", exc_info=True
            )

    def record_admin_refusal(self, *, operation: str, reason: str) -> None:
        try:
            self.metrics.record_admin_refusal(operation=operation, reason=reason)
        except Exception:
            import logging

            logging.getLogger(__name__).warning("admin refusal metric failed", exc_info=True)

    def record_tool_call_attempt(self, *, tool_name: str) -> None:
        try:
            self.metrics.record_tool_call_attempt(
                tool_name=tool_name,
                known=self._tool_is_known(tool_name),
            )
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
                known=self._tool_is_known(tool_name),
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

    def record_oauth_client_eviction(self) -> None:
        try:
            self.metrics.record_oauth_client_eviction()
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "oauth client eviction metric failed",
                exc_info=True,
            )

    def record_token_exchange(self, *, grant_type: str, outcome: str) -> None:
        try:
            self.metrics.record_token_exchange(grant_type=grant_type, outcome=outcome)
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "oauth token exchange metric failed",
                exc_info=True,
            )

    def record_login_identity_binding(self, *, outcome: str) -> None:
        try:
            self.metrics.record_login_identity_binding(outcome=outcome)
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "login identity binding metric failed",
                exc_info=True,
            )

    def record_session_event(
        self,
        *,
        action: str,
        subject: str,
        client_id: str,
        revoked_tokens: int | None = None,
        reason: str | None = None,
        delay_ms: int | None = None,
        login_provider: str | None = None,
    ) -> None:
        try:
            self.session_audit.record_session_event(
                action=action,
                subject=subject,
                client_id=client_id,
                revoked_tokens=revoked_tokens,
                reason=reason,
                delay_ms=delay_ms,
                login_provider=login_provider,
            )
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "oauth session audit failed",
                exc_info=True,
            )

    def record_api_key_verification(self, outcome: str) -> None:
        try:
            self.metrics.record_api_key_verification(outcome=outcome)
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "api key verification metric failed",
                exc_info=True,
            )

    def set_api_key_cache_size(self, cache: str, size: int) -> None:
        try:
            self.metrics.set_api_key_cache_size(cache=cache, size=size)
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "api key cache size metric failed",
                exc_info=True,
            )

    def record_api_key_cache_evictions(self, cache: str, count: int) -> None:
        try:
            self.metrics.record_api_key_cache_evictions(cache=cache, count=count)
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "api key cache eviction metric failed",
                exc_info=True,
            )

    def record_users_revision_bump_failed(self) -> None:
        try:
            self.metrics.record_users_revision_bump_failed()
        except Exception:
            import logging

            logging.getLogger(__name__).warning(
                "users revision bump failed metric failed",
                exc_info=True,
            )

    def metrics_response(self) -> tuple[bytes, str]:
        return self.metrics.scrape()
