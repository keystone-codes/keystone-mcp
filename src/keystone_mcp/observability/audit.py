"""Structured audit events for RBAC decisions and users mutations."""

from __future__ import annotations

import json
import logging
import random
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from keystone_mcp.identity import resolve_verified_identity
from keystone_mcp.observability.logging.context import get_request_id
from keystone_mcp.observability.subject import hash_subject, roles_label
from keystone_mcp.observability.tool_family import tool_family
from keystone_mcp.observability.tracing import current_trace_ids

if TYPE_CHECKING:
    from keystone_mcp.rbac.loader import PolicyIdentity
    from keystone_mcp.router.rbac_middleware import RbacDenialReason

logger = logging.getLogger(__name__)


def _audit_trace_fields() -> dict[str, str]:
    ids = current_trace_ids()
    if ids is None:
        return {}
    trace_id, _span_id = ids
    return {"trace_id": trace_id}


@dataclass(frozen=True, slots=True)
class PolicyAuditFields:
    version: str | None
    content_hash: str | None


def policy_fields(identity: PolicyIdentity | None) -> PolicyAuditFields:
    if identity is None:
        return PolicyAuditFields(version=None, content_hash=None)
    return PolicyAuditFields(version=identity.version, content_hash=identity.content_hash)


class AuthzAuditRecorder:
    """Best-effort structured audit for RBAC allow/deny decisions."""

    def __init__(
        self,
        *,
        enabled: bool,
        list_tools_allow_sample_rate: float,
        subject_salt: str = "",
    ) -> None:
        self._enabled = enabled
        self._list_tools_allow_sample_rate = max(0.0, min(1.0, list_tools_allow_sample_rate))
        self._subject_salt = subject_salt

    @property
    def enabled(self) -> bool:
        return self._enabled

    def should_emit(
        self,
        *,
        allowed: bool,
        tool_name: str,
        operation: str,
    ) -> bool:
        if not self._enabled:
            return False
        if not allowed:
            return True
        if operation != "list_tools":
            return True
        if tool_name:
            return True
        return random.random() < self._list_tools_allow_sample_rate

    def record_decision(
        self,
        *,
        tool_name: str,
        email: str | None,
        allowed: bool,
        reason: RbacDenialReason | None,
        roles: frozenset[str],
        policy: PolicyAuditFields,
        cache_hit: bool | None,
        operation: str,
        request_id: str | None,
        critical: bool = False,
        login_provider: str | None = None,
        subject_type: str | None = None,
        task_id: str | None = None,
    ) -> None:
        if not self.should_emit(allowed=allowed, tool_name=tool_name, operation=operation):
            return
        if request_id is None:
            request_id = get_request_id()
        event = {
            "event": "rbac_authz_decision",
            "subject": hash_subject(email, salt=self._subject_salt),
            "tool": tool_name or "*",
            "tool_family": tool_family(tool_name),
            "decision": "allow" if allowed else "deny",
            "reason": reason.value if reason is not None else None,
            "roles": roles_label(roles),
            "policy_version": policy.version,
            "policy_content_hash": policy.content_hash,
            "critical": critical,
            "cache_hit": cache_hit,
            "operation": operation,
            "request_id": request_id,
            # The sign-in method's name: lets an operator see *why* a
            # human_identity_required denial happened without looking up the
            # token separately, e.g. "signed in with api_key".
            "login_provider": login_provider,
            "subject_type": subject_type,
            "task_id": task_id,
        }
        try:
            event.update(self._delegation_fields())
        except Exception:
            logger.warning("delegation fields for rbac audit failed", exc_info=True)
        self._emit(event)

    def _delegation_fields(self) -> dict[str, Any]:
        """Actor and requester from a delegated token. Absent keys stay absent."""
        identity = resolve_verified_identity()
        if identity is None:
            return {}
        claims = identity.claims or {}
        extra: dict[str, Any] = {}
        act = claims.get("act")
        if isinstance(act, dict) and isinstance(act.get("sub"), str) and act["sub"]:
            hashed = hash_subject(act["sub"], salt=self._subject_salt)
            if hashed is not None:
                extra["actor"] = hashed
        requested_by = claims.get("requested_by")
        if isinstance(requested_by, str) and requested_by:
            hashed = hash_subject(requested_by, salt=self._subject_salt)
            if hashed is not None:
                extra["requested_by"] = hashed
        delegation_jti = claims.get("delegation_jti")
        if isinstance(delegation_jti, str) and delegation_jti:
            extra["delegation_jti"] = delegation_jti
        return extra

    def record_delegation_exchange(
        self,
        *,
        outcome: str,
        reason: str | None,
        mode: str | None,
        delegation_jti: str | None,
        resource: str | None,
        requested_by_verified: bool | None,
        subject: str | None,
        actor: str | None,
        requested_by: str | None,
        kst_client: str | None = None,
        kst_project: str | None = None,
        kst_session: str | None = None,
    ) -> None:
        """One ``delegation_exchange`` line. Addresses and keys are already hashed."""
        if not self._enabled:
            return
        event: dict[str, Any] = {
            "event": "delegation_exchange",
            "outcome": outcome,
            "reason": reason,
            "mode": mode,
            "delegation_jti": delegation_jti,
            "resource": resource,
            "requested_by_verified": requested_by_verified,
            "subject": hash_subject(subject, salt=self._subject_salt),
            "actor": hash_subject(actor, salt=self._subject_salt),
            "requested_by": hash_subject(requested_by, salt=self._subject_salt),
        }
        if kst_client is not None:
            event["kst_client"] = kst_client
        if kst_project is not None:
            event["kst_project"] = kst_project
        if kst_session is not None:
            event["kst_session"] = kst_session
        self._emit(event)

    def _emit(self, event: dict[str, Any]) -> None:
        try:
            payload = {**event, **_audit_trace_fields()}
            logger.info(
                "rbac audit %s",
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                extra={"stream": "audit"},
            )
        except Exception:
            logger.warning("rbac audit emit failed", exc_info=True)


class UsersMutationAuditRecorder:
    """Best-effort audit for users_* administrative operations."""

    def __init__(self, *, enabled: bool, subject_salt: str = "") -> None:
        self._enabled = enabled
        self._subject_salt = subject_salt

    def record_mutation(
        self,
        *,
        operation: str,
        actor_email: str,
        target_email: str | None,
        outcome: str,
        code: str | None,
        task_id: str,
        policy: PolicyAuditFields,
        before_roles: tuple[str, ...] | None = None,
        after_roles: tuple[str, ...] | None = None,
        blocked_before: bool | None = None,
        blocked_after: bool | None = None,
        role: str | None = None,
        actor_subject_type: str | None = None,
        key_id: str | None = None,
    ) -> None:
        if not self._enabled:
            return
        event: dict[str, Any] = {
            "event": "rbac_users_mutation",
            "operation": operation,
            "actor": hash_subject(actor_email, salt=self._subject_salt),
            "target": hash_subject(target_email, salt=self._subject_salt) if target_email else None,
            "outcome": outcome,
            "code": code,
            "task_id": task_id,
            "policy_version": policy.version,
            "policy_content_hash": policy.content_hash,
        }
        if role is not None:
            event["role"] = role
        if before_roles is not None or after_roles is not None:
            event["roles_before"] = roles_label(before_roles or ())
            event["roles_after"] = roles_label(after_roles or ())
        if blocked_before is not None or blocked_after is not None:
            event["blocked_before"] = blocked_before
            event["blocked_after"] = blocked_after
        if actor_subject_type is not None:
            event["actor_subject_type"] = actor_subject_type
        if key_id is not None:
            event["key_id"] = key_id
        try:
            logger.info(
                "rbac audit %s",
                json.dumps(event, sort_keys=True, separators=(",", ":")),
                extra={"stream": "audit"},
            )
        except Exception:
            logger.warning("rbac users mutation audit emit failed", exc_info=True)


class SessionAuditRecorder:
    """Best-effort audit for OAuth session rotation and replay events."""

    def __init__(self, *, enabled: bool, subject_salt: str = "") -> None:
        self._enabled = enabled
        self._subject_salt = subject_salt

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
        if not self._enabled:
            return
        hashed = hash_subject(subject, salt=self._subject_salt) if subject else None
        event: dict[str, Any] = {
            "event": "oauth_session",
            "action": action,
            "subject": hashed,
            "client_id": client_id,
        }
        if login_provider is not None:
            event["login_provider"] = login_provider
        if revoked_tokens is not None:
            event["revoked_tokens"] = revoked_tokens
        if reason is not None:
            event["reason"] = reason
        if delay_ms is not None:
            event["delay_ms"] = delay_ms
        try:
            logger.info(
                "rbac audit %s",
                json.dumps(event, sort_keys=True, separators=(",", ":")),
                extra={"stream": "audit"},
            )
        except Exception:
            logger.warning("oauth session audit emit failed", exc_info=True)


class PolicyMutationAuditRecorder:
    """Best-effort audit for ``policy_*`` administrative operations.

    Never includes allow-pattern or other glob text, only role names and
    pattern counts (see
    :func:`keystone_mcp.rbac.policy_document.describe_change`), so the audit
    log cannot leak the shape of a policy an operator wanted kept private.
    """

    def __init__(self, *, enabled: bool, subject_salt: str = "") -> None:
        self._enabled = enabled
        self._subject_salt = subject_salt

    def record_mutation(
        self,
        *,
        operation: str,
        actor_email: str,
        outcome: str,
        code: str | None,
        task_id: str,
        policy_version_before: str | None,
        policy_version_after: str | None,
        content_hash_before: str | None,
        content_hash_after: str | None,
        changes: tuple[str, ...],
        warnings_count: int,
        actor_subject_type: str | None = None,
    ) -> None:
        if not self._enabled:
            return
        event: dict[str, Any] = {
            "event": "rbac_policy_mutation",
            "operation": operation,
            "actor": hash_subject(actor_email, salt=self._subject_salt),
            "outcome": outcome,
            "code": code,
            "task_id": task_id,
            "policy_version_before": policy_version_before,
            "policy_version_after": policy_version_after,
            "content_hash_before": content_hash_before,
            "content_hash_after": content_hash_after,
            "changes": list(changes),
            "warnings_count": warnings_count,
        }
        if actor_subject_type is not None:
            event["actor_subject_type"] = actor_subject_type
        try:
            logger.info(
                "rbac audit %s",
                json.dumps(event, sort_keys=True, separators=(",", ":")),
                extra={"stream": "audit"},
            )
        except Exception:
            logger.warning("rbac policy mutation audit emit failed", exc_info=True)
