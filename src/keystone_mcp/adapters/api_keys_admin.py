"""Builtin api_keys_* admin tools."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from redis.exceptions import RedisError

from keystone_mcp.adapters.guards import (
    check_management_authority,
    require_human_actor,
    resolve_admin_call,
)
from keystone_mcp.plugins import missing_members
from keystone_mcp.user_directory.errors import UsersError
from keystone_mcp.user_directory.protocol import ApiKeyDirectory, UserDirectory
from keystone_mcp.user_directory.types import subject_type_of

API_KEYS_ADMIN_ERROR_CODES: frozenset[str] = frozenset(
    {
        "actor_email_required",
        "bad_request",
        "conflict",
        "forbidden",
        "identity_binding_conflict",
        "last_administrator",
        "self_admin_mutation_forbidden",
        "service_error",
        "service_timeout",
        "service_unavailable",
        "user_not_found",
        "validation_error",
    }
)

if TYPE_CHECKING:
    from keystone_mcp.auth.sessions import SessionRevoker
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.rbac.management import ManagementSource
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route

logger = logging.getLogger(__name__)


class ApiKeysAdminAdapter:
    def __init__(
        self,
        *,
        directory: UserDirectory | None = None,
        management_source: ManagementSource | None = None,
        observability: RbacObservability | None = None,
        session_revoker: SessionRevoker | None = None,
    ) -> None:
        self._directory = directory
        self._management_source = management_source
        self._observability = observability
        self._session_revoker = session_revoker

    @staticmethod
    def _error(route: Route, ctx: RouteContext, *, code: str, message: str) -> dict[str, Any]:
        return {
            "state": "error",
            "tool": route.name,
            "task_id": ctx.task_id,
            "code": code,
            "message": message,
        }

    @staticmethod
    def _done(route: Route, ctx: RouteContext, **payload: Any) -> dict[str, Any]:
        return {
            "state": "done",
            "tool": route.name,
            "task_id": ctx.task_id,
            **payload,
        }

    async def execute(
        self,
        route: Route,
        ctx: RouteContext,
        args: dict[str, Any],
        request: Any,
    ) -> dict[str, Any]:
        spec = request if isinstance(request, dict) else dict(args)
        name = route.name

        refusal = require_human_actor(route, ctx, observability=self._observability)
        if refusal is not None:
            self._record_mutation_audit(route, ctx, spec, refusal)
            return refusal

        directory = self._directory
        if (
            directory is None
            or "api_keys" not in directory.capabilities
            or missing_members(directory, ApiKeyDirectory)
        ):
            return self._error(
                route,
                ctx,
                code="service_unavailable",
                message="API keys are not available",
            )

        validation_error = self._validate_args(route, ctx, spec)
        if validation_error is not None:
            self._record_mutation_audit(route, ctx, spec, validation_error)
            return validation_error

        if name in ("api_keys_issue", "api_keys_revoke") and self._management_source is not None:
            try:
                target_subject = await self._management_target_subject(directory, name, spec)
            except UsersError:
                result = self._error(
                    route,
                    ctx,
                    code="service_unavailable",
                    message="users directory is unavailable",
                )
                self._record_mutation_audit(route, ctx, spec, result)
                return result
            admin_call = await resolve_admin_call(
                route,
                ctx,
                directory=directory,
                management_source=self._management_source,
                target_subject=target_subject,
            )
            if isinstance(admin_call, dict):
                self._record_mutation_audit(route, ctx, spec, admin_call)
                return admin_call
            mgmt_refusal = check_management_authority(
                route,
                ctx,
                call=admin_call,
                observability=self._observability,
            )
            if mgmt_refusal is not None:
                self._record_mutation_audit(route, ctx, spec, mgmt_refusal)
                return mgmt_refusal

        actor = ctx.verified_identity.subject
        try:
            if name == "api_keys_issue":
                issued = await directory.issue_api_key(
                    subject=str(spec["subject"]),
                    label=spec.get("label"),
                    expires_in_days=spec.get("expires_in_days"),
                    actor=actor,
                )
                payload = issued.record.to_dict()
                payload["key"] = issued.key
                result = self._done(
                    route,
                    ctx,
                    api_key=payload,
                    notice="Store this key now; it cannot be shown again.",
                )
            elif name == "api_keys_list":
                rows = await directory.list_api_keys(
                    subject=spec.get("subject"),
                    include_revoked=bool(spec.get("include_revoked", False)),
                )
                result = self._done(
                    route,
                    ctx,
                    api_keys=[row.to_dict() for row in rows],
                    total=len(rows),
                )
            else:
                assert name == "api_keys_revoke"
                record, _changed = await directory.revoke_api_key(
                    key_id=str(spec["key_id"]),
                    actor=actor,
                )
                extra: dict[str, Any] = {}
                if subject_type_of(record.subject) == "human":
                    if self._session_revoker is None:
                        extra["revoked_tokens"] = 0
                    else:
                        try:
                            extra[
                                "revoked_tokens"
                            ] = await self._session_revoker.revoke_api_key_sessions(
                                record.subject, record.key_id
                            )
                        except RedisError:
                            logger.warning(
                                "api key revoked but sessions not revoked: token store unavailable"
                            )
                            result = self._error(
                                route,
                                ctx,
                                code="service_unavailable",
                                message=(
                                    "key is revoked; sessions were not revoked. "
                                    "Call api_keys_revoke again to retry session revocation."
                                ),
                            )
                            self._record_mutation_audit(route, ctx, spec, result)
                            return result
                    if self._observability is not None:
                        self._observability.record_session_event(
                            action="key_sessions_revoked",
                            subject=record.subject,
                            client_id="",
                            revoked_tokens=extra.get("revoked_tokens"),
                            reason=record.key_id,
                        )
                result = self._done(route, ctx, api_key=record.to_dict(), **extra)
        except UsersError as exc:
            result = self._error(route, ctx, code=exc.code, message=str(exc))
            self._record_mutation_audit(route, ctx, spec, result)
            return result

        self._record_mutation_audit(route, ctx, spec, result)
        return result

    async def _management_target_subject(
        self,
        directory: ApiKeyDirectory,
        name: str,
        spec: dict[str, Any],
    ) -> str | None:
        if name == "api_keys_issue":
            return str(spec["subject"])
        assert name == "api_keys_revoke"
        rows = await directory.list_api_keys(subject=None, include_revoked=True)
        key_id = str(spec["key_id"])
        for row in rows:
            if row.key_id == key_id:
                return row.subject
        return None

    @staticmethod
    def _validate_args(
        route: Route, ctx: RouteContext, spec: dict[str, Any]
    ) -> dict[str, Any] | None:
        name = route.name

        def err(message: str) -> dict[str, Any]:
            return ApiKeysAdminAdapter._error(route, ctx, code="validation_error", message=message)

        if name == "api_keys_issue":
            if not spec.get("subject"):
                return err("subject is required")
            return None
        if name == "api_keys_list":
            return None
        if name == "api_keys_revoke":
            if not spec.get("key_id"):
                return err("key_id is required")
            return None
        return None

    def _record_mutation_audit(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
        result: dict[str, Any],
    ) -> None:
        if self._observability is None:
            return
        outcome = str(result.get("state", "error"))
        code = result.get("code") if outcome != "done" else None
        api_key = result.get("api_key") if isinstance(result.get("api_key"), dict) else None
        target_email = spec.get("subject")
        if target_email is None and api_key is not None:
            target_email = api_key.get("subject")
        key_id = spec.get("key_id")
        if key_id is None and api_key is not None:
            key_id = api_key.get("key_id")
        self._observability.record_users_mutation(
            operation=route.name,
            actor_email=ctx.verified_identity.subject,
            target_email=str(target_email) if target_email else None,
            outcome=outcome,
            code=str(code) if code is not None else None,
            task_id=ctx.task_id,
            actor_subject_type=ctx.verified_identity.subject_type,
            key_id=str(key_id) if key_id is not None else None,
        )
