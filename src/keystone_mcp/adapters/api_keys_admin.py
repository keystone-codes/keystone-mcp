"""Builtin api_keys_* admin tools."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from keystone_mcp.adapters.guards import require_human_actor
from keystone_mcp.user_directory.errors import UsersError
from keystone_mcp.user_directory.protocol import ApiKeyDirectory, UserDirectory

if TYPE_CHECKING:
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route


class ApiKeysAdminAdapter:
    def __init__(
        self,
        *,
        directory: UserDirectory | None = None,
        observability: RbacObservability | None = None,
    ) -> None:
        self._directory = directory
        self._observability = observability

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
        if directory is None or not isinstance(directory, ApiKeyDirectory):
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
                result = self._done(route, ctx, api_key=record.to_dict())
        except UsersError as exc:
            result = self._error(route, ctx, code=exc.code, message=str(exc))
            self._record_mutation_audit(route, ctx, spec, result)
            return result

        self._record_mutation_audit(route, ctx, spec, result)
        return result

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
