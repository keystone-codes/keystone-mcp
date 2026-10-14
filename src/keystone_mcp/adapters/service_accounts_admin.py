"""Builtin service_accounts_* admin tools."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from keystone_mcp.adapters.guards import check_management_authority, require_human_actor
from keystone_mcp.plugins import missing_members
from keystone_mcp.user_directory.errors import UsersError
from keystone_mcp.user_directory.protocol import ServiceAccountDirectory, UserDirectory
from keystone_mcp.user_directory.types import service_subject
from keystone_mcp.users.roles import normalize_roles

if TYPE_CHECKING:
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.rbac.management import ManagementSource
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route

RoleSource = Callable[[], frozenset[str] | None]

_ROLE_CHECKED_TOOLS = frozenset({"service_accounts_add", "service_accounts_update"})


class ServiceAccountsAdminAdapter:
    def __init__(
        self,
        *,
        directory: UserDirectory | None = None,
        role_source: RoleSource | None = None,
        management_source: ManagementSource | None = None,
        observability: RbacObservability | None = None,
    ) -> None:
        self._directory = directory
        self._role_source = role_source
        self._management_source = management_source
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
        if (
            directory is None
            or "service_accounts" not in directory.capabilities
            or missing_members(directory, ServiceAccountDirectory)
        ):
            return self._error(
                route,
                ctx,
                code="service_unavailable",
                message="service accounts are not available",
            )

        validation_error = self._validate_args(route, ctx, spec)
        if validation_error is not None:
            self._record_mutation_audit(route, ctx, spec, validation_error)
            return validation_error

        allowed_roles: frozenset[str] | None = None
        if name in _ROLE_CHECKED_TOOLS:
            try:
                allowed_roles = self._role_source() if self._role_source is not None else None
            except Exception:  # noqa: BLE001
                result = self._error(
                    route,
                    ctx,
                    code="service_unavailable",
                    message="role catalog is not loaded",
                )
                self._record_mutation_audit(route, ctx, spec, result)
                return result

        if name != "service_accounts_list":
            target_subject, roles_touched = self._management_targets(name, spec)
            mgmt_refusal = await check_management_authority(
                route,
                ctx,
                directory=directory,
                management_source=self._management_source,
                observability=self._observability,
                target_subject=target_subject,
                roles_touched=roles_touched,
            )
            if mgmt_refusal is not None:
                self._record_mutation_audit(route, ctx, spec, mgmt_refusal)
                return mgmt_refusal

        actor = ctx.verified_identity.subject
        try:
            if name == "service_accounts_list":
                is_blocked = spec.get("is_blocked")
                rows = await directory.list_service_accounts(
                    is_blocked=is_blocked if is_blocked is not None else False,
                )
                result = self._done(
                    route,
                    ctx,
                    service_accounts=[row.to_dict() for row in rows],
                    total=len(rows),
                )
                self._record_mutation_audit(route, ctx, spec, result)
                return result
            if name == "service_accounts_add":
                roles = normalize_roles(list(spec.get("roles") or []), allowed=allowed_roles)
                mutation = await directory.create_service_account(
                    name=str(spec["name"]),
                    description=spec.get("description"),
                    roles=roles,
                    actor=actor,
                )
            else:
                assert name == "service_accounts_update"
                roles_arg = spec.get("roles")
                roles = (
                    normalize_roles(list(roles_arg), allowed=allowed_roles)
                    if roles_arg is not None
                    else None
                )
                mutation = await directory.update_service_account(
                    name=str(spec["name"]),
                    description=spec.get("description"),
                    roles=roles,
                    is_blocked=spec.get("is_blocked"),
                    actor=actor,
                )
        except UsersError as exc:
            result = self._error(route, ctx, code=exc.code, message=str(exc))
            self._record_mutation_audit(route, ctx, spec, result)
            return result

        result = self._done(route, ctx, service_account=mutation.account.to_dict())
        self._record_mutation_audit(
            route,
            ctx,
            spec,
            result,
            before_roles=mutation.roles_before,
            blocked_before=mutation.blocked_before,
        )
        return result

    @staticmethod
    def _management_targets(name: str, spec: dict[str, Any]) -> tuple[str | None, list[str]]:
        if name == "service_accounts_add":
            roles = spec.get("roles")
            return None, list(roles) if isinstance(roles, list) else []
        if name == "service_accounts_update":
            roles = spec.get("roles")
            touched = list(roles) if isinstance(roles, list) else []
            return service_subject(str(spec["name"])), touched
        return None, []

    @staticmethod
    def _validate_args(
        route: Route, ctx: RouteContext, spec: dict[str, Any]
    ) -> dict[str, Any] | None:
        name = route.name

        def err(message: str) -> dict[str, Any]:
            return ServiceAccountsAdminAdapter._error(
                route, ctx, code="validation_error", message=message
            )

        if name == "service_accounts_add":
            if not spec.get("name") or not isinstance(spec["name"], str):
                return err("name is required")
            roles = spec.get("roles")
            if roles is not None and (
                not isinstance(roles, list) or not all(isinstance(item, str) for item in roles)
            ):
                return err("roles must be a list of strings")
            return None
        if name == "service_accounts_update":
            if not spec.get("name") or not isinstance(spec["name"], str):
                return err("name is required")
            has_description = "description" in spec and spec["description"] is not None
            has_roles = "roles" in spec and spec["roles"] is not None
            has_blocked = "is_blocked" in spec and spec["is_blocked"] is not None
            if not has_description and not has_roles and not has_blocked:
                return err("at least one of description, roles or is_blocked is required")
            roles = spec.get("roles")
            if roles is not None and (
                not isinstance(roles, list) or not all(isinstance(item, str) for item in roles)
            ):
                return err("roles must be a list of strings")
            return None
        return None

    def _record_mutation_audit(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
        result: dict[str, Any],
        *,
        before_roles: tuple[str, ...] | None = None,
        blocked_before: bool | None = None,
    ) -> None:
        if self._observability is None:
            return
        outcome = str(result.get("state", "error"))
        code = result.get("code") if outcome != "done" else None
        account = (
            result.get("service_account")
            if isinstance(result.get("service_account"), dict)
            else None
        )
        target_name = spec.get("name")
        target_email = service_subject(str(target_name)) if target_name else None
        if target_email is None and account is not None:
            target_email = account.get("subject")
        after_roles = tuple(account.get("roles") or ()) if account is not None else None
        blocked_after = account.get("is_blocked") if account is not None else None
        self._observability.record_users_mutation(
            operation=route.name,
            actor_email=ctx.verified_identity.subject,
            target_email=str(target_email) if target_email else None,
            outcome=outcome,
            code=str(code) if code is not None else None,
            task_id=ctx.task_id,
            before_roles=before_roles,
            after_roles=after_roles,
            blocked_before=blocked_before,
            blocked_after=blocked_after,
            actor_subject_type=ctx.verified_identity.subject_type,
        )
