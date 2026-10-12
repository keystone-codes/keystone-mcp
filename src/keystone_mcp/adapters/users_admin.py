"""Builtin users_* admin tools, dispatched through a ``UserDirectory``.

Works against whichever :class:`~keystone_mcp.user_directory.protocol.UserDirectory`
implementation the server was built with (the built-in database, an external
HTTP service, or a plugin) -- this adapter itself knows nothing about SQL or
HTTP. The acting administrator is always taken from the verified OAuth
identity, never from tool arguments.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from keystone_mcp.user_directory.errors import UsersError
from keystone_mcp.user_directory.protocol import UserDirectory, UserDirectoryAdmin
from keystone_mcp.user_directory.util import normalize_email
from keystone_mcp.users.roles import check_role_name, normalize_roles

if TYPE_CHECKING:
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route

# Returns the role names the active RBAC policy knows about, or ``None`` when
# no policy check should be performed (RBAC off). Raised exceptions (e.g.
# ``PolicyLoadError`` from an ``enforce`` deployment whose policy has not been
# loaded yet) are translated to ``service_unavailable``.
RoleSource = Callable[[], frozenset[str] | None]

# Tools whose role argument(s) are checked against the active RBAC policy
# before the directory is ever called (the directory only checks format).
_ROLE_CHECKED_TOOLS = frozenset({"users_add", "users_set_roles", "users_grant_role"})


class UsersAdminAdapter:
    """Dispatches ``users_*`` tool calls to a ``UserDirectory`` implementation."""

    def __init__(
        self,
        *,
        directory: UserDirectory | None = None,
        role_source: RoleSource | None = None,
        observability: RbacObservability | None = None,
    ) -> None:
        self._directory = directory
        self._role_source = role_source
        self._observability = observability

    @staticmethod
    def _error(
        route: Route,
        ctx: RouteContext,
        *,
        code: str,
        message: str,
    ) -> dict[str, Any]:
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

    @staticmethod
    def _error_message(exc: UsersError) -> str:
        # Fixed, caller-safe text for the two codes that can carry
        # implementation detail (a database error, a connection failure):
        # every other code's own message is already safe to show as-is.
        if exc.code == "service_unavailable":
            return "users directory is unavailable"
        if exc.code == "service_timeout":
            return "users service timed out"
        return str(exc)

    async def execute(
        self,
        route: Route,
        ctx: RouteContext,
        args: dict[str, Any],
        request: Any,
    ) -> dict[str, Any]:
        spec = request if isinstance(request, dict) else dict(args)
        name = route.name

        directory = self._directory
        if directory is None:
            result = self._error(
                route,
                ctx,
                code="service_unconfigured",
                message="users directory is not configured",
            )
            self._record_mutation_audit(route, ctx, spec, result)
            return result

        if name != "users_list" and not (
            isinstance(directory, UserDirectoryAdmin) and "admin" in directory.capabilities
        ):
            result = self._error(
                route,
                ctx,
                code="service_unconfigured",
                message=f"users directory {directory.name!r} does not support administration",
            )
            self._record_mutation_audit(route, ctx, spec, result)
            return result

        validation_error = self._validate_args(route, ctx, spec)
        if validation_error is not None:
            self._record_mutation_audit(route, ctx, spec, validation_error)
            return validation_error

        allowed_roles: frozenset[str] | None = None
        if name in _ROLE_CHECKED_TOOLS:
            try:
                allowed_roles = self._role_source() if self._role_source is not None else None
            except Exception:  # noqa: BLE001 — any failure means the policy is unusable
                result = self._error(
                    route,
                    ctx,
                    code="service_unavailable",
                    message="role catalog is not loaded",
                )
                self._record_mutation_audit(route, ctx, spec, result)
                return result

        actor_email = normalize_email(ctx.verified_identity.email)
        try:
            if name == "users_list":
                is_blocked = spec.get("is_blocked")
                role = spec.get("role")
                if role is not None:
                    role = check_role_name(str(role))
                rows = await directory.list_users(
                    is_blocked=is_blocked if is_blocked is not None else False,
                    role=role,
                    email_contains=spec.get("email_contains"),
                )
                result = self._done(
                    route, ctx, users=[row.to_dict() for row in rows], total=len(rows)
                )
                self._record_mutation_audit(route, ctx, spec, result)
                return result
            if name == "users_add":
                roles = normalize_roles(list(spec.get("roles") or []), allowed=allowed_roles)
                mutation = await directory.create_user(
                    email=str(spec["email"]),
                    full_name=str(spec["full_name"]),
                    roles=roles,
                    note=spec.get("note"),
                    actor=actor_email,
                )
            elif name == "users_update":
                mutation = await directory.update_user(
                    email=str(spec["email"]),
                    full_name=spec.get("full_name"),
                    note=spec.get("note"),
                    actor=actor_email,
                )
            elif name == "users_block":
                mutation = await directory.set_blocked(
                    email=str(spec["email"]), blocked=True, actor=actor_email
                )
            elif name == "users_unblock":
                mutation = await directory.set_blocked(
                    email=str(spec["email"]), blocked=False, actor=actor_email
                )
            elif name == "users_set_roles":
                roles = normalize_roles(list(spec["roles"]), allowed=allowed_roles)
                mutation = await directory.replace_roles(
                    email=str(spec["email"]), roles=roles, actor=actor_email
                )
            elif name == "users_grant_role":
                role = normalize_roles([str(spec["role"])], allowed=allowed_roles)[0]
                mutation = await directory.grant_role(
                    email=str(spec["email"]), role=role, actor=actor_email
                )
            else:
                assert name == "users_revoke_role"
                role = check_role_name(str(spec["role"]))
                mutation = await directory.revoke_role(
                    email=str(spec["email"]), role=role, actor=actor_email
                )
        except UsersError as exc:
            result = self._error(route, ctx, code=exc.code, message=self._error_message(exc))
            self._record_mutation_audit(route, ctx, spec, result)
            return result

        result = self._done(route, ctx, user=mutation.user.to_dict())
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
    def _validate_args(
        route: Route, ctx: RouteContext, spec: dict[str, Any]
    ) -> dict[str, Any] | None:
        name = route.name

        def err(message: str) -> dict[str, Any]:
            return UsersAdminAdapter._error(route, ctx, code="validation_error", message=message)

        def roles_type_error(roles: Any) -> dict[str, Any] | None:
            if roles is None:
                return None
            if not isinstance(roles, list) or not all(isinstance(item, str) for item in roles):
                return err("roles must be a list of strings")
            return None

        if name == "users_add":
            if not spec.get("email") or not spec.get("full_name"):
                return err("email and full_name are required")
            return roles_type_error(spec.get("roles"))
        if name == "users_update":
            if not spec.get("email"):
                return err("email is required")
            has_full_name = "full_name" in spec and spec["full_name"] is not None
            has_note = "note" in spec and spec["note"] is not None
            if not has_full_name and not has_note:
                return err("at least one of full_name or note is required")
            return None
        if name in ("users_block", "users_unblock"):
            if not spec.get("email"):
                return err("email is required")
            return None
        if name == "users_set_roles":
            email = spec.get("email")
            roles = spec.get("roles")
            if not email or roles is None:
                return err("email and roles are required")
            return roles_type_error(roles)
        if name in ("users_grant_role", "users_revoke_role"):
            email = spec.get("email")
            role = spec.get("role")
            if not email or not role:
                return err("email and role are required")
            if not isinstance(role, str):
                return err("role must be a string")
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
        user = result.get("user") if isinstance(result.get("user"), dict) else None
        target_email = spec.get("email")
        if target_email is None and user is not None:
            target_email = user.get("email")
        role = spec.get("role")
        role_label = str(role) if role is not None else None
        after_roles = tuple(user.get("roles") or ()) if user is not None else None
        if before_roles is None and user is not None:
            raw_before = user.get("roles_before") or user.get("previous_roles")
            if isinstance(raw_before, list):
                before_roles = tuple(str(item) for item in raw_before)
        blocked_after = user.get("is_blocked") if user is not None else None
        if blocked_before is None:
            if route.name == "users_block":
                blocked_before = False
                blocked_after = True if outcome == "done" else blocked_after
            elif route.name == "users_unblock":
                blocked_before = True
                blocked_after = False if outcome == "done" else blocked_after
        self._observability.record_users_mutation(
            operation=route.name,
            actor_email=ctx.verified_identity.email,
            target_email=str(target_email) if target_email else None,
            outcome=outcome,
            code=str(code) if code is not None else None,
            task_id=ctx.task_id,
            before_roles=before_roles,
            after_roles=after_roles,
            blocked_before=blocked_before,
            blocked_after=blocked_after,
            role=role_label,
        )
