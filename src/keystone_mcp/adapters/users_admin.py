"""Builtin users_* admin tools, dispatched through a ``UserDirectory``.

Works against whichever :class:`~keystone_mcp.user_directory.protocol.UserDirectory`
implementation the server was built with (the built-in database, an external
HTTP service, or a plugin) -- this adapter itself knows nothing about SQL or
HTTP. The acting administrator is always taken from the verified OAuth
identity, never from tool arguments.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from redis.exceptions import RedisError

from keystone_mcp.adapters import users_delete_support as delete_support
from keystone_mcp.adapters.guards import (
    AdminCall,
    CatalogNamesSource,
    check_delegation,
    check_management_authority,
    check_self_demotion,
    delegation_roles_granted,
    require_human_actor,
    resolve_admin_call,
)
from keystone_mcp.plugins import missing_members
from keystone_mcp.user_directory.errors import UsersError
from keystone_mcp.user_directory.protocol import (
    UserDeletionDirectory,
    UserDirectory,
    UserDirectoryAdmin,
)
from keystone_mcp.user_directory.util import normalize_email
from keystone_mcp.users.roles import check_role_name, normalize_roles

if TYPE_CHECKING:
    from keystone_mcp.auth.login_pending_store import LoginPendingStore
    from keystone_mcp.auth.oauth_store import OAuthStore
    from keystone_mcp.auth.sessions import SessionRevoker
    from keystone_mcp.config import UsersDeleteMode
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.rbac.management import ManagementSource
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route

logger = logging.getLogger(__name__)

# Returns the role names the active RBAC policy knows about, or ``None`` when
# no policy check should be performed (RBAC off). Raised exceptions (e.g.
# ``PolicyLoadError`` from an ``enforce`` deployment whose policy has not been
# loaded yet) are translated to ``service_unavailable``.
RoleSource = Callable[[], frozenset[str] | None]

# Tools whose role argument(s) are checked against the active RBAC policy
# before the directory is ever called (the directory only checks format).
_ROLE_CHECKED_TOOLS = frozenset({"users_add", "users_set_roles", "users_grant_role"})

USERS_ADMIN_ERROR_CODES: frozenset[str] = frozenset(
    {
        "actor_email_required",
        "bad_request",
        "conflict",
        "forbidden",
        "last_administrator",
        "self_admin_mutation_forbidden",
        "service_error",
        "service_timeout",
        "service_unavailable",
        "service_unconfigured",
        "user_not_found",
        "validation_error",
    }
)


class UsersAdminAdapter:
    """Dispatches ``users_*`` tool calls to a ``UserDirectory`` implementation."""

    def __init__(
        self,
        *,
        directory: UserDirectory | None = None,
        role_source: RoleSource | None = None,
        management_source: ManagementSource | None = None,
        catalog_names_source: CatalogNamesSource | None = None,
        observability: RbacObservability | None = None,
        session_revoker: SessionRevoker | None = None,
        login_pending_store: LoginPendingStore | None = None,
        oauth_store: OAuthStore | None = None,
        users_delete_mode: UsersDeleteMode = "anonymize",
        rbac_audit_subject_salt: str = "",
    ) -> None:
        self._directory = directory
        self._role_source = role_source
        self._management_source = management_source
        self._catalog_names_source = catalog_names_source
        self._observability = observability
        self._session_revoker = session_revoker
        self._login_pending_store = login_pending_store
        self._oauth_store = oauth_store
        self._users_delete_mode = users_delete_mode
        self._rbac_audit_subject_salt = rbac_audit_subject_salt

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

        refusal = require_human_actor(route, ctx, observability=self._observability)
        if refusal is not None:
            self._record_mutation_audit(route, ctx, spec, refusal)
            return refusal

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

        if name == "users_delete":
            return await self._execute_delete(route, ctx, spec)

        if name != "users_list" and not (
            "admin" in directory.capabilities and not missing_members(directory, UserDirectoryAdmin)
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

        admin_call: AdminCall | dict[str, Any] | None = None
        needs_admin_context = name != "users_list" and (
            self._management_source is not None
            or (name in _ROLE_CHECKED_TOOLS and self._catalog_names_source is not None)
        )
        if needs_admin_context:
            target_subject, roles_touched = self._management_targets(name, spec)
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
            if self._management_source is not None:
                mgmt_refusal = check_management_authority(
                    route,
                    ctx,
                    call=admin_call,
                    observability=self._observability,
                    roles_touched=roles_touched,
                )
                if mgmt_refusal is not None:
                    self._record_mutation_audit(route, ctx, spec, mgmt_refusal)
                    return mgmt_refusal
            if name in _ROLE_CHECKED_TOOLS and self._catalog_names_source is not None:
                roles_granted = delegation_roles_granted(
                    name,
                    spec,
                    target_roles=admin_call.target_roles,
                )
                delegation_refusal = check_delegation(
                    route,
                    ctx,
                    call=admin_call,
                    roles_granted=roles_granted,
                    catalog_names_source=self._catalog_names_source,
                    observability=self._observability,
                )
                if delegation_refusal is not None:
                    self._record_mutation_audit(route, ctx, spec, delegation_refusal)
                    return delegation_refusal
            if isinstance(admin_call, AdminCall) and name in (
                "users_block",
                "users_set_roles",
                "users_revoke_role",
            ):
                self_refusal = check_self_demotion(route, ctx, admin_call=admin_call, spec=spec)
                if self_refusal is not None:
                    self._record_mutation_audit(route, ctx, spec, self_refusal)
                    return self_refusal

        if name == "users_logout":
            return await self._execute_logout(route, ctx, spec)

        actor_email = ctx.verified_identity.subject
        if ctx.verified_identity.email is not None:
            actor_email = normalize_email(actor_email)
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

        extra: dict[str, Any] = {}
        if name == "users_block":
            if self._session_revoker is None:
                extra["revoked_tokens"] = 0
            else:
                try:
                    extra["revoked_tokens"] = await self._session_revoker.revoke_subject(
                        str(spec["email"])
                    )
                except RedisError:
                    logger.warning("user blocked but sessions not revoked: token store unavailable")
                    result = self._error(
                        route,
                        ctx,
                        code="service_unavailable",
                        message=(
                            "user is blocked; sessions were not revoked. "
                            "Call users_block again to retry session revocation."
                        ),
                    )
                    self._record_mutation_audit(
                        route,
                        ctx,
                        spec,
                        result,
                        before_roles=mutation.roles_before,
                        blocked_before=mutation.blocked_before,
                    )
                    return result
        result = self._done(route, ctx, user=mutation.user.to_dict(), **extra)
        self._record_mutation_audit(
            route,
            ctx,
            spec,
            result,
            before_roles=mutation.roles_before,
            blocked_before=mutation.blocked_before,
        )
        return result

    async def _execute_logout(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
    ) -> dict[str, Any]:
        email = normalize_email(str(spec["email"]))
        if self._session_revoker is None:
            result = self._done(route, ctx, email=email, revoked_tokens=0)
            self._record_mutation_audit(route, ctx, spec, result, operation_override="logout")
            return result
        try:
            revoked = await self._session_revoker.revoke_subject(email)
        except RedisError:
            result = self._error(
                route,
                ctx,
                code="service_unavailable",
                message="session store is unavailable",
            )
            self._record_mutation_audit(route, ctx, spec, result, operation_override="logout")
            return result
        result = self._done(route, ctx, email=email, revoked_tokens=revoked)
        self._record_mutation_audit(route, ctx, spec, result, operation_override="logout")
        return result

    async def _execute_delete(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
    ) -> dict[str, Any]:
        directory = self._directory
        assert directory is not None
        if not delete_support.directory_supports_delete(directory):
            result = self._error(
                route,
                ctx,
                code="service_unconfigured",
                message=f"users directory {directory.name!r} does not support deletion",
            )
            self._record_mutation_audit(
                route, ctx, spec, result, operation_override="delete_requested"
            )
            return result
        if self._login_pending_store is None:
            result = self._error(
                route,
                ctx,
                code="service_unconfigured",
                message="users delete confirmation store is not configured",
            )
            self._record_mutation_audit(
                route, ctx, spec, result, operation_override="delete_requested"
            )
            return result

        email_raw = spec.get("email")
        if not email_raw:
            result = self._error(
                route,
                ctx,
                code="validation_error",
                message="email is required",
            )
            self._record_mutation_audit(
                route, ctx, spec, result, operation_override="delete_requested"
            )
            return result
        target_email = normalize_email(str(email_raw))
        actor_email = normalize_email(ctx.verified_identity.subject)

        refusal_code, _target_roles = await delete_support.check_delete_preconditions(
            route,
            ctx,
            directory=directory,
            management_source=self._management_source,
            target_email=target_email,
        )
        if refusal_code == "forbidden":
            result = self._error(
                route,
                ctx,
                code="forbidden",
                message=(
                    "only a full administrator may delete a person from the users directory"
                ),
            )
            self._record_mutation_audit(
                route, ctx, spec, result, operation_override="delete_requested"
            )
            return result
        if refusal_code == "self_admin_mutation_forbidden":
            result = self._error(
                route,
                ctx,
                code="self_admin_mutation_forbidden",
                message="you cannot delete your own account",
            )
            self._record_mutation_audit(
                route, ctx, spec, result, operation_override="delete_requested"
            )
            return result
        if refusal_code == "last_administrator":
            result = self._error(
                route,
                ctx,
                code="last_administrator",
                message="Cannot remove or block the last active administrator",
            )
            self._record_mutation_audit(
                route, ctx, spec, result, operation_override="delete_requested"
            )
            return result
        if refusal_code is not None:
            result = self._error(
                route,
                ctx,
                code=refusal_code,
                message="users directory is unavailable",
            )
            self._record_mutation_audit(
                route, ctx, spec, result, operation_override="delete_requested"
            )
            return result

        mode = self._users_delete_mode
        confirmation = spec.get("confirmation")
        if not confirmation:
            try:
                summary = await delete_support.person_summary(
                    directory,
                    self._oauth_store,
                    email=target_email,
                )
            except UsersError as exc:
                result = self._error(
                    route, ctx, code=exc.code, message=self._error_message(exc)
                )
                self._record_mutation_audit(
                    route, ctx, spec, result, operation_override="delete_requested"
                )
                return result
            code = delete_support._issue_confirmation_code()
            await delete_support.store_confirmation(
                self._login_pending_store,
                code=code,
                actor_email=actor_email,
                target_email=target_email,
                mode=mode,
            )
            result = {
                "state": "confirmation_required",
                "tool": route.name,
                "task_id": ctx.task_id,
                "email": target_email,
                "mode": mode,
                "summary": {**summary, "mode": mode},
                "confirmation": code,
                "expires_in": delete_support._CONFIRM_TTL_SECONDS,
            }
            self._record_mutation_audit(
                route, ctx, spec, result, operation_override="delete_requested"
            )
            return result

        if not await delete_support.consume_confirmation(
            self._login_pending_store,
            code=str(confirmation),
            actor_email=actor_email,
            target_email=target_email,
            mode=mode,
        ):
            result = self._error(
                route,
                ctx,
                code="validation_error",
                message=delete_support._INVALID_CONFIRMATION,
            )
            self._record_mutation_audit(
                route, ctx, spec, result, operation_override="delete_requested"
            )
            return result

        pseudonym = delete_support.build_pseudonym(
            target_email, salt=self._rbac_audit_subject_salt
        )
        deleter = directory  # typed as UserDeletionDirectory after capability check
        assert isinstance(deleter, UserDeletionDirectory)
        try:
            deletion = await deleter.delete_user(
                email=target_email,
                actor=actor_email,
                mode=mode,
                pseudonym=pseudonym,
            )
        except UsersError as exc:
            result = self._error(route, ctx, code=exc.code, message=self._error_message(exc))
            self._record_mutation_audit(route, ctx, spec, result, operation_override="delete")
            return result

        revoked_tokens = 0
        if self._session_revoker is None:
            revoked_tokens = 0
        else:
            try:
                revoked_tokens = await self._session_revoker.revoke_subject(target_email)
            except RedisError:
                result = self._error(
                    route,
                    ctx,
                    code="service_unavailable",
                    message=(
                        "user deleted, but sessions were not revoked; "
                        "call users_logout for this email"
                    ),
                )
                self._record_mutation_audit(
                    route,
                    ctx,
                    spec,
                    result,
                    operation_override="delete",
                    before_roles=deletion.roles_before,
                )
                return result

        payload: dict[str, Any] = {
            "email": target_email,
            "mode": deletion.mode,
            "pseudonym": deletion.pseudonym,
            "revoked_tokens": revoked_tokens,
            "api_keys_revoked": deletion.api_keys_revoked,
        }
        if not self._rbac_audit_subject_salt.strip():
            payload["warning"] = (
                "KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT is empty: the pseudonym can be "
                "matched against known e-mail addresses"
            )
        result = self._done(route, ctx, **payload)
        self._record_mutation_audit(
            route,
            ctx,
            spec,
            result,
            operation_override="delete",
            before_roles=deletion.roles_before,
        )
        return result

    @staticmethod
    def _management_targets(name: str, spec: dict[str, Any]) -> tuple[str | None, list[str]]:
        if name == "users_add":
            roles = spec.get("roles")
            return None, list(roles) if isinstance(roles, list) else []
        if name in ("users_update", "users_block", "users_unblock", "users_logout"):
            return normalize_email(str(spec["email"])), []
        if name == "users_set_roles":
            return normalize_email(str(spec["email"])), list(spec.get("roles") or [])
        if name in ("users_grant_role", "users_revoke_role"):
            return normalize_email(str(spec["email"])), [str(spec["role"])]
        return None, []

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
        if name in ("users_block", "users_unblock", "users_logout", "users_delete"):
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
        operation_override: str | None = None,
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
            operation=operation_override or route.name,
            actor_email=ctx.verified_identity.subject,
            actor_subject_type=ctx.verified_identity.subject_type,
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
