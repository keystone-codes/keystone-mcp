"""Builtin users_* admin tools.

By default (``KEYSTONE_MCP_USERS_BACKEND=local``) these tools write straight to
the built-in users directory (:mod:`keystone_mcp.users.store`). Set
``KEYSTONE_MCP_USERS_BACKEND=http`` to proxy each route to an external mcp-users
service instead (service authentication uses the server-held users service
token). Either way, the acting administrator is taken from the verified OAuth
identity, never from tool arguments.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

import httpx

from keystone_mcp.user_directory.util import normalize_email
from keystone_mcp.users.errors import UsersError, UsersStoreUnavailableError

if TYPE_CHECKING:
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route
    from keystone_mcp.users.store import UsersStore

ACTOR_EMAIL_HEADER = "X-Actor-Email"

_STATUS_CODES: dict[int, str] = {
    400: "bad_request",
    403: "forbidden",
    404: "user_not_found",
    409: "conflict",
    422: "validation_error",
}

# Returns the role names the active RBAC policy knows about, or ``None`` when
# no policy check should be performed (RBAC off). Raised exceptions (e.g.
# ``PolicyLoadError`` from an ``enforce`` deployment whose policy has not been
# loaded yet) are translated to ``service_unavailable`` by the local branch.
RoleSource = Callable[[], frozenset[str] | None]

# Tool names the local (built-in store) branch knows how to dispatch.
_LOCAL_TOOL_NAMES = frozenset(
    {
        "users_list",
        "users_add",
        "users_update",
        "users_block",
        "users_unblock",
        "users_set_roles",
        "users_grant_role",
        "users_revoke_role",
    }
)

# Tools whose role argument(s) are checked against the active RBAC policy.
_ROLE_CHECKED_TOOLS = frozenset({"users_add", "users_set_roles", "users_grant_role"})


class UsersAdminAdapter:
    """Dispatches ``users_*`` tool calls to the built-in store or mcp-users."""

    def __init__(
        self,
        client_factory: Any | None = None,
        *,
        observability: RbacObservability | None = None,
        users_store: UsersStore | None = None,
        role_source: RoleSource | None = None,
    ) -> None:
        self._client_factory = client_factory
        self._observability = observability
        self._users_store = users_store
        self._role_source = role_source

    def _client(self, ctx: RouteContext) -> httpx.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory(ctx)
        base_url = ctx.settings.users_service_url.rstrip("/")
        token = ctx.settings.users_service_token
        return httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(ctx.settings.users_service_timeout_seconds),
            headers={"Authorization": f"Bearer {token}"},
        )

    @staticmethod
    def _actor_headers(ctx: RouteContext) -> dict[str, str]:
        return {ACTOR_EMAIL_HEADER: normalize_email(ctx.verified_identity.email)}

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
    def _infer_code_from_message(status_code: int, message: str) -> str:
        lowered = message.lower()
        if "last active administrator" in lowered:
            return "last_administrator"
        if "self-block" in lowered or "own administrator access" in lowered:
            return "self_admin_mutation_forbidden"
        if "x-actor-email" in lowered and "required" in lowered:
            return "actor_email_required"
        return _STATUS_CODES.get(status_code, "service_error")

    @classmethod
    def _parse_service_error(cls, response: httpx.Response) -> tuple[str, str]:
        try:
            body = response.json()
        except ValueError:
            return (
                _STATUS_CODES.get(response.status_code, "service_error"),
                "users service request failed",
            )
        if not isinstance(body, dict):
            return (
                _STATUS_CODES.get(response.status_code, "service_error"),
                "users service request failed",
            )

        top_level_code = body.get("code")
        detail = body.get("detail")
        if isinstance(detail, dict):
            code = str(
                detail.get("code")
                or top_level_code
                or _STATUS_CODES.get(response.status_code, "service_error")
            )
            message = str(detail.get("detail") or detail.get("message") or "request failed")
            return code, message
        if isinstance(detail, list):
            return "validation_error", "request validation failed"
        if isinstance(detail, str):
            if top_level_code:
                return str(top_level_code), detail
            return cls._infer_code_from_message(response.status_code, detail), detail
        message = str(body.get("message") or "users service request failed")
        code = str(top_level_code or _STATUS_CODES.get(response.status_code, "service_error"))
        return code, message

    def _service_unconfigured(self, route: Route, ctx: RouteContext) -> dict[str, Any] | None:
        if (
            not ctx.settings.users_service_url.strip()
            or not ctx.settings.users_service_token.strip()
        ):
            return self._error(
                route,
                ctx,
                code="service_unconfigured",
                message="users directory is not configured",
            )
        return None

    @staticmethod
    def _email_path(email: str) -> str:
        return quote(normalize_email(email), safe="")

    async def execute(
        self,
        route: Route,
        ctx: RouteContext,
        args: dict[str, Any],
        request: Any,
    ) -> dict[str, Any]:
        spec = request if isinstance(request, dict) else dict(args)
        if ctx.settings.users_backend == "local":
            return await self._execute_local(route, ctx, spec)
        unconfigured = self._service_unconfigured(route, ctx)
        if unconfigured is not None:
            self._record_mutation_audit(route, ctx, spec, unconfigured)
            return unconfigured

        client = self._client(ctx)
        try:
            result = await self._dispatch(route, ctx, spec, client)
            self._record_mutation_audit(route, ctx, spec, result)
            return result
        except httpx.TimeoutException:
            result = self._error(
                route, ctx, code="service_timeout", message="users service timed out"
            )
            self._record_mutation_audit(route, ctx, spec, result)
            return result
        except httpx.HTTPError:
            result = self._error(
                route,
                ctx,
                code="service_unavailable",
                message="users service is unavailable",
            )
            self._record_mutation_audit(route, ctx, spec, result)
            return result
        finally:
            await client.aclose()

    async def _execute_local(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
    ) -> dict[str, Any]:
        store = self._users_store
        if store is None:
            result = self._error(
                route,
                ctx,
                code="service_unconfigured",
                message="users directory is not configured",
            )
            self._record_mutation_audit(route, ctx, spec, result)
            return result

        name = route.name
        if name not in _LOCAL_TOOL_NAMES:
            result = self._error(
                route, ctx, code="unsupported_operation", message="unknown users admin tool"
            )
            self._record_mutation_audit(route, ctx, spec, result)
            return result

        validation_error = self._validate_local_args(route, ctx, spec)
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
                rows = await store.list_users(
                    is_blocked=is_blocked if is_blocked is not None else False,
                    role=spec.get("role"),
                    email_contains=spec.get("email_contains"),
                )
                result = self._done(
                    route, ctx, users=[row.to_dict() for row in rows], total=len(rows)
                )
                self._record_mutation_audit(route, ctx, spec, result)
                return result
            if name == "users_add":
                mutation = await store.create_user(
                    email=str(spec["email"]),
                    full_name=str(spec["full_name"]),
                    roles=list(spec.get("roles") or []),
                    note=spec.get("note"),
                    created_by=actor_email,
                    allowed_roles=allowed_roles,
                )
            elif name == "users_update":
                mutation = await store.update_profile(
                    email=str(spec["email"]),
                    full_name=spec.get("full_name"),
                    note=spec.get("note"),
                )
            elif name == "users_block":
                mutation = await store.set_blocked(
                    email=str(spec["email"]), blocked=True, actor_email=actor_email
                )
            elif name == "users_unblock":
                mutation = await store.set_blocked(
                    email=str(spec["email"]), blocked=False, actor_email=actor_email
                )
            elif name == "users_set_roles":
                mutation = await store.replace_roles(
                    email=str(spec["email"]),
                    roles=list(spec["roles"]),
                    actor_email=actor_email,
                    allowed_roles=allowed_roles,
                )
            elif name == "users_grant_role":
                mutation = await store.grant_role(
                    email=str(spec["email"]),
                    role=str(spec["role"]),
                    allowed_roles=allowed_roles,
                )
            else:
                assert name == "users_revoke_role"
                mutation = await store.revoke_role(
                    email=str(spec["email"]), role=str(spec["role"]), actor_email=actor_email
                )
        except UsersStoreUnavailableError:
            result = self._error(
                route,
                ctx,
                code="service_unavailable",
                message="users directory is unavailable",
            )
            self._record_mutation_audit(route, ctx, spec, result)
            return result
        except UsersError as exc:
            result = self._error(route, ctx, code=exc.code, message=str(exc))
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
    def _validate_local_args(
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

    async def _dispatch(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
        client: httpx.AsyncClient,
    ) -> dict[str, Any]:
        name = route.name
        if name == "users_list":
            return await self._list_users(route, ctx, spec, client)
        if name == "users_add":
            return await self._create_user(route, ctx, spec, client)
        if name == "users_update":
            return await self._update_user(route, ctx, spec, client)
        if name == "users_block":
            return await self._block_user(route, ctx, spec, client)
        if name == "users_unblock":
            return await self._unblock_user(route, ctx, spec, client)
        if name == "users_set_roles":
            return await self._set_roles(route, ctx, spec, client)
        if name == "users_grant_role":
            return await self._grant_role(route, ctx, spec, client)
        if name == "users_revoke_role":
            return await self._revoke_role(route, ctx, spec, client)
        return self._error(
            route, ctx, code="unsupported_operation", message="unknown users admin tool"
        )

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

    async def _handle_response(
        self,
        route: Route,
        ctx: RouteContext,
        response: httpx.Response,
        *,
        list_payload: bool = False,
    ) -> dict[str, Any]:
        if response.is_success:
            body = response.json() if response.content else {}
            if list_payload:
                return self._done(
                    route, ctx, users=body.get("users", []), total=body.get("total", 0)
                )
            return self._done(route, ctx, user=body)
        code, message = self._parse_service_error(response)
        return self._error(route, ctx, code=code, message=message)

    async def _list_users(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
        client: httpx.AsyncClient,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if "is_blocked" in spec and spec["is_blocked"] is not None:
            params["is_blocked"] = spec["is_blocked"]
        else:
            params["is_blocked"] = False
        role = spec.get("role")
        if role:
            params["role"] = role
        email_contains = spec.get("email_contains")
        if email_contains:
            params["email_contains"] = email_contains
        response = await client.get("/v1/users", params=params)
        return await self._handle_response(route, ctx, response, list_payload=True)

    async def _create_user(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
        client: httpx.AsyncClient,
    ) -> dict[str, Any]:
        email = spec.get("email")
        full_name = spec.get("full_name")
        if not email or not full_name:
            return self._error(
                route, ctx, code="validation_error", message="email and full_name are required"
            )
        payload = {
            "email": normalize_email(str(email)),
            "full_name": str(full_name),
            "roles": list(spec.get("roles") or []),
            "created_by": normalize_email(ctx.verified_identity.email),
        }
        note = spec.get("note")
        if note is not None:
            payload["note"] = note
        response = await client.post("/v1/users", json=payload, headers=self._actor_headers(ctx))
        return await self._handle_response(route, ctx, response)

    async def _update_user(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
        client: httpx.AsyncClient,
    ) -> dict[str, Any]:
        email = spec.get("email")
        if not email:
            return self._error(route, ctx, code="validation_error", message="email is required")
        payload: dict[str, Any] = {}
        if "full_name" in spec and spec["full_name"] is not None:
            payload["full_name"] = spec["full_name"]
        if "note" in spec and spec["note"] is not None:
            payload["note"] = spec["note"]
        if not payload:
            return self._error(
                route,
                ctx,
                code="validation_error",
                message="at least one of full_name or note is required",
            )
        response = await client.patch(
            f"/v1/users/{self._email_path(str(email))}",
            json=payload,
            headers=self._actor_headers(ctx),
        )
        return await self._handle_response(route, ctx, response)

    async def _block_user(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
        client: httpx.AsyncClient,
    ) -> dict[str, Any]:
        email = spec.get("email")
        if not email:
            return self._error(route, ctx, code="validation_error", message="email is required")
        response = await client.post(
            f"/v1/users/{self._email_path(str(email))}/block",
            headers=self._actor_headers(ctx),
        )
        return await self._handle_response(route, ctx, response)

    async def _unblock_user(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
        client: httpx.AsyncClient,
    ) -> dict[str, Any]:
        email = spec.get("email")
        if not email:
            return self._error(route, ctx, code="validation_error", message="email is required")
        response = await client.post(
            f"/v1/users/{self._email_path(str(email))}/unblock",
            headers=self._actor_headers(ctx),
        )
        return await self._handle_response(route, ctx, response)

    async def _set_roles(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
        client: httpx.AsyncClient,
    ) -> dict[str, Any]:
        email = spec.get("email")
        roles = spec.get("roles")
        if not email or roles is None:
            return self._error(
                route, ctx, code="validation_error", message="email and roles are required"
            )
        response = await client.put(
            f"/v1/users/{self._email_path(str(email))}/roles",
            json={"roles": list(roles)},
            headers=self._actor_headers(ctx),
        )
        return await self._handle_response(route, ctx, response)

    async def _grant_role(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
        client: httpx.AsyncClient,
    ) -> dict[str, Any]:
        email = spec.get("email")
        role = spec.get("role")
        if not email or not role:
            return self._error(
                route, ctx, code="validation_error", message="email and role are required"
            )
        response = await client.post(
            f"/v1/users/{self._email_path(str(email))}/roles/{quote(str(role), safe='')}",
            headers=self._actor_headers(ctx),
        )
        return await self._handle_response(route, ctx, response)

    async def _revoke_role(
        self,
        route: Route,
        ctx: RouteContext,
        spec: dict[str, Any],
        client: httpx.AsyncClient,
    ) -> dict[str, Any]:
        email = spec.get("email")
        role = spec.get("role")
        if not email or not role:
            return self._error(
                route, ctx, code="validation_error", message="email and role are required"
            )
        response = await client.delete(
            f"/v1/users/{self._email_path(str(email))}/roles/{quote(str(role), safe='')}",
            headers=self._actor_headers(ctx),
        )
        return await self._handle_response(route, ctx, response)
