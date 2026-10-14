"""Fake HTTP users directory service, for testing :class:`HttpUserDirectory`.

Implements the external directory's HTTP contract (see
``docs/user-directory.md``, "The HTTP directory contract") as a small
Starlette app over the built-in :class:`~keystone_mcp.users.store.UsersStore`
on SQLite, so :class:`~keystone_mcp.user_directory.http.HttpUserDirectory` can
be driven through ``httpx.ASGITransport`` exactly as it would drive a real
external service. Checks the Bearer token and ``X-Actor-Email`` header the
real contract requires.

Deliberately reports two error codes using the pre-0.5.0 service's own
vocabulary (``invalid_role``, ``user_already_exists``) rather than the
``users_*`` skill's (``validation_error``, ``conflict``): this is exactly
what the real external service still does, and
``tests/test_http_user_directory.py`` verifies ``HttpUserDirectory``
normalizes both onto the skill's codes (HTTP users error-code normalization).
"""

from __future__ import annotations

from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from keystone_mcp.user_directory.util import normalize_email
from keystone_mcp.users.errors import InvalidRoleError, UserAlreadyExistsError, UsersError
from keystone_mcp.users.store import UsersStore

ACTOR_EMAIL_HEADER = "X-Actor-Email"

_STATUS_FOR_CODE: dict[str, int] = {
    "user_not_found": 404,
    "conflict": 409,
    "validation_error": 422,
    "last_administrator": 409,
    "self_admin_mutation_forbidden": 409,
    "actor_email_required": 400,
    "service_unavailable": 503,
}

#: The legacy service's own codes for the two cases the skill renamed (S3).
_LEGACY_CODE_FOR: dict[type[UsersError], str] = {
    InvalidRoleError: "invalid_role",
    UserAlreadyExistsError: "user_already_exists",
}


def _user_payload(record: Any) -> dict[str, Any]:
    return record.to_dict()


def _mutation_payload(mutation: Any) -> dict[str, Any]:
    payload = _user_payload(mutation.user)
    payload["changed"] = mutation.changed
    payload["created"] = mutation.created
    return payload


def _error_response(exc: UsersError) -> JSONResponse:
    code = _LEGACY_CODE_FOR.get(type(exc), exc.code)
    status = _STATUS_FOR_CODE.get(exc.code, 500)
    return JSONResponse({"code": code, "detail": str(exc)}, status_code=status)


def build_fake_users_service(store: UsersStore, *, token: str = "test-service-token") -> Starlette:
    """Build the Starlette app; point an ``httpx.ASGITransport`` at it."""

    def _require_auth(request: Request) -> JSONResponse | None:
        if request.headers.get("authorization") != f"Bearer {token}":
            return JSONResponse({"code": "forbidden", "detail": "invalid token"}, status_code=403)
        return None

    def _require_actor(request: Request) -> tuple[str, JSONResponse | None]:
        actor = request.headers.get(ACTOR_EMAIL_HEADER, "")
        if not actor:
            return "", JSONResponse(
                {
                    "code": "actor_email_required",
                    "detail": f"{ACTOR_EMAIL_HEADER} is required",
                },
                status_code=400,
            )
        return normalize_email(actor), None

    async def resolve(request: Request) -> JSONResponse:
        if (denied := _require_auth(request)) is not None:
            return denied
        resolved = await store.resolve(normalize_email(request.query_params.get("email", "")))
        return JSONResponse(
            {
                "exists": resolved.exists,
                "roles": list(resolved.roles),
                "is_blocked": resolved.is_blocked,
            }
        )

    async def list_users(request: Request) -> JSONResponse:
        if (denied := _require_auth(request)) is not None:
            return denied
        raw_is_blocked = request.query_params.get("is_blocked")
        is_blocked = raw_is_blocked.lower() == "true" if raw_is_blocked is not None else None
        rows = await store.list_users(
            is_blocked=is_blocked,
            role=request.query_params.get("role") or None,
            email_contains=request.query_params.get("email_contains") or None,
        )
        return JSONResponse({"users": [_user_payload(row) for row in rows], "total": len(rows)})

    async def create_user(request: Request) -> JSONResponse:
        if (denied := _require_auth(request)) is not None:
            return denied
        actor, denied = _require_actor(request)
        if denied is not None:
            return denied
        body = await request.json()
        try:
            mutation = await store.create_user(
                email=str(body["email"]),
                full_name=str(body["full_name"]),
                roles=list(body.get("roles") or []),
                note=body.get("note"),
                created_by=actor,
                allowed_roles=None,
            )
        except UsersError as exc:
            return _error_response(exc)
        return JSONResponse(_mutation_payload(mutation))

    async def update_user(request: Request) -> JSONResponse:
        if (denied := _require_auth(request)) is not None:
            return denied
        _actor, denied = _require_actor(request)
        if denied is not None:
            return denied
        body = await request.json()
        try:
            mutation = await store.update_profile(
                email=request.path_params["email"],
                full_name=body.get("full_name"),
                note=body.get("note"),
            )
        except UsersError as exc:
            return _error_response(exc)
        return JSONResponse(_mutation_payload(mutation))

    async def block_user(request: Request) -> JSONResponse:
        if (denied := _require_auth(request)) is not None:
            return denied
        actor, denied = _require_actor(request)
        if denied is not None:
            return denied
        try:
            mutation = await store.set_blocked(
                email=request.path_params["email"], blocked=True, actor_email=actor
            )
        except UsersError as exc:
            return _error_response(exc)
        return JSONResponse(_mutation_payload(mutation))

    async def unblock_user(request: Request) -> JSONResponse:
        if (denied := _require_auth(request)) is not None:
            return denied
        actor, denied = _require_actor(request)
        if denied is not None:
            return denied
        try:
            mutation = await store.set_blocked(
                email=request.path_params["email"], blocked=False, actor_email=actor
            )
        except UsersError as exc:
            return _error_response(exc)
        return JSONResponse(_mutation_payload(mutation))

    async def replace_roles(request: Request) -> JSONResponse:
        if (denied := _require_auth(request)) is not None:
            return denied
        actor, denied = _require_actor(request)
        if denied is not None:
            return denied
        body = await request.json()
        try:
            mutation = await store.replace_roles(
                email=request.path_params["email"],
                roles=list(body.get("roles") or []),
                actor_email=actor,
                allowed_roles=None,
            )
        except UsersError as exc:
            return _error_response(exc)
        return JSONResponse(_mutation_payload(mutation))

    async def grant_role(request: Request) -> JSONResponse:
        if (denied := _require_auth(request)) is not None:
            return denied
        _actor, denied = _require_actor(request)
        if denied is not None:
            return denied
        try:
            mutation = await store.grant_role(
                email=request.path_params["email"],
                role=request.path_params["role"],
                allowed_roles=None,
            )
        except UsersError as exc:
            return _error_response(exc)
        return JSONResponse(_mutation_payload(mutation))

    async def revoke_role(request: Request) -> JSONResponse:
        if (denied := _require_auth(request)) is not None:
            return denied
        actor, denied = _require_actor(request)
        if denied is not None:
            return denied
        try:
            mutation = await store.revoke_role(
                email=request.path_params["email"],
                role=request.path_params["role"],
                actor_email=actor,
            )
        except UsersError as exc:
            return _error_response(exc)
        return JSONResponse(_mutation_payload(mutation))

    return Starlette(
        routes=[
            Route("/v1/users/resolve", resolve, methods=["GET"]),
            Route("/v1/users", list_users, methods=["GET"]),
            Route("/v1/users", create_user, methods=["POST"]),
            Route("/v1/users/{email}", update_user, methods=["PATCH"]),
            Route("/v1/users/{email}/block", block_user, methods=["POST"]),
            Route("/v1/users/{email}/unblock", unblock_user, methods=["POST"]),
            Route("/v1/users/{email}/roles", replace_roles, methods=["PUT"]),
            Route("/v1/users/{email}/roles/{role}", grant_role, methods=["POST"]),
            Route("/v1/users/{email}/roles/{role}", revoke_role, methods=["DELETE"]),
        ]
    )
