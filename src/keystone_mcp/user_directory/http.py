"""HTTP users directory: reads and administers an external HTTP users directory service.

Used when ``KEYSTONE_MCP_USERS_BACKEND=http``. The read path
(``resolve_user``, ``ping``) raises
:class:`~keystone_mcp.user_directory.errors.UserDirectoryUnavailableError`
(codes ``catalog_unavailable``, ``catalog_timeout``), consumed by
:class:`~keystone_mcp.user_directory.resolver.CachedUserDirectoryResolver`.
The admin path (``list_users`` and every
:class:`~keystone_mcp.user_directory.protocol.UserDirectoryAdmin` method)
raises the ``users_*`` skill's own error vocabulary instead (see
:mod:`keystone_mcp.user_directory.errors`), normalizing whatever the service
reports: ``invalid_role`` becomes ``validation_error``, ``user_already_exists``
becomes ``conflict`` (decision S3) -- every other code passes through
unchanged. See ``docs/user-directory.md`` ("The HTTP directory contract") for
the full wire contract (paths, bodies, headers, revision).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import quote

import httpx

from keystone_mcp.observability.metrics import count_directory_response_issue
from keystone_mcp.user_directory.errors import (
    DirectoryTimeoutError,
    UserDirectoryUnavailableError,
    UsersError,
    UsersStoreUnavailableError,
)
from keystone_mcp.user_directory.types import (
    MutationResult,
    UserRecord,
    UserResolveResult,
    subject_type_of,
)
from keystone_mcp.user_directory.util import normalize_email
from keystone_mcp.users.errors import InvalidRoleError
from keystone_mcp.users.roles import check_role_name

logger = logging.getLogger(__name__)

_warned_directory_response_issues: set[tuple[str, str]] = set()


def reset_directory_response_issue_warnings() -> None:
    """Clear one-shot warning state (for tests)."""
    _warned_directory_response_issues.clear()


def _warn_directory_response_issue(field: str, issue: str, *, meaning: str) -> None:
    count_directory_response_issue(field, issue)
    key = (field, issue)
    if key in _warned_directory_response_issues:
        return
    _warned_directory_response_issues.add(key)
    logger.warning(
        "users directory response: %s is %s; treated as %s. Fix the directory service; "
        "see docs/user-directory.md",
        field,
        issue,
        meaning,
    )


#: Header carrying the acting administrator's email on every mutating call.
ACTOR_EMAIL_HEADER = "X-Actor-Email"

_STATUS_CODES: dict[int, str] = {
    400: "bad_request",
    403: "forbidden",
    404: "user_not_found",
    409: "conflict",
    422: "validation_error",
}

#: Service codes normalized onto the ``users_*`` skill's own vocabulary (S3):
#: the HTTP contract predates the skill and still uses its own names for two
#: cases the skill calls something else.
_CODE_NORMALIZATION: dict[str, str] = {
    "invalid_role": "validation_error",
    "user_already_exists": "conflict",
}


def _normalize_code(code: str) -> str:
    return _CODE_NORMALIZATION.get(code, code)


def _reject_resolve_field(field: str, *, kind: str) -> None:
    logger.warning(
        "users directory resolve response field %s has invalid %s",
        field,
        kind,
    )
    raise UserDirectoryUnavailableError(
        "users directory returned an invalid resolve response",
        code="catalog_unavailable",
    )


def _parse_resolve_exists(payload: dict[str, Any]) -> bool:
    if "exists" not in payload:
        _reject_resolve_field("exists", kind="type missing")
    value = payload["exists"]
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        _warn_directory_response_issue("exists", "integer", meaning=str(bool(value)))
        return bool(value)
    _reject_resolve_field("exists", kind=f"type {type(value).__name__}")


def _parse_resolve_is_blocked(payload: dict[str, Any]) -> bool:
    if "is_blocked" not in payload:
        _warn_directory_response_issue("is_blocked", "missing", meaning="false")
        return False
    value = payload["is_blocked"]
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        _warn_directory_response_issue("is_blocked", "integer", meaning=str(bool(value)))
        return bool(value)
    _reject_resolve_field("is_blocked", kind=f"type {type(value).__name__}")


def _parse_resolve_roles(payload: dict[str, Any]) -> tuple[str, ...]:
    roles_raw = payload.get("roles")
    if roles_raw is None:
        return ()
    if not isinstance(roles_raw, list):
        _reject_resolve_field("roles", kind=f"type {type(roles_raw).__name__}")
    roles: list[str] = []
    for role in roles_raw:
        if not isinstance(role, str):
            _reject_resolve_field("roles", kind=f"type {type(role).__name__}")
        roles.append(role)
    return tuple(roles)


def _parse_resolve_subject_type(
    payload: dict[str, Any], *, subject: str
) -> Literal["human", "service"]:
    expected = subject_type_of(subject)
    if "subject_type" not in payload:
        return expected
    value = payload["subject_type"]
    if value not in ("human", "service"):
        _reject_resolve_field("subject_type", kind=f"type {type(value).__name__}")
    if value != expected:
        _reject_resolve_field("subject_type", kind="value mismatch")
    return value  # type: ignore[return-value]


def _parse_resolve_payload(payload: Any, *, subject: str) -> UserResolveResult:
    if not isinstance(payload, dict):
        raise UserDirectoryUnavailableError(
            "users directory returned an invalid resolve response",
            code="catalog_unavailable",
        )
    return UserResolveResult(
        exists=_parse_resolve_exists(payload),
        roles=_parse_resolve_roles(payload),
        is_blocked=_parse_resolve_is_blocked(payload),
        subject_type=_parse_resolve_subject_type(payload, subject=subject),
    )


def _parse_datetime(value: Any) -> datetime:
    """Parse an ISO 8601 timestamp, anchoring a naive one to UTC.

    The HTTP contract's timestamps are always UTC (see ``docs/user-directory.md``),
    but a service that omits the offset would otherwise produce a *naive*
    ``datetime`` here, which ``UserRecord.to_dict()`` later shifts by the
    host's own local timezone via ``astimezone`` -- silently corrupting the
    value. Attaching ``UTC`` directly (rather than converting) keeps the wall-
    clock time exactly as reported.
    """
    parsed = datetime.fromisoformat(str(value))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _user_record_from_payload(payload: dict[str, Any]) -> UserRecord:
    return UserRecord(
        email=str(payload["email"]),
        full_name=str(payload["full_name"]),
        roles=tuple(str(role) for role in payload.get("roles") or ()),
        is_blocked=bool(payload.get("is_blocked")),
        created_at=_parse_datetime(payload["created_at"]),
        updated_at=_parse_datetime(payload["updated_at"]),
        created_by=payload.get("created_by"),
        note=payload.get("note"),
    )


def _parse_user_response_body(body: Any) -> UserRecord:
    """Parse one user object from a mutation/list response.

    Raises :class:`UsersError` (``service_error``) for anything this client
    cannot make sense of -- an empty body, a body that is not the expected
    shape, or a record missing a required field -- rather than letting a bare
    ``KeyError``/``ValueError``/``TypeError`` escape past
    :class:`~keystone_mcp.adapters.users_admin.UsersAdminAdapter`'s error
    envelope (and, with it, past the audit record it would otherwise write).
    """
    try:
        return _user_record_from_payload(body)
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise UsersError(
            "users directory returned an invalid user response", code="service_error"
        ) from exc


class HttpUserDirectory:
    """Calls the HTTP users directory contract with a Bearer service token."""

    def __init__(
        self,
        *,
        base_url: str,
        service_token: str,
        timeout_seconds: float,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(timeout_seconds),
            headers={"Authorization": f"Bearer {service_token}"},
        )

    @property
    def name(self) -> str:
        return "http"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"admin"})

    # ── Read path: errors become UserDirectoryUnavailableError ─────────────

    async def resolve_user(self, subject: str) -> UserResolveResult:
        try:
            response = await self._client.get(
                "/v1/users/resolve",
                params={"email": normalize_email(subject)},
            )
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise UserDirectoryUnavailableError(
                "users directory request timed out",
                code="catalog_timeout",
            ) from exc
        except httpx.HTTPError as exc:
            raise UserDirectoryUnavailableError(
                "users directory is unavailable",
                code="catalog_unavailable",
            ) from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise UserDirectoryUnavailableError(
                "users directory returned an invalid resolve response",
                code="catalog_unavailable",
            ) from exc
        return _parse_resolve_payload(payload, subject=subject)

    async def ping(self) -> None:
        """Not called by ``/readyz`` (S16): an external service's own outage

        already fails every call that needs it; it should not pull every
        Keystone replica out of rotation. Implemented for completeness (a
        plugin directory, or a future internal use, may still want it).
        """
        try:
            response = await self._client.get(
                "/v1/users/resolve", params={"email": "readyz-ping@invalid"}
            )
            response.raise_for_status()
        except httpx.TimeoutException as exc:
            raise UserDirectoryUnavailableError(
                "users directory request timed out", code="catalog_timeout"
            ) from exc
        except httpx.HTTPError as exc:
            raise UserDirectoryUnavailableError(
                "users directory is unavailable", code="catalog_unavailable"
            ) from exc

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    # ── Admin path: errors become UsersError subclasses (users_* skill) ────

    @staticmethod
    def _actor_headers(actor: str) -> dict[str, str]:
        return {ACTOR_EMAIL_HEADER: normalize_email(actor)}

    @staticmethod
    def _email_path(email: str) -> str:
        return quote(normalize_email(email), safe="")

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
            return _normalize_code(code), message
        if isinstance(detail, list):
            return "validation_error", "request validation failed"
        if isinstance(detail, str):
            if top_level_code:
                return _normalize_code(str(top_level_code)), detail
            return _normalize_code(
                cls._infer_code_from_message(response.status_code, detail)
            ), detail
        message = str(body.get("message") or "users service request failed")
        code = str(top_level_code or _STATUS_CODES.get(response.status_code, "service_error"))
        return _normalize_code(code), message

    async def _admin_request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        try:
            return await self._client.request(
                method, path, params=params, json=json, headers=headers
            )
        except httpx.TimeoutException as exc:
            raise DirectoryTimeoutError("users directory request timed out") from exc
        except httpx.HTTPError as exc:
            raise UsersStoreUnavailableError("users directory is unavailable") from exc

    async def _mutation_response(self, response: httpx.Response) -> MutationResult:
        # The service already applied this mutation once it answers with a
        # success status: a failure to parse that answer below must not look
        # like the mutation itself failed (and must not escape as a bare
        # KeyError/ValueError, which would skip UsersAdminAdapter's audit
        # write -- see _parse_user_response_body).
        if not response.is_success:
            code, message = self._parse_service_error(response)
            raise UsersError(message, code=code)
        try:
            body = response.json() if response.content else {}
        except ValueError as exc:
            raise UsersError(
                "users directory returned an invalid user response", code="service_error"
            ) from exc
        changed = True
        created = False
        if isinstance(body, dict):
            if "changed" in body:
                changed = bool(body["changed"])
            if "created" in body:
                created = bool(body["created"])
        return MutationResult(
            user=_parse_user_response_body(body),
            changed=changed,
            created=created,
            roles_before=None,
            blocked_before=None,
        )

    async def list_users(
        self,
        *,
        is_blocked: bool | None = False,
        role: str | None = None,
        email_contains: str | None = None,
    ) -> list[UserRecord]:
        params: dict[str, Any] = {}
        if is_blocked is not None:
            params["is_blocked"] = is_blocked
        if role:
            params["role"] = role
        if email_contains:
            params["email_contains"] = email_contains
        response = await self._admin_request("GET", "/v1/users", params=params)
        if not response.is_success:
            code, message = self._parse_service_error(response)
            raise UsersError(message, code=code)
        try:
            body = response.json() if response.content else {}
            rows = body.get("users", []) if isinstance(body, dict) else body
            return [_parse_user_response_body(row) for row in rows]
        except (ValueError, TypeError, AttributeError) as exc:
            raise UsersError(
                "users directory returned an invalid list response", code="service_error"
            ) from exc

    async def create_user(
        self,
        *,
        email: str,
        full_name: str,
        roles: Sequence[str],
        note: str | None,
        actor: str,
    ) -> MutationResult:
        payload: dict[str, Any] = {
            "email": normalize_email(email),
            "full_name": full_name,
            "roles": list(roles),
            "created_by": normalize_email(actor),
        }
        if note is not None:
            payload["note"] = note
        response = await self._admin_request(
            "POST", "/v1/users", json=payload, headers=self._actor_headers(actor)
        )
        return await self._mutation_response(response)

    async def update_user(
        self,
        *,
        email: str,
        full_name: str | None,
        note: str | None,
        actor: str,
    ) -> MutationResult:
        payload: dict[str, Any] = {}
        if full_name is not None:
            payload["full_name"] = full_name
        if note is not None:
            payload["note"] = note
        response = await self._admin_request(
            "PATCH",
            f"/v1/users/{self._email_path(email)}",
            json=payload,
            headers=self._actor_headers(actor),
        )
        return await self._mutation_response(response)

    async def set_blocked(self, *, email: str, blocked: bool, actor: str) -> MutationResult:
        action = "block" if blocked else "unblock"
        response = await self._admin_request(
            "POST",
            f"/v1/users/{self._email_path(email)}/{action}",
            headers=self._actor_headers(actor),
        )
        return await self._mutation_response(response)

    async def replace_roles(
        self, *, email: str, roles: Sequence[str], actor: str
    ) -> MutationResult:
        response = await self._admin_request(
            "PUT",
            f"/v1/users/{self._email_path(email)}/roles",
            json={"roles": list(roles)},
            headers=self._actor_headers(actor),
        )
        return await self._mutation_response(response)

    async def grant_role(self, *, email: str, role: str, actor: str) -> MutationResult:
        try:
            check_role_name(role)
        except InvalidRoleError as exc:
            raise UsersError(str(exc), code="validation_error") from exc
        response = await self._admin_request(
            "POST",
            f"/v1/users/{self._email_path(email)}/roles/{quote(role, safe='')}",
            headers=self._actor_headers(actor),
        )
        return await self._mutation_response(response)

    async def revoke_role(self, *, email: str, role: str, actor: str) -> MutationResult:
        try:
            check_role_name(role)
        except InvalidRoleError as exc:
            raise UsersError(str(exc), code="validation_error") from exc
        response = await self._admin_request(
            "DELETE",
            f"/v1/users/{self._email_path(email)}/roles/{quote(role, safe='')}",
            headers=self._actor_headers(actor),
        )
        return await self._mutation_response(response)


def create_http_directory(context, options) -> HttpUserDirectory:
    from keystone_mcp.config import Settings
    from keystone_mcp.plugins import PluginContext

    if not isinstance(context, PluginContext):
        raise TypeError("invalid factory arguments")
    settings = context.settings
    if not isinstance(settings, Settings):
        raise TypeError("context.settings must be Settings")
    return HttpUserDirectory(
        base_url=settings.users_service_url,
        service_token=settings.users_service_token,
        timeout_seconds=settings.users_service_timeout_seconds,
    )
