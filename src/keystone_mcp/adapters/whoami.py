"""Built-in ``whoami`` tool: the signed-in caller, and nobody else.

Reads the users directory directly (not the RBAC role cache) so a block is
visible on the next call. It takes no arguments and cannot look up a
different person. An RBAC refusal never becomes an envelope here: the
middleware raises ``access denied`` before ``execute`` runs.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import httpx
from redis.exceptions import RedisError

from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError, UsersError
from keystone_mcp.user_directory.protocol import UserDirectory
from keystone_mcp.user_directory.util import normalize_email

if TYPE_CHECKING:
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route

logger = logging.getLogger(__name__)

WHOAMI_ERROR_CODES: frozenset[str] = frozenset(
    {
        "forbidden",
        "service_timeout",
        "service_unavailable",
        "service_unconfigured",
        "user_not_found",
    }
)


class WhoamiAdapter:
    """Returns the caller's subject, e-mail, name, roles and subject type."""

    def __init__(self, directory: UserDirectory | None) -> None:
        self._directory = directory

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
    def _directory_failure(exc: UsersError) -> tuple[str, str]:
        # Fixed text for codes that can carry a host, a query or a credential.
        # Every other code in this tool's set is already safe to show.
        if exc.code == "service_unavailable":
            return "service_unavailable", "users directory is unavailable"
        if exc.code == "service_timeout":
            return "service_timeout", "users service timed out"
        if exc.code in WHOAMI_ERROR_CODES:
            return exc.code, str(exc)
        return "service_unavailable", "users directory is unavailable"

    async def execute(
        self,
        route: Route,
        ctx: RouteContext,
        args: dict[str, Any],
        request: Any,
    ) -> dict[str, Any]:
        del args, request
        directory = self._directory
        if directory is None:
            return self._error(
                route,
                ctx,
                code="service_unconfigured",
                message="users directory is not configured",
            )

        identity = ctx.verified_identity
        try:
            resolved = await directory.resolve_user(identity.subject)
            if not resolved.exists:
                return self._error(
                    route,
                    ctx,
                    code="user_not_found",
                    message="user not found",
                )
            if resolved.is_blocked:
                return self._error(
                    route,
                    ctx,
                    code="forbidden",
                    message="account is blocked",
                )
            full_name: str | None = None
            email = identity.email
            if resolved.subject_type == "human" and email is not None:
                rows = await directory.list_users(email_contains=email, is_blocked=False)
                normalized = normalize_email(email)
                for row in rows:
                    if normalize_email(row.email) == normalized:
                        full_name = row.full_name
                        break
        except UsersError as exc:
            code, message = self._directory_failure(exc)
            return self._error(route, ctx, code=code, message=message)
        except UserDirectoryUnavailableError as exc:
            logger.warning("whoami directory unavailable: %s", exc.code)
            if exc.code == "catalog_timeout":
                return self._error(
                    route,
                    ctx,
                    code="service_timeout",
                    message="users service timed out",
                )
            return self._error(
                route,
                ctx,
                code="service_unavailable",
                message="users directory is unavailable",
            )
        except (httpx.TimeoutException, TimeoutError):
            logger.warning("whoami directory timed out")
            return self._error(
                route,
                ctx,
                code="service_timeout",
                message="users service timed out",
            )
        except (httpx.HTTPError, RedisError, OSError):
            logger.warning("whoami directory call failed")
            return self._error(
                route,
                ctx,
                code="service_unavailable",
                message="users directory is unavailable",
            )

        return self._done(
            route,
            ctx,
            sub=identity.subject,
            subject_type=resolved.subject_type,
            email=identity.email,
            full_name=full_name,
            roles=list(resolved.roles),
            client_id=identity.client_id,
        )
