"""Directory errors: resolver fail-closed errors plus admin domain errors.

Two related but distinct error families live here:

* :class:`UserDirectoryError` / :class:`UserDirectoryUnavailableError` --
  raised by the read-only path (``resolve_user``, ``ping``) that
  :class:`~keystone_mcp.user_directory.resolver.CachedUserDirectoryResolver`
  and the readiness probe depend on. These signal "fail closed": the catalog
  could not be reached, timed out, or the circuit breaker is open.
* :class:`UsersError` and its subclasses -- raised by ``list_users`` and the
  :class:`~keystone_mcp.user_directory.protocol.UserDirectoryAdmin` methods.
  Their ``code`` values follow ``skills/keystone-user-admin/SKILL.md`` (table
  "Errors"), which is what the ``users_*`` tool adapter
  (:class:`~keystone_mcp.adapters.users_admin.UsersAdminAdapter`) promises its
  callers. An HTTP-backed directory normalizes whatever its service returns
  onto these same codes (see
  :mod:`keystone_mcp.user_directory.http`) rather than leaking its own.
"""

from __future__ import annotations

UNAVAILABLE_ERROR_CODES = frozenset(
    {
        "catalog_unavailable",
        "catalog_timeout",
        "circuit_open",
        "revision_unavailable",
    }
)


class UserDirectoryError(Exception):
    """Base error for user-directory client failures."""

    code: str

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class UserDirectoryUnavailableError(UserDirectoryError):
    """Fail-closed: catalog/revision unreachable, timed out, or circuit is open."""

    def __init__(self, message: str, *, code: str) -> None:
        if code not in UNAVAILABLE_ERROR_CODES:
            raise ValueError(f"unexpected unavailable code: {code}")
        super().__init__(message, code=code)


class UsersError(Exception):
    """Base class for all users-directory admin domain errors."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class UserNotFoundError(UsersError):
    def __init__(self, email: str, *, message: str | None = None) -> None:
        super().__init__(message or f"User not found: {email}", code="user_not_found")


class UserAlreadyExistsError(UsersError):
    def __init__(self, email: str) -> None:
        super().__init__(f"User already exists: {email}", code="conflict")


class InvalidRoleError(UsersError):
    def __init__(self, role: str, *, reason: str) -> None:
        self.role = role
        self.reason = reason
        if reason == "unknown":
            message = f"unknown role: {role}"
        elif reason == "reserved":
            message = f"{role} is reserved for people"
        else:
            message = f"invalid role name: {role!r}"
        super().__init__(message, code="validation_error")


class InvalidUserFieldError(UsersError):
    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"invalid {field}: {reason}", code="validation_error")


class LastAdministratorError(UsersError):
    def __init__(self) -> None:
        super().__init__(
            "Cannot remove or block the last active administrator",
            code="last_administrator",
        )


class SelfAdminMutationError(UsersError):
    def __init__(self, action: str) -> None:
        super().__init__(
            f"Administrator cannot {action} their own administrator access",
            code="self_admin_mutation_forbidden",
        )


class ActorEmailRequiredError(UsersError):
    def __init__(self) -> None:
        super().__init__(
            "actor email is required for this mutation",
            code="actor_email_required",
        )


class UsersStoreUnavailableError(UsersError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="service_unavailable")


class DirectoryTimeoutError(UsersError):
    """A directory's administration path timed out (distinct from ``catalog_timeout``,

    which belongs to the read-only ``resolve_user``/``ping`` path)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, code="service_timeout")
