"""Domain errors for the users directory.

Error codes follow ``skills/keystone-user-admin/SKILL.md`` (table "Errors"),
which is what the ``users_*`` tool adapter promises its callers. They do not
necessarily match the codes used by the legacy HTTP-based directory service.
"""

from __future__ import annotations


class UsersError(Exception):
    """Base class for all users-directory domain errors."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


class UserNotFoundError(UsersError):
    def __init__(self, email: str) -> None:
        super().__init__(f"User not found: {email}", code="user_not_found")


class UserAlreadyExistsError(UsersError):
    def __init__(self, email: str) -> None:
        super().__init__(f"User already exists: {email}", code="conflict")


class InvalidRoleError(UsersError):
    def __init__(self, role: str, *, reason: str) -> None:
        self.role = role
        self.reason = reason
        if reason == "unknown":
            message = f"unknown role: {role}"
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
