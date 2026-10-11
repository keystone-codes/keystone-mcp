"""Directory resolver errors distinguishable from authorization denial."""

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
