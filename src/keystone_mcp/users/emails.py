"""Email normalization and validation helpers for the users directory."""

from __future__ import annotations

from keystone_mcp.user_directory.util import email_folds_to_ascii
from keystone_mcp.users.errors import InvalidUserFieldError

MAX_EMAIL_LENGTH = 320


def normalize_email(email: str) -> str:
    """Return the canonical lowercase form used for storage and lookup."""
    return email.strip().lower()


def require_valid_email(email: str) -> str:
    """Normalize ``email`` and reject anything that is not a plausible address.

    Used on write paths (create, seed, ensure_administrator). Lookups go
    through ``normalize_email`` alone: a malformed or unknown address there
    should surface as ``UserNotFoundError``, not a validation error.
    """
    if email_folds_to_ascii(email):
        raise InvalidUserFieldError("email", "contains characters that look like ASCII letters")
    normalized = normalize_email(email)
    if len(normalized) > MAX_EMAIL_LENGTH:
        raise InvalidUserFieldError("email", "too long")
    if normalized.count("@") != 1:
        raise InvalidUserFieldError("email", "must contain exactly one '@'")
    local_part, _, domain_part = normalized.partition("@")
    if not local_part or not domain_part:
        raise InvalidUserFieldError("email", "must have a non-empty local and domain part")
    return normalized
