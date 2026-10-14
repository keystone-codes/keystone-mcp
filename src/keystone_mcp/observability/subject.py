"""PII-minimized subject identifiers for audit records."""

from __future__ import annotations

import hashlib

from keystone_mcp.user_directory.types import parse_service_subject
from keystone_mcp.user_directory.util import normalize_email

_subject_salt: str = ""


def configure_subject_salt(salt: str) -> None:
    """Set once at startup from KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT."""
    global _subject_salt
    _subject_salt = salt


def normalize_subject(subject: str) -> str:
    """Normalize a directory subject (human email or svc:… service account)."""
    if parse_service_subject(subject) is not None:
        return subject.strip().lower()
    return normalize_email(subject)


def hash_subject(email: str | None, *, salt: str) -> str | None:
    """Return a stable pseudonym for a verified subject (never the raw address)."""
    if not email:
        return None
    normalized = normalize_subject(email)
    digest = hashlib.sha256(f"{salt}{normalized}".encode("utf-8")).hexdigest()
    return f"sub_{digest[:16]}"


def subject_pseudonym(subject: str | None) -> str | None:
    """Salted pseudonym for any log line (audit or not)."""
    return hash_subject(subject, salt=_subject_salt)


def roles_label(roles: frozenset[str] | tuple[str, ...] | set[str]) -> str:
    """Compact, sorted role aggregate for audit and metrics labels."""
    if not roles:
        return "-"
    return ",".join(sorted(roles))
