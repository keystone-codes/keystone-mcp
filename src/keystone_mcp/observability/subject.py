"""PII-minimized subject identifiers for audit records."""

from __future__ import annotations

import hashlib

from keystone_mcp.user_directory.util import normalize_email


def hash_subject(email: str | None, *, salt: str = "") -> str | None:
    """Return a stable pseudonym for a verified email (never the raw address)."""
    if not email:
        return None
    normalized = normalize_email(email)
    digest = hashlib.sha256(f"{salt}{normalized}".encode("utf-8")).hexdigest()
    return f"sub_{digest[:16]}"


def roles_label(roles: frozenset[str] | tuple[str, ...] | set[str]) -> str:
    """Compact, sorted role aggregate for audit and metrics labels."""
    if not roles:
        return "-"
    return ",".join(sorted(roles))
