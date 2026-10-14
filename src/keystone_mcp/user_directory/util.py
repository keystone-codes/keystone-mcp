"""Shared helpers for the user-directory client."""

from __future__ import annotations

import unicodedata


def normalize_email(email: str) -> str:
    """Normalize a verified email for cache keys and directory lookups."""
    return email.strip().lower()


def email_folds_to_ascii(raw: str) -> bool:
    """True when a non-ASCII character in *raw* can become ASCII after case or NFKC."""
    for ch in raw.strip():
        if ord(ch) <= 127:
            continue
        for form in (
            ch.lower(),
            unicodedata.normalize("NFKC", ch),
            unicodedata.normalize("NFKC", ch).lower(),
        ):
            if any(ord(c) < 128 for c in form):
                return True
    return False
