"""Shared helpers for the user-directory client."""

from __future__ import annotations


def normalize_email(email: str) -> str:
    """Normalize a verified email for cache keys and directory lookups."""
    return email.strip().lower()
