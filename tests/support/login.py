"""Helpers for wiring API-key login in tests."""

from __future__ import annotations

from keystone_mcp.login.api_key import ApiKeyLoginProvider
from keystone_mcp.user_directory.protocol import UserDirectoryResolver


def dev_token_login(
    tokens: set[str],
    *,
    resolver: UserDirectoryResolver | None = None,
) -> ApiKeyLoginProvider:
    """API-key login that accepts only the given DEV tokens (no directory keys)."""
    return ApiKeyLoginProvider(
        resolver=resolver,
        dev_tokens=frozenset(tokens),
        resolve_directory_keys=False,
        enforce_directory_for_dev_tokens=False,
    )
