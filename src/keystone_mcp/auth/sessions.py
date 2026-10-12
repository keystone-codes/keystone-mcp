"""Revoke OAuth sessions for a human subject (access + refresh tokens)."""

from __future__ import annotations

import logging
import time

from keystone_mcp.auth.login_pending_store import LoginPendingStore
from keystone_mcp.auth.oauth_store import OAuthStore
from keystone_mcp.observability.subject import hash_subject
from keystone_mcp.user_directory.util import normalize_email

logger = logging.getLogger(__name__)

_NS_REFRESH_AUTH = "refresh_auth"


class SessionRevoker:
    """Drop every OAuth token for a subject and clear refresh login markers."""

    def __init__(self, oauth_store: OAuthStore, login_store: LoginPendingStore) -> None:
        self._oauth_store = oauth_store
        self._login_store = login_store

    async def revoke_subject(self, subject: str) -> int:
        """Revoke every token of the subject; return the number of tokens removed."""
        normalized = normalize_email(subject)
        revoked = await self._oauth_store.revoke_subject(normalized, now=int(time.time()))
        for refresh_token in revoked.refresh_tokens:
            await self._login_store.consume(_NS_REFRESH_AUTH, refresh_token)
        count = revoked.access + len(revoked.refresh_tokens)
        logger.info(
            "sessions revoked subject=%s tokens=%d",
            hash_subject(normalized),
            count,
        )
        return count
