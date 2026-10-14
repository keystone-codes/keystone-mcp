"""Revoke OAuth sessions for a human subject (access + refresh tokens)."""

from __future__ import annotations

import logging
import time

from keystone_mcp.auth.keystone_oauth_provider import parse_refresh_meta
from keystone_mcp.auth.login_pending_store import LoginPendingStore
from keystone_mcp.auth.oauth_store import OAuthStore
from keystone_mcp.observability.subject import subject_pseudonym
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
            subject_pseudonym(normalized),
            count,
        )
        return count

    async def revoke_api_key_sessions(self, subject: str, key_id: str) -> int:
        """Revoke tokens for sessions opened with the given API key id."""
        normalized = normalize_email(subject)
        access_list, refresh_list = await self._oauth_store.subject_tokens(normalized)
        access_tokens: list[str] = []
        refresh_tokens: list[str] = []
        legacy = False

        for refresh in refresh_list:
            raw = await self._login_store.get(_NS_REFRESH_AUTH, refresh.token)
            meta = parse_refresh_meta(raw)
            if meta is None:
                continue
            if meta.key_id_known and meta.key_id == key_id:
                refresh_tokens.append(refresh.token)
            elif meta.auth_method == "api_key" and not meta.key_id_known:
                refresh_tokens.append(refresh.token)
                legacy = True

        for access in access_list:
            claims = access.claims or {}
            if claims.get("key_id") == key_id:
                access_tokens.append(access.token)

        revoked = await self._oauth_store.revoke_tokens(
            normalized, access=access_tokens, refresh=refresh_tokens
        )
        for rt in revoked.refresh_tokens:
            await self._login_store.consume(_NS_REFRESH_AUTH, rt)

        count = revoked.access + len(revoked.refresh_tokens)
        if legacy:
            count += await self.revoke_subject(normalized)
            logger.info(
                "legacy api-key sessions revoked subject=%s key_id=%s",
                subject_pseudonym(normalized),
                key_id,
            )
        return count
