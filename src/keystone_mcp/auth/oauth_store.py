"""Persistent OAuth session store (clients, access tokens, refresh tokens).

Production uses the deployment's Redis; tests inject
:class:`InMemoryOAuthStore`.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Protocol, Sequence, runtime_checkable

from mcp.server.auth.provider import AccessToken, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import ConfigDict, Field
from redis.asyncio import Redis
from redis.exceptions import RedisError, WatchError

from keystone_mcp.observability.metrics import record_oauth_token_key_migration
from keystone_mcp.redis_client import redis_from_url
from keystone_mcp.user_directory.util import normalize_email

_SUBJECT_INDEX_MAX_MEMBERS = 256
_COMMIT_MAX_WATCH_RETRIES = 16
_LEGACY_CLIENT_SCAN_LIMIT = 100_000

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def _trace_redis_operation(operation: str):
    from keystone_mcp.observability.tracing import (
        DB_OPERATION_NAME,
        DB_SYSTEM_NAME,
        traced,
    )

    with traced(
        f"keystone.redis.{operation}",
        **{DB_SYSTEM_NAME: "redis", DB_OPERATION_NAME: operation},
    ):
        yield


@dataclass(frozen=True, slots=True)
class RevokedTokens:
    access: int
    refresh_tokens: tuple[str, ...]


class CredentialRevokedError(Exception):
    """Consumed credential was issued at or before the subject's not-before time."""


class RefreshTokenAlreadyRotatedError(Exception):
    """Refresh token was already rotated by another concurrent exchange."""


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class RotationRecord:
    used_json: str
    used_ttl: int
    grace_blob: str | None
    grace_ttl: int
    old_meta: str | None
    old_meta_ttl: int


@dataclass(frozen=True, slots=True)
class RotatedRefresh:
    subject: str
    client_id: str
    scopes: list[str]
    expires_at: int | None
    resource: str | None
    rotated_at: int


class KeystoneRefreshToken(RefreshToken):
    """Refresh token record with an optional issued-at time (0.6.0+)."""

    model_config = ConfigDict(extra="ignore")

    iat: int | None = None
    rotated: bool = Field(default=False, exclude=True)


def _subject_key(subject: str) -> str:
    if subject.startswith("svc:"):
        return subject
    return normalize_email(subject)


# Margin added on top of the longer of the refresh-token and access-token
# lifetimes to compute how long a registered client is kept in Redis. The
# margin absorbs the gap between a token's expiry and the client's last use.
CLIENT_TTL_MARGIN_SECONDS = 86400
UNUSED_CLIENT_TTL_SECONDS = 86400


def client_ttl_seconds(settings: object) -> int:
    """Client lifetime: the longer of the refresh/access TTLs, plus a day's margin."""
    refresh_ttl = getattr(settings, "refresh_token_ttl_seconds", 30 * 86400)
    access_ttl = getattr(settings, "token_cache_ttl_seconds", 86400)
    return max(refresh_ttl, access_ttl) + CLIENT_TTL_MARGIN_SECONDS


@runtime_checkable
class OAuthStore(Protocol):
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None: ...

    async def put_client(self, client: OAuthClientInformationFull) -> None: ...

    async def touch_client(self, client_id: str) -> None: ...

    async def count_clients(self) -> int: ...

    async def evict_unused_client(self) -> str | None: ...

    async def get_access_token(self, token: str) -> AccessToken | None: ...

    async def put_access_token(self, access: AccessToken) -> None: ...

    async def delete_access_token(self, token: str) -> None: ...

    async def get_refresh_token(self, token: str) -> RefreshToken | None: ...

    async def put_refresh_token(self, refresh: RefreshToken) -> None: ...

    async def delete_refresh_token(self, token: str) -> None: ...

    async def revoke_subject(self, subject: str, *, now: int) -> RevokedTokens: ...

    async def revoke_client_tokens(self, subject: str, client_id: str) -> int: ...

    async def revoke_refresh_grant(
        self, subject: str, client_id: str, refresh_token: str
    ) -> None: ...

    async def subject_not_before(self, subject: str) -> int | None: ...

    def refresh_credential_iat(self, refresh: RefreshToken) -> int | None: ...

    @property
    def writes_refresh_meta(self) -> bool: ...

    async def commit_token_pair(
        self,
        *,
        subject: str,
        consumed_iat: int | None,
        access: AccessToken,
        refresh: RefreshToken,
        replace_refresh_token: str | None = None,
        refresh_meta: str | None = None,
        rotation: RotationRecord | None = None,
    ) -> None: ...

    async def get_rotated_refresh(self, token: str) -> RotatedRefresh | None: ...

    async def get_refresh_grace(self, token: str) -> str | None: ...

    async def subject_tokens(
        self, subject: str
    ) -> tuple[list[AccessToken], list[KeystoneRefreshToken]]: ...

    async def revoke_tokens(
        self, subject: str, *, access: Sequence[str], refresh: Sequence[str]
    ) -> RevokedTokens: ...

    async def aclose(self) -> None: ...


class InMemoryOAuthStore:
    """Ephemeral store for unit tests only.

    Mirrors :class:`RedisOAuthStore`'s TTL semantics (client and refresh-token
    expiry, ``touch_client`` renewal) so tests can exercise the same behaviour
    without Redis.
    """

    def __init__(
        self,
        *,
        client_ttl_seconds: int = 31 * 86400,
        refresh_ttl_seconds: int = 30 * 86400,
        access_ttl_seconds: int = 3600,
    ) -> None:
        self._client_ttl_seconds = client_ttl_seconds
        self._refresh_ttl_seconds = refresh_ttl_seconds
        self._access_ttl_seconds = access_ttl_seconds
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._client_expires_at: dict[str, float] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}
        self._refresh_expires_at: dict[str, float] = {}
        self._subject_index: dict[str, set[str]] = {}
        self._subject_index_expires_at: dict[str, float] = {}
        self._subject_nbf: dict[str, int] = {}
        self._refresh_revoked: set[str] = set()
        self._client_unused: dict[str, float] = {}
        self._rt_used: dict[str, tuple[str, float]] = {}
        self._rt_grace: dict[str, tuple[str, float]] = {}
        self._commit_lock = asyncio.Lock()

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        client = self._clients.get(client_id)
        if client is None:
            return None
        expires_at = self._client_expires_at.get(client_id)
        if expires_at is not None and expires_at < time.time():
            self._clients.pop(client_id, None)
            self._client_expires_at.pop(client_id, None)
            return None
        return client

    async def put_client(self, client: OAuthClientInformationFull) -> None:
        unused_ttl = min(UNUSED_CLIENT_TTL_SECONDS, self._client_ttl_seconds)
        self._clients[client.client_id] = client
        self._client_expires_at[client.client_id] = time.time() + unused_ttl
        self._client_unused[client.client_id] = time.time()

    async def touch_client(self, client_id: str) -> None:
        if client_id not in self._clients:
            return
        self._client_expires_at[client_id] = time.time() + self._client_ttl_seconds
        self._client_unused.pop(client_id, None)

    async def count_clients(self) -> int:
        now = time.time()
        unused_cutoff = now - UNUSED_CLIENT_TTL_SECONDS
        for client_id, registered_at in list(self._client_unused.items()):
            if registered_at <= unused_cutoff:
                self._client_unused.pop(client_id, None)
        expired = [
            client_id
            for client_id, expires_at in self._client_expires_at.items()
            if expires_at < now
        ]
        for client_id in expired:
            self._clients.pop(client_id, None)
            self._client_expires_at.pop(client_id, None)
            self._client_unused.pop(client_id, None)
        return len(self._clients)

    async def evict_unused_client(self) -> str | None:
        for _ in range(10):
            if not self._client_unused:
                return None
            client_id = min(self._client_unused, key=self._client_unused.__getitem__)
            self._client_unused.pop(client_id, None)
            if client_id not in self._clients:
                continue
            self._clients.pop(client_id, None)
            self._client_expires_at.pop(client_id, None)
            return client_id
        return None

    def _touch_subject_index(self, sub: str) -> None:
        self._subject_index_expires_at[sub] = time.time() + self._client_ttl_seconds

    def _subject_index_alive(self, sub: str) -> bool:
        expires = self._subject_index_expires_at.get(sub)
        if expires is not None and expires < time.time():
            self._subject_index.pop(sub, None)
            self._subject_index_expires_at.pop(sub, None)
            self._subject_nbf.pop(sub, None)
            return False
        return True

    def _add_subject_member(self, sub: str, member: str) -> None:
        if not self._subject_index_alive(sub):
            self._subject_index.setdefault(sub, set())
        self._subject_index.setdefault(sub, set()).add(member)
        self._touch_subject_index(sub)
        members = self._subject_index.get(sub, set())
        if len(members) > _SUBJECT_INDEX_MAX_MEMBERS:
            dead = [m for m in members if not self._member_exists(m)]
            for m in dead:
                members.discard(m)

    def _member_exists(self, member: str) -> bool:
        if member.startswith("at:"):
            return member[3:] in self._access_tokens
        if member.startswith("rt:"):
            return member[3:] in self._refresh_tokens
        return False

    def _remove_subject_member(self, sub: str, member: str) -> None:
        if not self._subject_index_alive(sub):
            return
        members = self._subject_index.get(sub)
        if members is not None:
            members.discard(member)

    def _access_iat(self, access: AccessToken) -> int | None:
        claims = access.claims or {}
        iat = claims.get("iat")
        if isinstance(iat, int):
            return iat
        if access.expires_at is not None:
            return int(access.expires_at) - self._access_ttl_seconds
        return None

    def _refresh_iat(self, refresh: RefreshToken) -> int | None:
        stored_iat = getattr(refresh, "iat", None)
        if isinstance(stored_iat, int):
            return stored_iat
        if refresh.expires_at is not None:
            return int(refresh.expires_at) - self._refresh_ttl_seconds
        return None

    @property
    def writes_refresh_meta(self) -> bool:
        return False

    def _reject_if_before_nbf(self, sub: str, iat: int | None) -> bool:
        if iat is None:
            return False
        if not self._subject_index_alive(sub):
            return False
        nbf = self._subject_nbf.get(sub)
        return nbf is not None and iat < nbf

    def _migrate_access_storage_key(self, token: str, access: AccessToken) -> AccessToken:
        ref = token_digest(token)
        stored = access.model_copy(update={"token": ref})
        self._access_tokens.pop(token, None)
        self._access_tokens[ref] = stored
        if access.subject:
            norm = _subject_key(access.subject)
            members = self._subject_index.setdefault(norm, set())
            members.discard(f"at:{token}")
            members.add(f"at:{ref}")
        return stored

    async def get_access_token(self, token: str) -> AccessToken | None:
        ref = token_digest(token)
        access = self._access_tokens.get(ref)
        if access is None:
            legacy = self._access_tokens.get(token)
            if legacy is None:
                return None
            access = self._migrate_access_storage_key(token, legacy)
        if access.expires_at is not None and access.expires_at < time.time():
            await self.delete_access_token(token)
            return None
        sub = access.subject
        if sub:
            norm = _subject_key(sub)
            iat = self._access_iat(access)
            if self._reject_if_before_nbf(norm, iat):
                await self.delete_access_token(token)
                return None
            claims = dict(access.claims or {})
            if "iat" not in claims and iat is not None:
                claims["iat"] = iat
                access = access.model_copy(update={"claims": claims})
                self._access_tokens[ref] = access
            self._add_subject_member(norm, f"at:{ref}")
        return access.model_copy(update={"token": token})

    async def put_access_token(self, access: AccessToken) -> None:
        ref = token_digest(access.token)
        stored = access.model_copy(update={"token": ref})
        self._access_tokens[ref] = stored
        if access.subject:
            self._add_subject_member(_subject_key(access.subject), f"at:{ref}")

    async def _delete_access_suffix(self, suffix: str) -> None:
        access = self._access_tokens.pop(suffix, None)
        if access is not None and access.subject:
            self._remove_subject_member(_subject_key(access.subject), f"at:{suffix}")

    async def delete_access_token(self, token: str) -> None:
        if token.startswith("km_at_"):
            await self._delete_access_suffix(token_digest(token))
        await self._delete_access_suffix(token)

    def _migrate_refresh_storage_key(self, token: str, refresh: RefreshToken) -> RefreshToken:
        ref = token_digest(token)
        stored = refresh.model_copy(update={"token": ref})
        legacy_exp = self._refresh_expires_at.pop(token, None)
        self._refresh_tokens.pop(token, None)
        self._refresh_tokens[ref] = stored
        if legacy_exp is not None:
            self._refresh_expires_at[ref] = legacy_exp
        if refresh.subject:
            norm = _subject_key(refresh.subject)
            members = self._subject_index.setdefault(norm, set())
            members.discard(f"rt:{token}")
            members.add(f"rt:{ref}")
        return stored

    async def get_refresh_token(self, token: str) -> RefreshToken | None:
        ref = token_digest(token)
        refresh = self._refresh_tokens.get(ref)
        if refresh is None:
            legacy = self._refresh_tokens.get(token)
            if legacy is None:
                return None
            refresh = self._migrate_refresh_storage_key(token, legacy)
        expires_at = self._refresh_expires_at.get(ref)
        if expires_at is not None and expires_at < time.time():
            await self.delete_refresh_token(token)
            return None
        if refresh.subject:
            norm = _subject_key(refresh.subject)
            iat = self._refresh_iat(refresh)
            if self._reject_if_before_nbf(norm, iat):
                await self.delete_refresh_token(token)
                return None
            self._add_subject_member(norm, f"rt:{ref}")
        return refresh.model_copy(update={"token": token})

    async def put_refresh_token(self, refresh: RefreshToken) -> None:
        ref = token_digest(refresh.token)
        stored = refresh.model_copy(update={"token": ref})
        self._refresh_tokens[ref] = stored
        if refresh.expires_at is not None:
            ttl = max(refresh.expires_at - time.time(), 1)
        else:
            ttl = self._refresh_ttl_seconds
        self._refresh_expires_at[ref] = time.time() + ttl
        if refresh.subject:
            self._add_subject_member(_subject_key(refresh.subject), f"rt:{ref}")

    async def _delete_refresh_suffix(self, suffix: str) -> None:
        refresh = self._refresh_tokens.pop(suffix, None)
        self._refresh_expires_at.pop(suffix, None)
        if refresh is not None and refresh.subject:
            self._remove_subject_member(_subject_key(refresh.subject), f"rt:{suffix}")

    async def delete_refresh_token(self, token: str) -> None:
        if token.startswith("km_rt_"):
            await self._delete_refresh_suffix(token_digest(token))
        await self._delete_refresh_suffix(token)

    async def revoke_subject(self, subject: str, *, now: int) -> RevokedTokens:
        sub = _subject_key(subject)
        self._subject_nbf[sub] = now
        self._touch_subject_index(sub)
        members = list(self._subject_index.get(sub, ()))
        access_count = 0
        refresh_tokens: list[str] = []
        for member in members:
            if member.startswith("at:"):
                tok = member[3:]
                self._access_tokens.pop(tok, None)
                access_count += 1
            elif member.startswith("rt:"):
                tok = member[3:]
                self._refresh_tokens.pop(tok, None)
                self._refresh_expires_at.pop(tok, None)
                refresh_tokens.append(tok)
        self._subject_index.pop(sub, None)
        return RevokedTokens(access=access_count, refresh_tokens=tuple(refresh_tokens))

    async def revoke_client_tokens(self, subject: str, client_id: str) -> int:
        sub = _subject_key(subject)
        if not self._subject_index_alive(sub):
            return 0
        count = 0
        for member in list(self._subject_index.get(sub, ())):
            if not member.startswith("at:"):
                continue
            tok = member[3:]
            access = self._access_tokens.get(tok)
            if access is None or access.client_id != client_id:
                continue
            await self.delete_access_token(tok)
            count += 1
        return count

    async def revoke_refresh_grant(self, subject: str, client_id: str, refresh_token: str) -> None:
        async with self._commit_lock:
            await self.revoke_client_tokens(subject, client_id)
            self._refresh_revoked.add(token_digest(refresh_token))
            await self.delete_refresh_token(refresh_token)

    async def subject_not_before(self, subject: str) -> int | None:
        sub = _subject_key(subject)
        if not self._subject_index_alive(sub):
            return None
        return self._subject_nbf.get(sub)

    def refresh_credential_iat(self, refresh: RefreshToken) -> int | None:
        return self._refresh_iat(refresh)

    def _credential_revoked_by_nbf(self, sub: str, consumed_iat: int | None) -> bool:
        if not self._subject_index_alive(sub):
            return False
        nbf = self._subject_nbf.get(sub)
        if nbf is None:
            return False
        if consumed_iat is None:
            return True
        return consumed_iat <= nbf

    def _expiring_get(self, store: dict[str, tuple[str, float]], key: str) -> str | None:
        entry = store.get(key)
        if entry is None:
            return None
        payload, expires_at = entry
        if expires_at < time.time():
            store.pop(key, None)
            return None
        return payload

    def _expiring_put(
        self, store: dict[str, tuple[str, float]], key: str, payload: str, ttl: int
    ) -> None:
        if ttl <= 0:
            return
        store[key] = (payload, time.time() + ttl)

    async def commit_token_pair(
        self,
        *,
        subject: str,
        consumed_iat: int | None,
        access: AccessToken,
        refresh: RefreshToken,
        replace_refresh_token: str | None = None,
        refresh_meta: str | None = None,
        rotation: RotationRecord | None = None,
    ) -> None:
        sub = _subject_key(subject)
        async with self._commit_lock:
            if self._credential_revoked_by_nbf(sub, consumed_iat):
                if replace_refresh_token is not None:
                    await self.delete_refresh_token(replace_refresh_token)
                raise CredentialRevokedError()
            if replace_refresh_token is not None:
                replace_ref = token_digest(replace_refresh_token)
                if (
                    replace_ref in self._refresh_revoked
                    or replace_refresh_token in self._refresh_revoked
                ):
                    raise CredentialRevokedError()
                if (
                    replace_ref not in self._refresh_tokens
                    and replace_refresh_token not in self._refresh_tokens
                ):
                    raise RefreshTokenAlreadyRotatedError()
            await self.put_access_token(access)
            await self.put_refresh_token(refresh)
            if replace_refresh_token is not None:
                digest = token_digest(replace_refresh_token)
                if rotation is not None:
                    self._expiring_put(self._rt_used, digest, rotation.used_json, rotation.used_ttl)
                    if rotation.grace_blob is not None and rotation.grace_ttl > 0:
                        self._expiring_put(
                            self._rt_grace, digest, rotation.grace_blob, rotation.grace_ttl
                        )
                await self.delete_refresh_token(replace_refresh_token)

    async def get_rotated_refresh(self, token: str) -> RotatedRefresh | None:
        raw = self._expiring_get(self._rt_used, token_digest(token))
        if raw is None:
            return None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return RotatedRefresh(
            subject=data["subject"],
            client_id=data["client_id"],
            scopes=list(data.get("scopes") or []),
            expires_at=data.get("expires_at"),
            resource=data.get("resource"),
            rotated_at=int(data["rotated_at"]),
        )

    async def get_refresh_grace(self, token: str) -> str | None:
        return self._expiring_get(self._rt_grace, token_digest(token))

    async def subject_tokens(
        self, subject: str
    ) -> tuple[list[AccessToken], list[KeystoneRefreshToken]]:
        sub = _subject_key(subject)
        if not self._subject_index_alive(sub):
            return [], []
        access_out: list[AccessToken] = []
        refresh_out: list[KeystoneRefreshToken] = []
        for member in list(self._subject_index.get(sub, ())):
            if member.startswith("at:"):
                tok = member[3:]
                access = self._access_tokens.get(tok)
                if access is not None:
                    access_out.append(access)
            elif member.startswith("rt:"):
                tok = member[3:]
                refresh = self._refresh_tokens.get(tok)
                if refresh is not None:
                    refresh_out.append(KeystoneRefreshToken.model_validate(refresh.model_dump()))
        return access_out, refresh_out

    async def revoke_tokens(
        self, subject: str, *, access: Sequence[str], refresh: Sequence[str]
    ) -> RevokedTokens:
        access_count = 0
        refresh_tokens: list[str] = []
        for tok in access:
            if tok in self._access_tokens:
                await self.delete_access_token(tok)
                access_count += 1
        for tok in refresh:
            if tok in self._refresh_tokens:
                refresh = self._refresh_tokens[tok]
                if refresh.expires_at is None:
                    revoked_ttl = self._refresh_ttl_seconds
                else:
                    revoked_ttl = max(int(refresh.expires_at - time.time()), 1)
                self._refresh_revoked.add(tok)
                await self._delete_refresh_suffix(tok)
                refresh_tokens.append(tok)
                _ = revoked_ttl
        return RevokedTokens(access=access_count, refresh_tokens=tuple(refresh_tokens))

    async def aclose(self) -> None:
        return None


class RedisOAuthStore:
    """OAuth sessions in Redis (key prefix isolates from other applications)."""

    def __init__(
        self,
        redis_url: str,
        key_prefix: str = "km:oauth:",
        *,
        redis: Redis | None = None,
        owns_redis: bool = True,
        client_ttl_seconds: int = 31 * 86400,
        refresh_ttl_seconds: int = 30 * 86400,
        access_ttl_seconds: int = 3600,
        refresh_meta_key_prefix: str | None = None,
    ) -> None:
        prefix = key_prefix if key_prefix.endswith(":") else f"{key_prefix}:"
        self._prefix = prefix
        self._refresh_meta_key_prefix = refresh_meta_key_prefix
        self._client_ttl_seconds = client_ttl_seconds
        self._refresh_ttl_seconds = refresh_ttl_seconds
        self._access_ttl_seconds = access_ttl_seconds
        if redis is not None:
            self._redis = redis
            self._owns_redis = owns_redis
        else:
            self._redis = redis_from_url(redis_url)
            self._owns_redis = True
        self._legacy_clients_indexed = False
        self._legacy_clients_index_lock = asyncio.Lock()

    @property
    def redis(self) -> Redis:
        return self._redis

    def _client_key(self, client_id: str) -> str:
        return f"{self._prefix}client:{client_id}"

    def _client_index_key(self) -> str:
        # Separate namespace from `{prefix}client:{id}` keys (different
        # separator, no colon after "client_index"), so a sorted-set index
        # entry never collides with a client record key.
        return f"{self._prefix}client_index"

    def _client_unused_key(self) -> str:
        return f"{self._prefix}client_unused"

    def _access_key(self, token: str) -> str:
        return f"{self._prefix}at:{token}"

    def _refresh_key(self, token: str) -> str:
        return f"{self._prefix}rt:{token}"

    def _refresh_revoked_key(self, token: str) -> str:
        return f"{self._prefix}rt_revoked:{token}"

    def _rt_used_key(self, digest: str) -> str:
        return f"{self._prefix}rt_used:{digest}"

    def _rt_grace_key(self, digest: str) -> str:
        return f"{self._prefix}rt_grace:{digest}"

    def _subject_index_key(self, sub: str) -> str:
        return f"{self._prefix}subject:{sub}"

    def _subject_nbf_key(self, sub: str) -> str:
        return f"{self._prefix}subject_nbf:{sub}"

    def _access_iat(self, access: AccessToken) -> int | None:
        claims = access.claims or {}
        iat = claims.get("iat")
        if isinstance(iat, int):
            return iat
        if access.expires_at is not None:
            return int(access.expires_at) - self._access_ttl_seconds
        return None

    def _refresh_iat(self, refresh: RefreshToken) -> int | None:
        stored_iat = getattr(refresh, "iat", None)
        if isinstance(stored_iat, int):
            return stored_iat
        if refresh.expires_at is not None:
            # If refresh TTL was shortened after issuance, this estimate can be
            # later than the real issue time; the token may still pass nbf until
            # revoke_subject removes it from the index.
            return int(refresh.expires_at) - self._refresh_ttl_seconds
        return None

    @property
    def writes_refresh_meta(self) -> bool:
        return self._refresh_meta_key_prefix is not None

    def _refresh_meta_redis_key(self, refresh_token: str) -> str:
        assert self._refresh_meta_key_prefix is not None
        return f"{self._refresh_meta_key_prefix}{refresh_token}"

    async def _subject_nbf(self, sub: str) -> int | None:
        raw = await self._redis.get(self._subject_nbf_key(sub))
        if raw is None:
            return None
        return int(raw)

    async def _token_rejected_by_nbf(self, sub: str, iat: int | None) -> bool:
        if iat is None:
            return False
        nbf = await self._subject_nbf(sub)
        return nbf is not None and iat < nbf

    async def _prune_subject_index(self, sub: str) -> None:
        key = self._subject_index_key(sub)
        if await self._redis.scard(key) <= _SUBJECT_INDEX_MAX_MEMBERS:
            return
        members = list(await self._redis.smembers(key))
        if not members:
            return
        async with self._redis.pipeline(transaction=False) as pipe:
            for member in members:
                if member.startswith("at:"):
                    pipe.exists(self._access_key(member[3:]))
                elif member.startswith("rt:"):
                    pipe.exists(self._refresh_key(member[3:]))
                else:
                    pipe.exists("__keystone_no_such_key__")
            exists_flags = await pipe.execute()
        dead = [m for m, ok in zip(members, exists_flags, strict=True) if not ok]
        if dead:
            await self._redis.srem(key, *dead)

    @staticmethod
    def _access_ttl(access: AccessToken) -> int | None:
        if access.expires_at is None:
            return None
        ttl = int(access.expires_at - time.time())
        return ttl if ttl > 0 else 1

    def _token_key(self, kind: str, ref: str) -> str:
        if kind == "access":
            return self._access_key(ref)
        if kind == "refresh":
            return self._refresh_key(ref)
        raise ValueError(f"unknown token kind {kind!r}")

    def _index_member_prefix(self, kind: str) -> str:
        return "at:" if kind == "access" else "rt:"

    async def _load_with_migration(self, kind: str, bearer: str) -> str | None:
        digest = token_digest(bearer)
        hash_key = self._token_key(kind, digest)
        raw = await self._redis.get(hash_key)
        if raw is not None:
            return raw
        plain_key = self._token_key(kind, bearer)
        for _attempt in range(_COMMIT_MAX_WATCH_RETRIES):
            raw = await self._redis.get(plain_key)
            if raw is None:
                return await self._redis.get(hash_key)
            pttl = await self._redis.pttl(plain_key)
            if pttl == 0:
                return None
            if kind == "access":
                model = AccessToken.model_validate_json(raw)
                stored = model.model_copy(update={"token": digest})
                payload = stored.model_dump_json()
                subject = model.subject
            else:
                model = KeystoneRefreshToken.model_validate_json(raw)
                stored = model.model_copy(update={"token": digest})
                payload = stored.model_dump_json()
                subject = model.subject
            idx_key = self._subject_index_key(_subject_key(subject)) if subject else None
            member_prefix = self._index_member_prefix(kind)
            revoked_plain = self._refresh_revoked_key(bearer) if kind == "refresh" else None
            revoked_hash = self._refresh_revoked_key(digest) if kind == "refresh" else None
            meta_plain = (
                self._refresh_meta_redis_key(bearer)
                if kind == "refresh" and self.writes_refresh_meta
                else None
            )
            meta_hash = (
                self._refresh_meta_redis_key(digest)
                if kind == "refresh" and self.writes_refresh_meta
                else None
            )
            revoked_pttl: int | None = None
            if revoked_plain is not None and await self._redis.exists(revoked_plain):
                revoked_pttl = await self._redis.pttl(revoked_plain)
            meta_raw: str | None = None
            meta_pttl: int | None = None
            if meta_plain is not None:
                meta_raw = await self._redis.get(meta_plain)
                if meta_raw is not None:
                    meta_pttl = await self._redis.pttl(meta_plain)
            watch_keys = [plain_key]
            if revoked_plain is not None and revoked_pttl is not None and revoked_pttl != 0:
                watch_keys.append(revoked_plain)
            if meta_plain is not None and meta_raw is not None and meta_pttl != 0:
                watch_keys.append(meta_plain)
            try:
                async with self._redis.pipeline() as pipe:
                    await pipe.watch(*watch_keys)
                    if await self._redis.get(plain_key) is None:
                        await pipe.unwatch()
                        return await self._redis.get(hash_key)
                    pipe.multi()
                    if pttl > 0:
                        pipe.set(hash_key, payload, px=pttl)
                    else:
                        pipe.set(hash_key, payload)
                    pipe.delete(plain_key)
                    if idx_key is not None:
                        pipe.srem(idx_key, f"{member_prefix}{bearer}")
                        pipe.sadd(idx_key, f"{member_prefix}{digest}")
                        pipe.expire(idx_key, self._client_ttl_seconds)
                    if (
                        kind == "refresh"
                        and revoked_plain is not None
                        and revoked_hash is not None
                        and revoked_pttl is not None
                        and revoked_pttl != 0
                    ):
                        if revoked_pttl > 0:
                            pipe.set(revoked_hash, "1", px=revoked_pttl)
                        else:
                            pipe.set(revoked_hash, "1")
                        pipe.delete(revoked_plain)
                    if (
                        kind == "refresh"
                        and meta_plain is not None
                        and meta_hash is not None
                        and meta_raw is not None
                        and meta_pttl != 0
                    ):
                        if meta_pttl is not None and meta_pttl > 0:
                            pipe.set(meta_hash, meta_raw, px=meta_pttl)
                        else:
                            pipe.set(meta_hash, meta_raw)
                        pipe.delete(meta_plain)
                    await pipe.execute()
                    record_oauth_token_key_migration(kind=kind, direction="to_hashed")
                    return payload
            except WatchError:
                cached = await self._redis.get(hash_key)
                if cached is not None:
                    return cached
                continue
        return await self._redis.get(hash_key)

    async def _delete_access_suffix(self, suffix: str) -> None:
        key = self._access_key(suffix)
        raw = await self._redis.get(key)
        if raw is None:
            return
        access = AccessToken.model_validate_json(raw)
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.delete(key)
            if access.subject:
                pipe.srem(self._subject_index_key(_subject_key(access.subject)), f"at:{suffix}")
            await pipe.execute()

    async def _delete_refresh_suffix(self, suffix: str) -> None:
        key = self._refresh_key(suffix)
        raw = await self._redis.get(key)
        if raw is None:
            return
        refresh = RefreshToken.model_validate_json(raw)
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.delete(key)
            if refresh.subject:
                pipe.srem(self._subject_index_key(_subject_key(refresh.subject)), f"rt:{suffix}")
            await pipe.execute()

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        key = self._client_key(client_id)
        async with self._redis.pipeline(transaction=False) as pipe:
            pipe.get(key)
            pipe.ttl(key)
            raw, ttl = await pipe.execute()
        if raw is None:
            return None
        if ttl == -1:
            # Legacy record written without a TTL: give it one now so it does
            # not live forever, and add it to the client-count index (a
            # before the registration index record predates the index entirely).
            expiry = int(time.time()) + self._client_ttl_seconds
            async with self._redis.pipeline(transaction=False) as pipe:
                pipe.expire(key, self._client_ttl_seconds)
                pipe.zadd(self._client_index_key(), {client_id: expiry})
                await pipe.execute()
        return OAuthClientInformationFull.model_validate_json(raw)

    async def put_client(self, client: OAuthClientInformationFull) -> None:
        unused_ttl = min(UNUSED_CLIENT_TTL_SECONDS, self._client_ttl_seconds)
        now = time.time()
        expiry = int(now) + unused_ttl
        async with self._redis.pipeline(transaction=False) as pipe:
            pipe.set(
                self._client_key(client.client_id),
                client.model_dump_json(),
                ex=unused_ttl,
            )
            pipe.zadd(self._client_index_key(), {client.client_id: expiry})
            pipe.zadd(self._client_unused_key(), {client.client_id: now})
            await pipe.execute()

    async def touch_client(self, client_id: str) -> None:
        key = self._client_key(client_id)
        existed = await self._redis.expire(key, self._client_ttl_seconds)
        if not existed:
            return
        expiry = int(time.time()) + self._client_ttl_seconds
        async with self._redis.pipeline(transaction=False) as pipe:
            pipe.zadd(self._client_index_key(), {client_id: expiry})
            pipe.zrem(self._client_unused_key(), client_id)
            await pipe.execute()

    async def index_legacy_clients(self) -> int:
        pattern = f"{self._prefix}client:*"
        client_key_prefix = f"{self._prefix}client:"
        indexed = 0
        scanned = 0
        cursor = 0
        while True:
            cursor, keys = await self._redis.scan(cursor, match=pattern, count=500)
            if keys:
                scanned += len(keys)
                async with self._redis.pipeline(transaction=False) as pipe:
                    for key in keys:
                        pipe.ttl(key)
                    ttls = await pipe.execute()
                expiry = int(time.time()) + self._client_ttl_seconds
                async with self._redis.pipeline(transaction=False) as pipe:
                    batch = 0
                    for key, ttl in zip(keys, ttls, strict=True):
                        if ttl != -1 or not key.startswith(client_key_prefix):
                            continue
                        client_id = key[len(client_key_prefix) :]
                        pipe.expire(key, self._client_ttl_seconds)
                        pipe.zadd(self._client_index_key(), {client_id: expiry})
                        batch += 1
                    if batch:
                        await pipe.execute()
                        indexed += batch
            if scanned >= _LEGACY_CLIENT_SCAN_LIMIT:
                logger.warning(
                    "client index backfill stopped after %d keys; the rest is indexed on read",
                    scanned,
                )
                break
            if cursor == 0:
                break
        if indexed > 0:
            logger.info("indexed %d OAuth client records written before 0.4.0", indexed)
        return indexed

    async def count_clients(self) -> int:
        if not self._legacy_clients_indexed:
            async with self._legacy_clients_index_lock:
                if not self._legacy_clients_indexed:
                    try:
                        await self.index_legacy_clients()
                        self._legacy_clients_indexed = True
                    except RedisError as exc:
                        logger.warning("OAuth client legacy index backfill failed: %s", exc)
        index_key = self._client_index_key()
        unused_key = self._client_unused_key()
        now = int(time.time())
        unused_cutoff = time.time() - UNUSED_CLIENT_TTL_SECONDS
        async with self._redis.pipeline(transaction=False) as pipe:
            pipe.zremrangebyscore(unused_key, "-inf", unused_cutoff)
            pipe.zremrangebyscore(index_key, "-inf", now)
            pipe.zcard(index_key)
            _u, _i, count = await pipe.execute()
        return int(count)

    async def evict_unused_client(self) -> str | None:
        unused_key = self._client_unused_key()
        index_key = self._client_index_key()
        for _ in range(10):
            popped = await self._redis.zpopmin(unused_key, count=1)
            if not popped:
                return None
            client_id = popped[0][0]
            deleted = await self._redis.delete(self._client_key(client_id))
            await self._redis.zrem(index_key, client_id)
            if deleted:
                return client_id
        return None

    async def get_access_token(self, token: str) -> AccessToken | None:
        with _trace_redis_operation("get_access_token"):
            raw = await self._load_with_migration("access", token)
            if raw is None:
                return None
            access = AccessToken.model_validate_json(raw)
            ref = token_digest(token)
            if access.expires_at is not None and access.expires_at < time.time():
                await self.delete_access_token(token)
                return None
            if access.subject:
                sub = _subject_key(access.subject)
                iat = self._access_iat(access)
                if await self._token_rejected_by_nbf(sub, iat):
                    await self.delete_access_token(token)
                    return None
                claims = access.claims or {}
                if "iat" not in claims and iat is not None:
                    claims = {**claims, "iat": iat}
                    access = access.model_copy(update={"claims": claims})
                    await self._redis.set(
                        self._access_key(ref), access.model_dump_json(), keepttl=True
                    )
                idx = self._subject_index_key(sub)
                async with self._redis.pipeline(transaction=True) as pipe:
                    pipe.sadd(idx, f"at:{ref}")
                    pipe.expire(idx, self._client_ttl_seconds)
                    await pipe.execute()
            return access.model_copy(update={"token": token})

    async def put_access_token(self, access: AccessToken) -> None:
        ref = token_digest(access.token)
        stored = access.model_copy(update={"token": ref})
        ttl = self._access_ttl(access)
        payload = stored.model_dump_json()
        key = self._access_key(ref)
        sub = access.subject
        norm = _subject_key(sub) if sub else None
        async with self._redis.pipeline(transaction=True) as pipe:
            if ttl is None:
                pipe.set(key, payload)
            else:
                pipe.set(key, payload, ex=ttl)
            if norm:
                idx = self._subject_index_key(norm)
                pipe.sadd(idx, f"at:{ref}")
                pipe.expire(idx, self._client_ttl_seconds)
            await pipe.execute()
        if norm:
            await self._prune_subject_index(norm)

    async def delete_access_token(self, token: str) -> None:
        if token.startswith("km_at_"):
            await self._delete_access_suffix(token_digest(token))
        await self._delete_access_suffix(token)

    async def get_refresh_token(self, token: str) -> RefreshToken | None:
        with _trace_redis_operation("get_refresh_token"):
            return await self._get_refresh_token_inner(token)

    async def _get_refresh_token_inner(self, token: str) -> RefreshToken | None:
        raw = await self._load_with_migration("refresh", token)
        if raw is None:
            return None
        ref = token_digest(token)
        key = self._refresh_key(ref)
        ttl = await self._redis.ttl(key)
        refresh = KeystoneRefreshToken.model_validate_json(raw)
        if ttl == -1:
            if refresh.expires_at is not None:
                if refresh.expires_at < time.time():
                    await self._redis.delete(key)
                    return None
                await self._redis.expireat(key, int(refresh.expires_at))
            else:
                await self._redis.expire(key, self._refresh_ttl_seconds)
        if refresh.subject:
            sub = _subject_key(refresh.subject)
            iat = self._refresh_iat(refresh)
            if await self._token_rejected_by_nbf(sub, iat):
                await self.delete_refresh_token(token)
                return None
            idx = self._subject_index_key(sub)
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.sadd(idx, f"rt:{ref}")
                pipe.expire(idx, self._client_ttl_seconds)
                await pipe.execute()
        return refresh.model_copy(update={"token": token})

    async def put_refresh_token(self, refresh: RefreshToken) -> None:
        ref = token_digest(refresh.token)
        stored = refresh.model_copy(update={"token": ref})
        if refresh.expires_at is None:
            ttl = self._refresh_ttl_seconds
        else:
            ttl = int(refresh.expires_at - time.time())
            ttl = ttl if ttl > 0 else 1
        key = self._refresh_key(ref)
        payload = stored.model_dump_json()
        sub = refresh.subject
        norm = _subject_key(sub) if sub else None
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.set(key, payload, ex=ttl)
            if norm:
                idx = self._subject_index_key(norm)
                pipe.sadd(idx, f"rt:{ref}")
                pipe.expire(idx, self._client_ttl_seconds)
            await pipe.execute()
        if norm:
            await self._prune_subject_index(norm)

    async def delete_refresh_token(self, token: str) -> None:
        if token.startswith("km_rt_"):
            await self._delete_refresh_suffix(token_digest(token))
        await self._delete_refresh_suffix(token)

    async def revoke_subject(self, subject: str, *, now: int) -> RevokedTokens:
        with _trace_redis_operation("revoke_subject"):
            return await self._revoke_subject_inner(subject, now=now)

    async def _revoke_subject_inner(self, subject: str, *, now: int) -> RevokedTokens:
        sub = _subject_key(subject)
        idx_key = self._subject_index_key(sub)
        nbf_key = self._subject_nbf_key(sub)
        await self._redis.set(nbf_key, str(now), ex=self._client_ttl_seconds)
        members = await self._redis.smembers(idx_key)
        access_count = 0
        refresh_tokens: list[str] = []
        if members:
            async with self._redis.pipeline(transaction=True) as pipe:
                for member in members:
                    if member.startswith("at:"):
                        tok = member[3:]
                        pipe.delete(self._access_key(tok))
                        access_count += 1
                    elif member.startswith("rt:"):
                        tok = member[3:]
                        pipe.delete(self._refresh_key(tok))
                        refresh_tokens.append(tok)
                pipe.delete(idx_key)
                await pipe.execute()
        return RevokedTokens(access=access_count, refresh_tokens=tuple(refresh_tokens))

    async def revoke_client_tokens(self, subject: str, client_id: str) -> int:
        with _trace_redis_operation("revoke_client_tokens"):
            return await self._revoke_client_tokens_inner(subject, client_id)

    async def _revoke_client_tokens_inner(self, subject: str, client_id: str) -> int:
        sub = _subject_key(subject)
        idx_key = self._subject_index_key(sub)
        members = await self._redis.smembers(idx_key)
        to_delete: list[tuple[str, str]] = []
        for member in members:
            if not member.startswith("at:"):
                continue
            tok = member[3:]
            raw = await self._redis.get(self._access_key(tok))
            if raw is None:
                continue
            access = AccessToken.model_validate_json(raw)
            if access.client_id != client_id:
                continue
            to_delete.append((tok, member))
        if not to_delete:
            return 0
        async with self._redis.pipeline(transaction=True) as pipe:
            for tok, member in to_delete:
                pipe.delete(self._access_key(tok))
                pipe.srem(idx_key, member)
            await pipe.execute()
        return len(to_delete)

    async def revoke_refresh_grant(self, subject: str, client_id: str, refresh_token: str) -> None:
        sub = _subject_key(subject)
        idx_key = self._subject_index_key(sub)
        ref = token_digest(refresh_token)
        rt_key = self._refresh_key(ref)
        rt_legacy = self._refresh_key(refresh_token)
        revoked_key = self._refresh_revoked_key(ref)
        revoked_legacy = self._refresh_revoked_key(refresh_token)

        raw = await self._redis.get(rt_key)
        if raw is None:
            raw = await self._redis.get(rt_legacy)
        if raw is None:
            await self.revoke_client_tokens(subject, client_id)
            if not await self._redis.exists(revoked_key) and not await self._redis.exists(
                revoked_legacy
            ):
                await self._redis.set(revoked_key, "1", ex=self._refresh_ttl_seconds)
            return

        refresh = RefreshToken.model_validate_json(raw)
        if refresh.client_id != client_id:
            return

        if refresh.expires_at is None:
            revoked_ttl = self._refresh_ttl_seconds
        else:
            revoked_ttl = max(int(refresh.expires_at - time.time()), 1)

        members = await self._redis.smembers(idx_key)
        to_delete: list[tuple[str, str]] = []
        for member in members:
            if not member.startswith("at:"):
                continue
            tok = member[3:]
            at_raw = await self._redis.get(self._access_key(tok))
            if at_raw is None:
                continue
            access = AccessToken.model_validate_json(at_raw)
            if access.client_id != client_id:
                continue
            to_delete.append((tok, member))

        for _attempt in range(_COMMIT_MAX_WATCH_RETRIES):
            try:
                async with self._redis.pipeline() as pipe:
                    await pipe.watch(rt_key, rt_legacy)
                    pipe.multi()
                    for tok, member in to_delete:
                        pipe.delete(self._access_key(tok))
                        pipe.srem(idx_key, member)
                    pipe.set(revoked_key, "1", ex=revoked_ttl)
                    pipe.delete(rt_key)
                    pipe.delete(rt_legacy)
                    pipe.srem(idx_key, f"rt:{ref}")
                    pipe.srem(idx_key, f"rt:{refresh_token}")
                    await pipe.execute()
                    return
            except WatchError:
                continue

        raise CredentialRevokedError()

    def refresh_credential_iat(self, refresh: RefreshToken) -> int | None:
        return self._refresh_iat(refresh)

    def _pipe_put_access(self, pipe: object, access: AccessToken) -> None:
        ref = token_digest(access.token)
        stored = access.model_copy(update={"token": ref})
        ttl = self._access_ttl(access)
        key = self._access_key(ref)
        payload = stored.model_dump_json()
        if ttl is None:
            pipe.set(key, payload)
        else:
            pipe.set(key, payload, ex=ttl)
        if access.subject:
            sub = _subject_key(access.subject)
            idx = self._subject_index_key(sub)
            pipe.sadd(idx, f"at:{ref}")
            pipe.expire(idx, self._client_ttl_seconds)

    def _pipe_put_refresh(self, pipe: object, refresh: RefreshToken) -> None:
        ref = token_digest(refresh.token)
        stored = refresh.model_copy(update={"token": ref})
        if refresh.expires_at is None:
            ttl = self._refresh_ttl_seconds
        else:
            ttl = int(refresh.expires_at - time.time())
            ttl = ttl if ttl > 0 else 1
        key = self._refresh_key(ref)
        pipe.set(key, stored.model_dump_json(), ex=ttl)
        if refresh.subject:
            sub = _subject_key(refresh.subject)
            idx = self._subject_index_key(sub)
            pipe.sadd(idx, f"rt:{ref}")
            pipe.expire(idx, self._client_ttl_seconds)

    def _pipe_delete_refresh(self, pipe: object, token: str, subject: str | None) -> None:
        ref = token_digest(token)
        pipe.delete(self._refresh_key(ref))
        pipe.delete(self._refresh_key(token))
        if subject:
            idx = self._subject_index_key(_subject_key(subject))
            pipe.srem(idx, f"rt:{ref}")
            pipe.srem(idx, f"rt:{token}")

    def _pipe_put_refresh_meta(
        self, pipe: object, refresh_token: str, payload: str, ttl: int
    ) -> None:
        key = self._refresh_meta_redis_key(token_digest(refresh_token))
        pipe.set(key, payload, ex=ttl)

    async def commit_token_pair(
        self,
        *,
        subject: str,
        consumed_iat: int | None,
        access: AccessToken,
        refresh: RefreshToken,
        replace_refresh_token: str | None = None,
        refresh_meta: str | None = None,
        rotation: RotationRecord | None = None,
    ) -> None:
        with _trace_redis_operation("commit_token_pair"):
            await self._commit_token_pair_inner(
                subject=subject,
                consumed_iat=consumed_iat,
                access=access,
                refresh=refresh,
                replace_refresh_token=replace_refresh_token,
                refresh_meta=refresh_meta,
                rotation=rotation,
            )

    async def _commit_token_pair_inner(
        self,
        *,
        subject: str,
        consumed_iat: int | None,
        access: AccessToken,
        refresh: RefreshToken,
        replace_refresh_token: str | None = None,
        refresh_meta: str | None = None,
        rotation: RotationRecord | None = None,
    ) -> None:
        sub = _subject_key(subject)
        nbf_key = self._subject_nbf_key(sub)
        replace_ref = token_digest(replace_refresh_token) if replace_refresh_token else None
        revoked_key = self._refresh_revoked_key(replace_ref) if replace_ref else None
        revoked_legacy = (
            self._refresh_revoked_key(replace_refresh_token) if replace_refresh_token else None
        )
        rt_key = self._refresh_key(replace_ref) if replace_ref else None
        rt_legacy = self._refresh_key(replace_refresh_token) if replace_refresh_token else None
        old_refresh_subject = subject if replace_refresh_token else None
        meta_ttl: int | None = None
        if refresh_meta is not None and self.writes_refresh_meta:
            if refresh.expires_at is None:
                meta_ttl = self._refresh_ttl_seconds
            else:
                meta_ttl = int(refresh.expires_at - time.time())
                meta_ttl = meta_ttl if meta_ttl > 0 else 1

        for _attempt in range(_COMMIT_MAX_WATCH_RETRIES):
            async with self._redis.pipeline() as pipe:
                watch_keys = [nbf_key]
                if revoked_key is not None:
                    watch_keys.append(revoked_key)
                if revoked_legacy is not None:
                    watch_keys.append(revoked_legacy)
                if rt_key is not None:
                    watch_keys.append(rt_key)
                if rt_legacy is not None:
                    watch_keys.append(rt_legacy)
                await pipe.watch(*watch_keys)
                if replace_refresh_token is not None and not (
                    await self._redis.exists(rt_key) or await self._redis.exists(rt_legacy)
                ):
                    await pipe.unwatch()
                    raise RefreshTokenAlreadyRotatedError()
                nbf_raw = await self._redis.get(nbf_key)
                nbf = int(nbf_raw) if nbf_raw is not None else None
                if nbf is not None and (consumed_iat is None or consumed_iat <= nbf):
                    await pipe.unwatch()
                    if replace_refresh_token is not None:
                        await self.delete_refresh_token(replace_refresh_token)
                    raise CredentialRevokedError()
                if revoked_key is not None and (
                    await self._redis.exists(revoked_key)
                    or (revoked_legacy is not None and await self._redis.exists(revoked_legacy))
                ):
                    await pipe.unwatch()
                    raise CredentialRevokedError()
                pipe.multi()
                self._pipe_put_access(pipe, access)
                self._pipe_put_refresh(pipe, refresh)
                if refresh_meta is not None and meta_ttl is not None:
                    self._pipe_put_refresh_meta(pipe, refresh.token, refresh_meta, meta_ttl)
                if replace_refresh_token is not None:
                    digest = token_digest(replace_refresh_token)
                    if rotation is not None:
                        used_ttl = max(rotation.used_ttl, 1)
                        pipe.set(self._rt_used_key(digest), rotation.used_json, ex=used_ttl)
                        if rotation.grace_blob is not None and rotation.grace_ttl > 0:
                            pipe.set(
                                self._rt_grace_key(digest),
                                rotation.grace_blob,
                                ex=rotation.grace_ttl,
                            )
                        if (
                            rotation.old_meta is not None
                            and self.writes_refresh_meta
                            and rotation.old_meta_ttl > 0
                        ):
                            self._pipe_put_refresh_meta(
                                pipe,
                                replace_refresh_token,
                                rotation.old_meta,
                                rotation.old_meta_ttl,
                            )
                    self._pipe_delete_refresh(pipe, replace_refresh_token, old_refresh_subject)
                try:
                    await pipe.execute()
                    return
                except WatchError:
                    continue
        if replace_refresh_token is not None:
            if not (await self._redis.exists(rt_key) or await self._redis.exists(rt_legacy)):
                raise RefreshTokenAlreadyRotatedError()
            await self.delete_refresh_token(replace_refresh_token)
        raise CredentialRevokedError()

    async def get_rotated_refresh(self, token: str) -> RotatedRefresh | None:
        raw = await self._redis.get(self._rt_used_key(token_digest(token)))
        if raw is None:
            return None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return RotatedRefresh(
            subject=data["subject"],
            client_id=data["client_id"],
            scopes=list(data.get("scopes") or []),
            expires_at=data.get("expires_at"),
            resource=data.get("resource"),
            rotated_at=int(data["rotated_at"]),
        )

    async def get_refresh_grace(self, token: str) -> str | None:
        return await self._redis.get(self._rt_grace_key(token_digest(token)))

    async def subject_tokens(
        self, subject: str
    ) -> tuple[list[AccessToken], list[KeystoneRefreshToken]]:
        sub = _subject_key(subject)
        idx_key = self._subject_index_key(sub)
        members = await self._redis.smembers(idx_key)
        access_out: list[AccessToken] = []
        refresh_out: list[KeystoneRefreshToken] = []
        for member in members:
            if member.startswith("at:"):
                tok = member[3:]
                raw = await self._redis.get(self._access_key(tok))
                if raw is not None:
                    access_out.append(AccessToken.model_validate_json(raw))
            elif member.startswith("rt:"):
                tok = member[3:]
                raw = await self._redis.get(self._refresh_key(tok))
                if raw is not None:
                    refresh_out.append(KeystoneRefreshToken.model_validate_json(raw))
        return access_out, refresh_out

    async def revoke_tokens(
        self, subject: str, *, access: Sequence[str], refresh: Sequence[str]
    ) -> RevokedTokens:
        sub = _subject_key(subject)
        idx_key = self._subject_index_key(sub)
        access_to_drop: list[str] = []
        for tok in access:
            if await self._redis.exists(self._access_key(tok)):
                access_to_drop.append(tok)
        refresh_to_drop: list[tuple[str, int]] = []
        for tok in refresh:
            rt_key = self._refresh_key(tok)
            raw = await self._redis.get(rt_key)
            if raw is None:
                continue
            stored = RefreshToken.model_validate_json(raw)
            if stored.expires_at is None:
                revoked_ttl = self._refresh_ttl_seconds
            else:
                revoked_ttl = max(int(stored.expires_at - time.time()), 1)
            refresh_to_drop.append((tok, revoked_ttl))
        if not access_to_drop and not refresh_to_drop:
            return RevokedTokens(access=0, refresh_tokens=())
        async with self._redis.pipeline(transaction=True) as pipe:
            for tok in access_to_drop:
                pipe.delete(self._access_key(tok))
                pipe.srem(idx_key, f"at:{tok}")
            for tok, revoked_ttl in refresh_to_drop:
                pipe.set(self._refresh_revoked_key(tok), "1", ex=revoked_ttl)
                pipe.delete(self._refresh_key(tok))
                pipe.srem(idx_key, f"rt:{tok}")
            await pipe.execute()
        return RevokedTokens(
            access=len(access_to_drop),
            refresh_tokens=tuple(tok for tok, _ in refresh_to_drop),
        )

    async def subject_not_before(self, subject: str) -> int | None:
        return await self._subject_nbf(_subject_key(subject))

    async def aclose(self) -> None:
        if self._owns_redis:
            await self._redis.aclose()


def build_oauth_store(settings: object) -> OAuthStore:
    """Construct the OAuth store from settings (Redis required outside tests)."""
    redis_url = getattr(settings, "redis_url", "").strip()
    if not redis_url:
        raise RuntimeError(
            "KEYSTONE_MCP_REDIS_URL is required for OAuth session persistence. "
            "Set it to the shared keystone Redis (e.g. redis://redis:6379/0)."
        )
    from keystone_mcp.auth.login_pending_store import normalize_login_key_prefix

    prefix = getattr(settings, "redis_key_prefix", "km:oauth:")
    login_prefix = normalize_login_key_prefix(
        getattr(settings, "login_pending_key_prefix", "km:login:")
    )
    return RedisOAuthStore(
        redis_url,
        key_prefix=prefix,
        client_ttl_seconds=client_ttl_seconds(settings),
        refresh_ttl_seconds=getattr(settings, "refresh_token_ttl_seconds", 30 * 86400),
        access_ttl_seconds=getattr(settings, "token_cache_ttl_seconds", 3600),
        refresh_meta_key_prefix=f"{login_prefix}refresh_auth:",
    )


def build_shared_auth_stores(settings: object) -> tuple[OAuthStore, object]:
    """Build OAuth and login-pending stores sharing one Redis connection pool."""
    from keystone_mcp.auth.login_pending_store import (
        RedisLoginPendingStore,
        normalize_login_key_prefix,
    )

    redis_url = getattr(settings, "redis_url", "").strip()
    if not redis_url:
        raise RuntimeError(
            "KEYSTONE_MCP_REDIS_URL is required for OAuth session persistence. "
            "Set it to the shared keystone Redis (e.g. redis://redis:6379/0)."
        )

    redis = redis_from_url(redis_url)
    oauth_prefix = getattr(settings, "redis_key_prefix", "km:oauth:")
    login_prefix = normalize_login_key_prefix(
        getattr(settings, "login_pending_key_prefix", "km:login:")
    )
    oauth_store = RedisOAuthStore(
        redis_url,
        key_prefix=oauth_prefix,
        redis=redis,
        owns_redis=True,
        client_ttl_seconds=client_ttl_seconds(settings),
        refresh_ttl_seconds=getattr(settings, "refresh_token_ttl_seconds", 30 * 86400),
        access_ttl_seconds=getattr(settings, "token_cache_ttl_seconds", 3600),
        refresh_meta_key_prefix=f"{login_prefix}refresh_auth:",
    )
    login_store = RedisLoginPendingStore(
        redis,
        key_prefix=login_prefix,
        owns_redis=False,
    )
    return oauth_store, login_store
