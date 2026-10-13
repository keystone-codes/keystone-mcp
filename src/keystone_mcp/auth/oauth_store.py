"""Persistent OAuth session store (clients, access tokens, refresh tokens).

Production uses the deployment's Redis; tests inject
:class:`InMemoryOAuthStore`.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from mcp.server.auth.provider import AccessToken, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull
from redis.asyncio import Redis
from redis.exceptions import WatchError

from keystone_mcp.user_directory.util import normalize_email

_SUBJECT_INDEX_MAX_MEMBERS = 256
_COMMIT_MAX_WATCH_RETRIES = 16


@dataclass(frozen=True, slots=True)
class RevokedTokens:
    access: int
    refresh_tokens: tuple[str, ...]


class CredentialRevokedError(Exception):
    """Consumed credential was issued at or before the subject's not-before time."""


def _subject_key(subject: str) -> str:
    if subject.startswith("svc:"):
        return subject
    return normalize_email(subject)


# Margin added on top of the longer of the refresh-token and access-token
# lifetimes to compute how long a registered client is kept in Redis. The
# margin absorbs the gap between a token's expiry and the client's last use.
CLIENT_TTL_MARGIN_SECONDS = 86400


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

    async def commit_token_pair(
        self,
        *,
        subject: str,
        consumed_iat: int | None,
        access: AccessToken,
        refresh: RefreshToken,
        replace_refresh_token: str | None = None,
    ) -> None: ...

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
        self._clients[client.client_id] = client
        self._client_expires_at[client.client_id] = time.time() + self._client_ttl_seconds

    async def touch_client(self, client_id: str) -> None:
        if client_id not in self._clients:
            return
        self._client_expires_at[client_id] = time.time() + self._client_ttl_seconds

    async def count_clients(self) -> int:
        now = time.time()
        expired = [
            client_id
            for client_id, expires_at in self._client_expires_at.items()
            if expires_at < now
        ]
        for client_id in expired:
            self._clients.pop(client_id, None)
            self._client_expires_at.pop(client_id, None)
        return len(self._clients)

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
        if refresh.expires_at is not None:
            return int(refresh.expires_at) - self._refresh_ttl_seconds
        return None

    def _reject_if_before_nbf(self, sub: str, iat: int | None) -> bool:
        if iat is None:
            return False
        if not self._subject_index_alive(sub):
            return False
        nbf = self._subject_nbf.get(sub)
        return nbf is not None and iat < nbf

    async def get_access_token(self, token: str) -> AccessToken | None:
        access = self._access_tokens.get(token)
        if access is None:
            return None
        if access.expires_at is not None and access.expires_at < time.time():
            self._access_tokens.pop(token, None)
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
                access = AccessToken(
                    token=access.token,
                    client_id=access.client_id,
                    scopes=access.scopes,
                    expires_at=access.expires_at,
                    resource=access.resource,
                    subject=access.subject,
                    claims=claims,
                )
                self._access_tokens[token] = access
            self._add_subject_member(norm, f"at:{token}")
        return access

    async def put_access_token(self, access: AccessToken) -> None:
        self._access_tokens[access.token] = access
        if access.subject:
            self._add_subject_member(_subject_key(access.subject), f"at:{access.token}")

    async def delete_access_token(self, token: str) -> None:
        access = self._access_tokens.pop(token, None)
        if access is not None and access.subject:
            self._remove_subject_member(_subject_key(access.subject), f"at:{token}")

    async def get_refresh_token(self, token: str) -> RefreshToken | None:
        refresh = self._refresh_tokens.get(token)
        if refresh is None:
            return None
        expires_at = self._refresh_expires_at.get(token)
        if expires_at is not None and expires_at < time.time():
            self._refresh_tokens.pop(token, None)
            self._refresh_expires_at.pop(token, None)
            return None
        if refresh.subject:
            norm = _subject_key(refresh.subject)
            iat = self._refresh_iat(refresh)
            if self._reject_if_before_nbf(norm, iat):
                await self.delete_refresh_token(token)
                return None
            self._add_subject_member(norm, f"rt:{token}")
        return refresh

    async def put_refresh_token(self, refresh: RefreshToken) -> None:
        self._refresh_tokens[refresh.token] = refresh
        if refresh.expires_at is not None:
            ttl = max(refresh.expires_at - time.time(), 1)
        else:
            ttl = self._refresh_ttl_seconds
        self._refresh_expires_at[refresh.token] = time.time() + ttl
        if refresh.subject:
            self._add_subject_member(_subject_key(refresh.subject), f"rt:{refresh.token}")

    async def delete_refresh_token(self, token: str) -> None:
        refresh = self._refresh_tokens.pop(token, None)
        self._refresh_expires_at.pop(token, None)
        if refresh is not None and refresh.subject:
            self._remove_subject_member(_subject_key(refresh.subject), f"rt:{token}")

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
            self._refresh_revoked.add(refresh_token)
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

    async def commit_token_pair(
        self,
        *,
        subject: str,
        consumed_iat: int | None,
        access: AccessToken,
        refresh: RefreshToken,
        replace_refresh_token: str | None = None,
    ) -> None:
        sub = _subject_key(subject)
        async with self._commit_lock:
            if self._credential_revoked_by_nbf(sub, consumed_iat):
                if replace_refresh_token is not None:
                    await self.delete_refresh_token(replace_refresh_token)
                raise CredentialRevokedError()
            if replace_refresh_token is not None and replace_refresh_token in self._refresh_revoked:
                raise CredentialRevokedError()
            await self.put_access_token(access)
            await self.put_refresh_token(refresh)
            if replace_refresh_token is not None:
                await self.delete_refresh_token(replace_refresh_token)

    async def aclose(self) -> None:
        return None


class RedisOAuthStore:
    """OAuth sessions in shared Redis (key prefix isolates from backend keys)."""

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
    ) -> None:
        prefix = key_prefix if key_prefix.endswith(":") else f"{key_prefix}:"
        self._prefix = prefix
        self._client_ttl_seconds = client_ttl_seconds
        self._refresh_ttl_seconds = refresh_ttl_seconds
        self._access_ttl_seconds = access_ttl_seconds
        if redis is not None:
            self._redis = redis
            self._owns_redis = owns_redis
        else:
            self._redis = Redis.from_url(redis_url, decode_responses=True)
            self._owns_redis = True

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

    def _access_key(self, token: str) -> str:
        return f"{self._prefix}at:{token}"

    def _refresh_key(self, token: str) -> str:
        return f"{self._prefix}rt:{token}"

    def _refresh_revoked_key(self, token: str) -> str:
        return f"{self._prefix}rt_revoked:{token}"

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
        if refresh.expires_at is not None:
            # If refresh TTL was shortened after issuance, this estimate can be
            # later than the real issue time; the token may still pass nbf until
            # revoke_subject removes it from the index.
            return int(refresh.expires_at) - self._refresh_ttl_seconds
        return None

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
            # pre-A12 record predates the index entirely).
            expiry = int(time.time()) + self._client_ttl_seconds
            async with self._redis.pipeline(transaction=False) as pipe:
                pipe.expire(key, self._client_ttl_seconds)
                pipe.zadd(self._client_index_key(), {client_id: expiry})
                await pipe.execute()
        return OAuthClientInformationFull.model_validate_json(raw)

    async def put_client(self, client: OAuthClientInformationFull) -> None:
        expiry = int(time.time()) + self._client_ttl_seconds
        async with self._redis.pipeline(transaction=False) as pipe:
            pipe.set(
                self._client_key(client.client_id),
                client.model_dump_json(),
                ex=self._client_ttl_seconds,
            )
            pipe.zadd(self._client_index_key(), {client.client_id: expiry})
            await pipe.execute()

    async def touch_client(self, client_id: str) -> None:
        key = self._client_key(client_id)
        existed = await self._redis.expire(key, self._client_ttl_seconds)
        if not existed:
            return
        expiry = int(time.time()) + self._client_ttl_seconds
        await self._redis.zadd(self._client_index_key(), {client_id: expiry})

    async def count_clients(self) -> int:
        index_key = self._client_index_key()
        now = int(time.time())
        async with self._redis.pipeline(transaction=False) as pipe:
            pipe.zremrangebyscore(index_key, "-inf", now)
            pipe.zcard(index_key)
            _removed, count = await pipe.execute()
        return int(count)

    async def get_access_token(self, token: str) -> AccessToken | None:
        key = self._access_key(token)
        raw = await self._redis.get(key)
        if raw is None:
            return None
        access = AccessToken.model_validate_json(raw)
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
                access = AccessToken(
                    token=access.token,
                    client_id=access.client_id,
                    scopes=access.scopes,
                    expires_at=access.expires_at,
                    resource=access.resource,
                    subject=access.subject,
                    claims=claims,
                )
                await self._redis.set(key, access.model_dump_json(), keepttl=True)
            idx = self._subject_index_key(sub)
            async with self._redis.pipeline(transaction=True) as pipe:
                pipe.sadd(idx, f"at:{token}")
                pipe.expire(idx, self._client_ttl_seconds)
                await pipe.execute()
        return access

    async def put_access_token(self, access: AccessToken) -> None:
        ttl = self._access_ttl(access)
        payload = access.model_dump_json()
        key = self._access_key(access.token)
        sub = access.subject
        norm = _subject_key(sub) if sub else None
        async with self._redis.pipeline(transaction=True) as pipe:
            if ttl is None:
                pipe.set(key, payload)
            else:
                pipe.set(key, payload, ex=ttl)
            if norm:
                idx = self._subject_index_key(norm)
                pipe.sadd(idx, f"at:{access.token}")
                pipe.expire(idx, self._client_ttl_seconds)
            await pipe.execute()
        if norm:
            await self._prune_subject_index(norm)

    async def delete_access_token(self, token: str) -> None:
        key = self._access_key(token)
        raw = await self._redis.get(key)
        if raw is None:
            return
        access = AccessToken.model_validate_json(raw)
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.delete(key)
            if access.subject:
                pipe.srem(self._subject_index_key(_subject_key(access.subject)), f"at:{token}")
            await pipe.execute()

    async def get_refresh_token(self, token: str) -> RefreshToken | None:
        key = self._refresh_key(token)
        async with self._redis.pipeline(transaction=False) as pipe:
            pipe.get(key)
            pipe.ttl(key)
            raw, ttl = await pipe.execute()
        if raw is None:
            return None
        refresh = RefreshToken.model_validate_json(raw)
        if ttl == -1:
            # Legacy record written without a TTL.
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
                pipe.sadd(idx, f"rt:{token}")
                pipe.expire(idx, self._client_ttl_seconds)
                await pipe.execute()
        return refresh

    async def put_refresh_token(self, refresh: RefreshToken) -> None:
        if refresh.expires_at is None:
            ttl = self._refresh_ttl_seconds
        else:
            ttl = int(refresh.expires_at - time.time())
            ttl = ttl if ttl > 0 else 1
        key = self._refresh_key(refresh.token)
        payload = refresh.model_dump_json()
        sub = refresh.subject
        norm = _subject_key(sub) if sub else None
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.set(key, payload, ex=ttl)
            if norm:
                idx = self._subject_index_key(norm)
                pipe.sadd(idx, f"rt:{refresh.token}")
                pipe.expire(idx, self._client_ttl_seconds)
            await pipe.execute()
        if norm:
            await self._prune_subject_index(norm)

    async def delete_refresh_token(self, token: str) -> None:
        key = self._refresh_key(token)
        raw = await self._redis.get(key)
        if raw is None:
            return
        refresh = RefreshToken.model_validate_json(raw)
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.delete(key)
            if refresh.subject:
                pipe.srem(self._subject_index_key(_subject_key(refresh.subject)), f"rt:{token}")
            await pipe.execute()

    async def revoke_subject(self, subject: str, *, now: int) -> RevokedTokens:
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
        rt_key = self._refresh_key(refresh_token)
        revoked_key = self._refresh_revoked_key(refresh_token)

        raw = await self._redis.get(rt_key)
        if raw is None:
            await self.revoke_client_tokens(subject, client_id)
            if not await self._redis.exists(revoked_key):
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
                    await pipe.watch(rt_key)
                    pipe.multi()
                    for tok, member in to_delete:
                        pipe.delete(self._access_key(tok))
                        pipe.srem(idx_key, member)
                    pipe.set(revoked_key, "1", ex=revoked_ttl)
                    pipe.delete(rt_key)
                    pipe.srem(idx_key, f"rt:{refresh_token}")
                    await pipe.execute()
                    return
            except WatchError:
                continue

        raise CredentialRevokedError()

    def refresh_credential_iat(self, refresh: RefreshToken) -> int | None:
        return self._refresh_iat(refresh)

    def _pipe_put_access(self, pipe: object, access: AccessToken) -> None:
        ttl = self._access_ttl(access)
        key = self._access_key(access.token)
        payload = access.model_dump_json()
        if ttl is None:
            pipe.set(key, payload)
        else:
            pipe.set(key, payload, ex=ttl)
        if access.subject:
            sub = _subject_key(access.subject)
            idx = self._subject_index_key(sub)
            pipe.sadd(idx, f"at:{access.token}")
            pipe.expire(idx, self._client_ttl_seconds)

    def _pipe_put_refresh(self, pipe: object, refresh: RefreshToken) -> None:
        if refresh.expires_at is None:
            ttl = self._refresh_ttl_seconds
        else:
            ttl = int(refresh.expires_at - time.time())
            ttl = ttl if ttl > 0 else 1
        key = self._refresh_key(refresh.token)
        pipe.set(key, refresh.model_dump_json(), ex=ttl)
        if refresh.subject:
            sub = _subject_key(refresh.subject)
            idx = self._subject_index_key(sub)
            pipe.sadd(idx, f"rt:{refresh.token}")
            pipe.expire(idx, self._client_ttl_seconds)

    def _pipe_delete_refresh(self, pipe: object, token: str, subject: str | None) -> None:
        pipe.delete(self._refresh_key(token))
        if subject:
            pipe.srem(self._subject_index_key(_subject_key(subject)), f"rt:{token}")

    async def commit_token_pair(
        self,
        *,
        subject: str,
        consumed_iat: int | None,
        access: AccessToken,
        refresh: RefreshToken,
        replace_refresh_token: str | None = None,
    ) -> None:
        sub = _subject_key(subject)
        nbf_key = self._subject_nbf_key(sub)
        revoked_key = (
            self._refresh_revoked_key(replace_refresh_token) if replace_refresh_token else None
        )
        old_refresh_subject = subject if replace_refresh_token else None

        for _attempt in range(_COMMIT_MAX_WATCH_RETRIES):
            async with self._redis.pipeline() as pipe:
                watch_keys = [nbf_key]
                if revoked_key is not None:
                    watch_keys.append(revoked_key)
                await pipe.watch(*watch_keys)
                nbf_raw = await self._redis.get(nbf_key)
                nbf = int(nbf_raw) if nbf_raw is not None else None
                if nbf is not None and (consumed_iat is None or consumed_iat <= nbf):
                    await pipe.unwatch()
                    if replace_refresh_token is not None:
                        await self.delete_refresh_token(replace_refresh_token)
                    raise CredentialRevokedError()
                if revoked_key is not None and await self._redis.exists(revoked_key):
                    await pipe.unwatch()
                    raise CredentialRevokedError()
                pipe.multi()
                self._pipe_put_access(pipe, access)
                self._pipe_put_refresh(pipe, refresh)
                if replace_refresh_token is not None:
                    self._pipe_delete_refresh(pipe, replace_refresh_token, old_refresh_subject)
                try:
                    await pipe.execute()
                    return
                except WatchError:
                    continue
        if replace_refresh_token is not None:
            await self.delete_refresh_token(replace_refresh_token)
        raise CredentialRevokedError()

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
    prefix = getattr(settings, "redis_key_prefix", "km:oauth:")
    return RedisOAuthStore(
        redis_url,
        key_prefix=prefix,
        client_ttl_seconds=client_ttl_seconds(settings),
        refresh_ttl_seconds=getattr(settings, "refresh_token_ttl_seconds", 30 * 86400),
        access_ttl_seconds=getattr(settings, "token_cache_ttl_seconds", 3600),
    )


def build_shared_auth_stores(settings: object) -> tuple[OAuthStore, object]:
    """Build OAuth and login-pending stores sharing one Redis connection pool."""
    from keystone_mcp.auth.login_pending_store import RedisLoginPendingStore

    redis_url = getattr(settings, "redis_url", "").strip()
    if not redis_url:
        raise RuntimeError(
            "KEYSTONE_MCP_REDIS_URL is required for OAuth session persistence. "
            "Set it to the shared keystone Redis (e.g. redis://redis:6379/0)."
        )

    redis = Redis.from_url(redis_url, decode_responses=True)
    oauth_prefix = getattr(settings, "redis_key_prefix", "km:oauth:")
    login_prefix = getattr(settings, "login_pending_key_prefix", "km:login:")
    oauth_store = RedisOAuthStore(
        redis_url,
        key_prefix=oauth_prefix,
        redis=redis,
        owns_redis=True,
        client_ttl_seconds=client_ttl_seconds(settings),
        refresh_ttl_seconds=getattr(settings, "refresh_token_ttl_seconds", 30 * 86400),
        access_ttl_seconds=getattr(settings, "token_cache_ttl_seconds", 3600),
    )
    login_store = RedisLoginPendingStore(
        redis,
        key_prefix=login_prefix,
        owns_redis=False,
    )
    return oauth_store, login_store
