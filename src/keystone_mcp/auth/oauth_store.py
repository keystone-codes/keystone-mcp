"""Persistent OAuth session store (clients, access tokens, refresh tokens).

Production uses the deployment's Redis; tests inject
:class:`InMemoryOAuthStore`.
"""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable

from mcp.server.auth.provider import AccessToken, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull
from redis.asyncio import Redis

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
    ) -> None:
        self._client_ttl_seconds = client_ttl_seconds
        self._refresh_ttl_seconds = refresh_ttl_seconds
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._client_expires_at: dict[str, float] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}
        self._refresh_expires_at: dict[str, float] = {}

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

    async def get_access_token(self, token: str) -> AccessToken | None:
        access = self._access_tokens.get(token)
        if access is None:
            return None
        if access.expires_at is not None and access.expires_at < time.time():
            self._access_tokens.pop(token, None)
            return None
        return access

    async def put_access_token(self, access: AccessToken) -> None:
        self._access_tokens[access.token] = access

    async def delete_access_token(self, token: str) -> None:
        self._access_tokens.pop(token, None)

    async def get_refresh_token(self, token: str) -> RefreshToken | None:
        refresh = self._refresh_tokens.get(token)
        if refresh is None:
            return None
        expires_at = self._refresh_expires_at.get(token)
        if expires_at is not None and expires_at < time.time():
            self._refresh_tokens.pop(token, None)
            self._refresh_expires_at.pop(token, None)
            return None
        return refresh

    async def put_refresh_token(self, refresh: RefreshToken) -> None:
        self._refresh_tokens[refresh.token] = refresh
        if refresh.expires_at is not None:
            ttl = max(refresh.expires_at - time.time(), 1)
        else:
            ttl = self._refresh_ttl_seconds
        self._refresh_expires_at[refresh.token] = time.time() + ttl

    async def delete_refresh_token(self, token: str) -> None:
        self._refresh_tokens.pop(token, None)
        self._refresh_expires_at.pop(token, None)

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
    ) -> None:
        prefix = key_prefix if key_prefix.endswith(":") else f"{key_prefix}:"
        self._prefix = prefix
        self._client_ttl_seconds = client_ttl_seconds
        self._refresh_ttl_seconds = refresh_ttl_seconds
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
        raw = await self._redis.get(self._access_key(token))
        if raw is None:
            return None
        access = AccessToken.model_validate_json(raw)
        if access.expires_at is not None and access.expires_at < time.time():
            await self.delete_access_token(token)
            return None
        return access

    async def put_access_token(self, access: AccessToken) -> None:
        ttl = self._access_ttl(access)
        payload = access.model_dump_json()
        key = self._access_key(access.token)
        if ttl is None:
            await self._redis.set(key, payload)
        else:
            await self._redis.set(key, payload, ex=ttl)

    async def delete_access_token(self, token: str) -> None:
        await self._redis.delete(self._access_key(token))

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
        return refresh

    async def put_refresh_token(self, refresh: RefreshToken) -> None:
        if refresh.expires_at is None:
            ttl = self._refresh_ttl_seconds
        else:
            ttl = int(refresh.expires_at - time.time())
            ttl = ttl if ttl > 0 else 1
        await self._redis.set(self._refresh_key(refresh.token), refresh.model_dump_json(), ex=ttl)

    async def delete_refresh_token(self, token: str) -> None:
        await self._redis.delete(self._refresh_key(token))

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
    )
    login_store = RedisLoginPendingStore(
        redis,
        key_prefix=login_prefix,
        owns_redis=False,
    )
    return oauth_store, login_store
