"""Shared Redis revision marker for RBAC policy changes across replicas."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from redis.asyncio import Redis
from redis.exceptions import RedisError

from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.router.registry import RouterRegistry

if TYPE_CHECKING:
    from keystone_mcp.observability.service import RbacObservability

logger = logging.getLogger(__name__)

_UNAVAILABLE_WARNING_INTERVAL_SECONDS = 60.0

__all__ = [
    "PolicyRevision",
    "PolicyRevisionStore",
    "RedisPolicyRevisionStore",
    "InMemoryPolicyRevisionStore",
    "PolicyRevisionWatcher",
]


@dataclass(frozen=True, slots=True)
class PolicyRevision:
    revision: int
    content_hash: str


@runtime_checkable
class PolicyRevisionStore(Protocol):
    async def read(self) -> PolicyRevision | None: ...

    async def publish(self, content_hash: str) -> PolicyRevision: ...


class InMemoryPolicyRevisionStore:
    """Test double shared by multiple replica watchers in one process."""

    def __init__(self) -> None:
        self._revision = 0
        self._content_hash: str | None = None
        self.read_count = 0

    async def read(self) -> PolicyRevision | None:
        self.read_count += 1
        if self._revision == 0 or self._content_hash is None:
            return None
        return PolicyRevision(revision=self._revision, content_hash=self._content_hash)

    async def publish(self, content_hash: str) -> PolicyRevision:
        self._revision += 1
        self._content_hash = content_hash
        return PolicyRevision(revision=self._revision, content_hash=content_hash)


class RedisPolicyRevisionStore:
    """Redis hash holding monotonic revision, content hash, and updated_at."""

    def __init__(self, client: Redis, *, key: str) -> None:
        self._client = client
        self._key = key

    async def read(self) -> PolicyRevision | None:
        try:
            raw = await self._client.hgetall(self._key)
        except (RedisError, OSError) as exc:
            raise RedisError(str(exc)) from exc
        if not raw:
            return None
        decoded = {
            (k.decode() if isinstance(k, bytes) else str(k)): (
                v.decode() if isinstance(v, bytes) else str(v)
            )
            for k, v in raw.items()
        }
        revision_raw = decoded.get("revision")
        content_hash = decoded.get("content_hash")
        if revision_raw is None or content_hash is None:
            logger.warning(
                "rbac policy revision key %s has incomplete fields: %s",
                self._key,
                sorted(decoded),
            )
            return None
        try:
            revision = int(revision_raw)
        except (TypeError, ValueError):
            logger.warning(
                "rbac policy revision key %s has invalid revision field: %r",
                self._key,
                revision_raw,
            )
            return None
        return PolicyRevision(revision=revision, content_hash=content_hash)

    async def publish(self, content_hash: str) -> PolicyRevision:
        updated_at = datetime.now(UTC).isoformat()
        pipe = self._client.pipeline(transaction=True)
        pipe.hincrby(self._key, "revision", 1)
        pipe.hset(self._key, mapping={"content_hash": content_hash, "updated_at": updated_at})
        results = await pipe.execute()
        revision = int(results[0])
        return PolicyRevision(revision=revision, content_hash=content_hash)


class PolicyRevisionWatcher:
    """Notifies replicas when another instance changes the RBAC policy file."""

    def __init__(
        self,
        *,
        store: PolicyRevisionStore,
        policy_manager: RbacPolicyManager,
        registry: RouterRegistry,
        observability: RbacObservability | None = None,
        min_interval_seconds: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self._policy_manager = policy_manager
        self._registry = registry
        self._observability = observability
        self._min_interval_seconds = min_interval_seconds
        self._clock = clock
        self._lock = asyncio.Lock()
        self._last_check_at: float | None = None
        self._seen_revision: int | None = None
        self._in_sync: bool | None = None
        self._divergence_logged_revision: int | None = None
        self._last_unavailable_warning_at: float | None = None
        if self._observability is not None:
            self._observability.set_policy_in_sync(None)

    @property
    def in_sync(self) -> bool | None:
        return self._in_sync

    def _set_in_sync(self, value: bool | None) -> None:
        if value == self._in_sync:
            return
        self._in_sync = value
        if self._observability is not None:
            self._observability.set_policy_in_sync(value)

    def _local_content_hash(self) -> str | None:
        identity = self._policy_manager.identity
        return identity.content_hash if identity is not None else None

    def _recompute_in_sync_for_current_revision(self, rev: PolicyRevision) -> None:
        local_hash = self._local_content_hash()
        if local_hash is None:
            self._set_in_sync(None)
            return
        self._set_in_sync(local_hash == rev.content_hash)

    async def ensure_current(self, *, force: bool = False) -> None:
        now = self._clock()
        if not force and self._last_check_at is not None:
            if now - self._last_check_at < self._min_interval_seconds:
                return

        async with self._lock:
            now = self._clock()
            if not force and self._last_check_at is not None:
                if now - self._last_check_at < self._min_interval_seconds:
                    return
            self._last_check_at = now

            try:
                rev = await self._store.read()
            except (RedisError, OSError) as exc:
                if (
                    self._last_unavailable_warning_at is None
                    or now - self._last_unavailable_warning_at
                    >= _UNAVAILABLE_WARNING_INTERVAL_SECONDS
                ):
                    logger.warning("rbac policy revision marker unavailable: %s", exc)
                    self._last_unavailable_warning_at = now
                if self._observability is not None:
                    self._observability.record_policy_revision_check(outcome="unavailable")
                return

            if rev is None:
                self._set_in_sync(None)
                return

            if self._seen_revision == rev.revision:
                self._recompute_in_sync_for_current_revision(rev)
                return

            local_hash = self._local_content_hash()
            if local_hash is not None and local_hash == rev.content_hash:
                self._seen_revision = rev.revision
                self._set_in_sync(True)
                return

            await asyncio.to_thread(self._policy_manager.reload, self._registry)
            local_hash = self._local_content_hash()
            self._seen_revision = rev.revision
            if local_hash is not None and local_hash == rev.content_hash:
                self._set_in_sync(True)
                if self._observability is not None:
                    self._observability.record_policy_revision_check(outcome="reloaded")
                return

            self._set_in_sync(False)
            if self._observability is not None:
                self._observability.record_policy_revision_check(outcome="diverged")
            if self._divergence_logged_revision != rev.revision:
                self._divergence_logged_revision = rev.revision
                logger.error(
                    "rbac policy revision %d (content_hash=%s) was published by another "
                    "replica, but this replica's policy file has content_hash=%s; this "
                    "replica keeps enforcing its own file. Put the policy on a shared "
                    "volume, or apply the change on every replica and send SIGHUP",
                    rev.revision,
                    rev.content_hash,
                    local_hash,
                )

    async def publish(self, content_hash: str) -> PolicyRevision | None:
        try:
            rev = await self._store.publish(content_hash)
        except (RedisError, OSError) as exc:
            logger.warning("rbac policy revision publish failed: %s", exc)
            return None
        self._seen_revision = rev.revision
        self._set_in_sync(True)
        return rev
