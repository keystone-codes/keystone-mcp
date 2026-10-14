"""Shared Redis client factory for Keystone."""

from __future__ import annotations

from typing import Any

from redis.asyncio import Redis
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff
from redis.exceptions import ConnectionError

REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS = 5
REDIS_SOCKET_TIMEOUT_SECONDS = 5
REDIS_HEALTH_CHECK_INTERVAL_SECONDS = 30


def redis_from_url(url: str, **overrides: Any) -> Redis:
    """The one way Keystone opens an asyncio Redis client."""
    options: dict[str, Any] = dict(
        decode_responses=True,
        socket_connect_timeout=REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS,
        socket_timeout=REDIS_SOCKET_TIMEOUT_SECONDS,
        health_check_interval=REDIS_HEALTH_CHECK_INTERVAL_SECONDS,
        retry=Retry(
            ExponentialBackoff(cap=0.5, base=0.05),
            retries=2,
            supported_errors=(ConnectionError,),
        ),
        retry_on_timeout=False,
    )
    options.update(overrides)
    return Redis.from_url(url, **options)
