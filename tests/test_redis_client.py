"""Tests for the shared Redis client factory."""

from __future__ import annotations

import asyncio
import socket
import subprocess
from pathlib import Path

import pytest
from redis.exceptions import TimeoutError as RedisTimeoutError

from keystone_mcp.redis_client import (
    REDIS_HEALTH_CHECK_INTERVAL_SECONDS,
    REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS,
    REDIS_SOCKET_TIMEOUT_SECONDS,
    redis_from_url,
)
from support.test_env import UNUSED_REDIS_URL

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src" / "keystone_mcp"


def test_all_redis_clients_use_the_helper() -> None:
    hits = subprocess.run(
        ["grep", "-rn", "Redis.from_url", str(SRC_ROOT)],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = [line for line in hits.stdout.splitlines() if line and "redis_client.py" not in line]
    assert lines == []


def test_helper_sets_timeouts() -> None:
    client = redis_from_url(UNUSED_REDIS_URL)
    try:
        kwargs = client.connection_pool.connection_kwargs
        assert kwargs["socket_timeout"] == REDIS_SOCKET_TIMEOUT_SECONDS
        assert kwargs["socket_connect_timeout"] == REDIS_SOCKET_CONNECT_TIMEOUT_SECONDS
        assert kwargs["health_check_interval"] == REDIS_HEALTH_CHECK_INTERVAL_SECONDS
    finally:
        asyncio.run(client.aclose())


@pytest.mark.asyncio
async def test_hung_redis_fails_within_timeout() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(10.0)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    conn_holder: list[socket.socket] = []

    def accept_once() -> None:
        conn, _ = server.accept()
        conn_holder.append(conn)

    loop = asyncio.get_running_loop()
    accept_future = loop.run_in_executor(None, accept_once)

    bound_host = "127.0.0.1"
    client = redis_from_url(f"redis://{bound_host}:{port}/0")
    try:
        with pytest.raises((RedisTimeoutError, asyncio.TimeoutError, TimeoutError)):
            await asyncio.wait_for(client.get("x"), timeout=7.0)
    finally:
        await client.aclose()
        for conn in conn_holder:
            conn.close()
        server.close()
        await accept_future
