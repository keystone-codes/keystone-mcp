"""Unit tests for upstream guard ordering and failure classification."""

from __future__ import annotations

import asyncio

import httpx
import httpx2
import pytest
from fastmcp.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from mcp_types.jsonrpc import REQUEST_TIMEOUT

from keystone_mcp.auth.rate_window import InMemorySlidingWindow
from keystone_mcp.config import UpstreamLimits
from keystone_mcp.router.stdio_process import UpstreamProcessUnavailableError
from keystone_mcp.router.upstream_guard import (
    UpstreamGuard,
    UpstreamLimitError,
    is_upstream_failure,
)
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker


@pytest.mark.asyncio
async def test_concurrency_slot_wait_uses_tool_timeout() -> None:
    limits = UpstreamLimits(concurrency=1)
    guard = UpstreamGuard("ns", limits, window=InMemorySlidingWindow(), observability=None)
    guard._semaphore = asyncio.Semaphore(0)

    with pytest.raises(UpstreamLimitError, match="is busy"):
        async with guard.call(timeout=0.5, slot_wait_timeout=0.5):
            pass


@pytest.mark.asyncio
async def test_guard_order_circuit_before_rate_before_concurrency() -> None:
    window = InMemorySlidingWindow()
    limits = UpstreamLimits(
        concurrency=1,
        rate=1,
        window_seconds=60,
        breaker_failures=1,
        breaker_recovery_seconds=60,
    )
    guard = UpstreamGuard("ns", limits, window=window, observability=None)
    guard._breaker = CircuitBreaker(failure_threshold=1, recovery_seconds=60)
    guard._breaker.record_failure()

    with pytest.raises(UpstreamLimitError, match="temporarily unavailable"):
        async with guard.call(timeout=5.0):
            pass

    guard._breaker.reset()
    await window.hit("upstream:ns", limit=1, window_seconds=60)
    await window.hit("upstream:ns", limit=1, window_seconds=60)

    with pytest.raises(UpstreamLimitError, match="over its call limit"):
        async with guard.call(timeout=5.0):
            pass


@pytest.mark.asyncio
async def test_cancelled_half_open_probe_records_failure() -> None:
    breaker = CircuitBreaker(failure_threshold=1, recovery_seconds=0.001)
    breaker.record_failure()
    await asyncio.sleep(0.01)
    assert breaker.state() == "half_open"

    limits = UpstreamLimits(breaker_failures=1, breaker_recovery_seconds=0.001)
    guard = UpstreamGuard("ns", limits, window=InMemorySlidingWindow(), observability=None)
    guard._breaker = breaker

    with pytest.raises(asyncio.CancelledError):
        async with guard.call(timeout=5.0):
            raise asyncio.CancelledError

    assert breaker.state() in ("open", "half_open")
    assert breaker._consecutive_failures >= 1  # noqa: SLF001


def test_is_upstream_failure_transport_and_timeout() -> None:
    assert is_upstream_failure(UpstreamProcessUnavailableError("x"))
    assert is_upstream_failure(httpx.ConnectError("x"))
    assert is_upstream_failure(httpx2.ConnectError("x"))
    assert is_upstream_failure(MCPError(REQUEST_TIMEOUT, "timeout"))
    assert is_upstream_failure(TimeoutError())
    assert not is_upstream_failure(asyncio.CancelledError())
    assert not is_upstream_failure(ToolError("upstream said no"))
    assert is_upstream_failure(RuntimeError("Client failed to connect to MCP server"))
