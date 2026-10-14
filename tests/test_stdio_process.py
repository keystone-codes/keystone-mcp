"""Tests for :class:`keystone_mcp.router.stdio_process.StdioUpstreamProcess`.

Real subprocesses throughout (the test upstream at ``tests/support/
stdio_upstream.py``, or plain shell commands for the failure-path tests).
Every test stops its own process in a ``finally`` block so a failing
assertion never leaks a child.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sys
from pathlib import Path

import anyio
import pytest
from prometheus_client import REGISTRY

from keystone_mcp.router import stdio_process
from keystone_mcp.router.stdio_process import (
    StdioUpstreamProcess,
    UpstreamProcessUnavailableError,
)

STDIO_SERVER = str(Path(__file__).parent / "support" / "stdio_upstream.py")
NOISY_STDIO_SERVER = str(Path(__file__).parent / "support" / "noisy_stdio_upstream.py")
CRASH_BEFORE_INIT_SERVER = str(
    Path(__file__).parent / "support" / "crash_before_init_stdio_upstream.py"
)
GIANT_STDERR_LINE_SERVER = str(Path(__file__).parent / "support" / "giant_stderr_line_upstream.py")


def _make_proc(
    *, states: list[tuple[str, str | None]] | None = None, **overrides
) -> StdioUpstreamProcess:
    kwargs: dict = {
        "namespace": "notes",
        "command": sys.executable,
        "args": [STDIO_SERVER],
        "env": {},
        "cwd": None,
        "init_timeout": 10,
    }
    if states is not None:
        kwargs["on_state"] = lambda state, reason: states.append((state, reason))
    kwargs.update(overrides)
    return StdioUpstreamProcess(**kwargs)


async def _crash(proc: StdioUpstreamProcess) -> None:
    """Call the ``crash`` tool; the process dies before answering."""
    with contextlib.suppress(Exception), anyio.fail_after(5):
        async with proc.client() as client:
            await client.call_tool("crash", {})


def _count(states: list[tuple[str, str | None]], state: str) -> int:
    return sum(1 for s, _ in states if s == state)


async def _wait_for_nth_running(
    states: list[tuple[str, str | None]], n: int, *, timeout: float = 5
) -> None:
    """Wait until ``states`` has recorded ``n`` transitions into ``running``.

    Polling ``proc.state`` directly is racy here: a crash takes effect
    asynchronously (stderr EOF, cancellation, teardown), so the state can
    still read ``"running"`` — the pre-crash value — for a little while
    after the crashing call returns. Counting transitions recorded by
    ``on_state`` has no such window.
    """
    with anyio.fail_after(timeout):
        while _count(states, "running") < n:
            await anyio.sleep(0.02)


async def test_start_reaches_running_and_serves_calls():
    proc = _make_proc()
    try:
        assert await proc.start(wait=10) is True
        assert proc.state == "running"
        async with proc.client() as client:
            result = await client.call_tool("pid", {})
        assert result.content[0].text.isdigit()
    finally:
        await proc.stop()


async def test_start_reaches_running_despite_noisy_startup_stderr():
    """A server that floods stderr before answering ``initialize`` must not

    hang: stderr has to be drained from the moment the pipe exists, not only
    after that answer arrives, or the child blocks on ``write()`` forever.
    """
    proc = _make_proc(args=[NOISY_STDIO_SERVER])
    try:
        with anyio.fail_after(15):
            started = await proc.start(wait=15)
        assert started is True
        async with proc.client() as client:
            result = await client.call_tool("pid", {})
        assert result.content[0].text.isdigit()
    finally:
        await proc.stop()


async def test_start_failure_stderr_is_logged(caplog):
    """A server that fails before ``initialize`` still gets its stderr output

    logged, instead of only a generic ``start failed: ...`` with no clue why.
    """
    proc = _make_proc(args=[CRASH_BEFORE_INIT_SERVER], init_timeout=3)
    try:
        with caplog.at_level(logging.INFO, logger="keystone_mcp.upstream.stderr"):
            with anyio.fail_after(10):
                started = await proc.start(wait=3)
            assert started is False
            with anyio.fail_after(5):
                while "CRASH-BEFORE-INIT-MARKER" not in caplog.text:
                    await anyio.sleep(0.05)
        assert "CRASH-BEFORE-INIT-MARKER: synthetic startup failure" in caplog.text
    finally:
        with anyio.fail_after(5):
            await proc.stop()


async def test_oversized_stderr_line_does_not_crash_supervisor(caplog):
    """A single stderr line longer than the reader's buffer limit, with no

    newline in sight, must not kill (and misleadingly restart) an otherwise
    healthy process -- only that one line is lost.
    """
    proc = _make_proc(args=[GIANT_STDERR_LINE_SERVER])
    try:
        with caplog.at_level(logging.WARNING, logger="keystone_mcp.upstream.stderr"):
            with anyio.fail_after(15):
                started = await proc.start(wait=15)
            assert started is True
            async with proc.client() as client:
                result = await client.call_tool("pid", {})
            assert result.content[0].text.isdigit()
        assert "stderr line exceeded" in caplog.text
    finally:
        await proc.stop()


async def test_crash_is_restarted():
    states: list[tuple[str, str | None]] = []
    proc = _make_proc(states=states)
    try:
        assert await proc.start(wait=10) is True
        async with proc.client() as client:
            pid_before = int((await client.call_tool("pid", {})).content[0].text)

        await _crash(proc)
        await _wait_for_nth_running(states, 2)

        async with proc.client() as client:
            pid_after = int((await client.call_tool("pid", {})).content[0].text)

        assert pid_after != pid_before
        assert proc.restarts == 1
        assert ("backoff", "process exited") in states
    finally:
        await proc.stop()


#: The restart backoff only ever sleeps for one of these durations; the
#: periodic health ping (``_PING_INTERVAL_SECONDS`` = 15s) sleeps for a
#: different one. A fake ``sleep`` that short-circuits only these values lets
#: a test fast-forward restarts without also fast-forwarding health pings
#: into a busy loop against the real subprocess.
_BACKOFF_DELAYS = frozenset((1, 2, 4, 8, 16, 32, 60))


def _make_backoff_fast_forward(pauses: list[float]):
    async def fake_sleep(seconds: float) -> None:
        if seconds in _BACKOFF_DELAYS:
            pauses.append(seconds)
            return
        await anyio.sleep(seconds)

    return fake_sleep


async def test_restart_backoff_is_rate_limited():
    pauses: list[float] = []
    fake_sleep = _make_backoff_fast_forward(pauses)

    proc = _make_proc(
        command=sys.executable,
        args=["-c", "import sys; sys.exit(1)"],
        init_timeout=1,
        sleep=fake_sleep,
    )
    try:
        await proc.start(wait=2)
        with anyio.fail_after(10):
            while len(pauses) < 9:
                await anyio.sleep(0.01)
    finally:
        await proc.stop()

    assert pauses[:9] == [1, 2, 4, 8, 16, 32, 60, 60, 60]


async def test_backoff_resets_after_stable_run():
    pauses: list[float] = []
    states: list[tuple[str, str | None]] = []
    fake_sleep = _make_backoff_fast_forward(pauses)

    clock_value = [0.0]
    proc = _make_proc(states=states, clock=lambda: clock_value[0], sleep=fake_sleep)
    try:
        assert await proc.start(wait=10) is True

        # First crash happens "immediately" (fake clock unmoved): the schedule
        # starts at its first entry regardless, so this alone would not tell a
        # reset from no-reset. It only advances the backoff index to 1.
        await _crash(proc)
        await _wait_for_nth_running(states, 2)
        assert pauses == [1]

        # Second crash, after the fake clock reports a 1000-second run: well
        # past the 60-second stability threshold, so the backoff must reset
        # to its first entry again instead of advancing to the second (2).
        clock_value[0] = 1000.0
        await _crash(proc)
        await _wait_for_nth_running(states, 3)
        assert pauses == [1, 1]
    finally:
        await proc.stop()


async def test_stop_during_backoff_pause_returns_quickly():
    """``stop()`` must not wait out the backoff pause (up to 60s) before

    returning: the pause has to be interrupted, not merely outlived.
    """
    states: list[tuple[str, str | None]] = []
    proc = _make_proc(
        states=states,
        command=sys.executable,
        args=["-c", "import sys; sys.exit(1)"],
        init_timeout=1,
    )
    try:
        await proc.start(wait=2)
        with anyio.fail_after(5):
            while _count(states, "backoff") < 1:
                await anyio.sleep(0.01)

        start = anyio.current_time()
        with anyio.fail_after(5):
            await proc.stop()
        elapsed = anyio.current_time() - start
    finally:
        with contextlib.suppress(Exception), anyio.fail_after(5):
            await proc.stop()

    # The first backoff pause is 1 second (real time, no fake sleep here);
    # returning well under that proves stop() interrupted it instead of
    # waiting it out.
    assert elapsed < 0.5


async def test_non_mcp_process_fails_start_and_retries():
    # `sleep` never answers `initialize` and, unlike the crash tool, is still
    # alive when the connect attempt gives up: tearing it down follows the
    # MCP shutdown sequence (close stdin, wait out a ~2s grace period, then
    # SIGTERM) on top of init_timeout, so `wait` must cover init_timeout plus
    # that grace period, not just init_timeout itself.
    proc = _make_proc(command="sleep", args=["1000"], init_timeout=1)
    try:
        with anyio.fail_after(10):
            started = await proc.start(wait=6)
        assert started is False
        assert proc.state == "backoff"
    finally:
        with anyio.fail_after(5):
            await proc.stop()


async def test_stop_terminates_process():
    proc = _make_proc()
    assert await proc.start(wait=10) is True
    async with proc.client() as client:
        pid = int((await client.call_tool("pid", {})).content[0].text)

    with anyio.fail_after(5):
        await proc.stop()

    assert proc.state == "stopped"
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


async def test_child_env_has_only_mapped_variables(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis://secret")
    proc = _make_proc(env={"NOTES_TOKEN": "t"})
    try:
        assert await proc.start(wait=10) is True
        async with proc.client() as client:
            mapped = await client.call_tool("env", {"name": "NOTES_TOKEN"})
            keystone = await client.call_tool("env", {"name": "KEYSTONE_MCP_REDIS_URL"})
        assert mapped.content[0].text == "t"
        assert keystone.content[0].text == "<unset>"
    finally:
        await proc.stop()


async def test_stderr_goes_to_log_with_namespace(caplog):
    proc = _make_proc()
    try:
        assert await proc.start(wait=10) is True
        with caplog.at_level(logging.INFO, logger="keystone_mcp.upstream.stderr"):
            async with proc.client() as client:
                await client.call_tool("stderr", {})
            with anyio.fail_after(5):
                while "hello-from-stderr" not in caplog.text:
                    await anyio.sleep(0.05)
        assert "namespace=notes hello-from-stderr" in caplog.text
    finally:
        await proc.stop()


def test_client_when_not_running_raises():
    proc = _make_proc()
    with pytest.raises(UpstreamProcessUnavailableError):
        proc.client()


async def test_hang_with_inflight_call_fails_call_and_restarts(monkeypatch):
    monkeypatch.setattr(stdio_process, "_PING_INTERVAL_SECONDS", 0.3)
    monkeypatch.setattr(stdio_process, "_PING_TIMEOUT_SECONDS", 0.3)
    monkeypatch.setattr(stdio_process, "_PING_FAILURES_TO_RESTART", 2)
    states: list[tuple[str, str | None]] = []
    proc = _make_proc(states=states)
    try:
        assert await proc.start(wait=10) is True
        async with proc.client() as client:
            pid_before = int((await client.call_tool("pid", {})).content[0].text)
            t0 = anyio.current_time()
            with pytest.raises(Exception):
                with anyio.fail_after(6):
                    await client.call_tool("block", {"seconds": 8})
            assert anyio.current_time() - t0 <= 3.0

        with anyio.fail_after(2):
            while proc.state == "running":
                await anyio.sleep(0.05)

        state_names = [s for s, _ in states]
        assert "stopping" in state_names
        assert "backoff" in state_names

        with anyio.fail_after(10):
            while proc.state != "running":
                await anyio.sleep(0.05)
        assert _count(states, "running") >= 2
        async with proc.client() as client:
            pid_after = int((await client.call_tool("pid", {})).content[0].text)
        assert pid_after != pid_before
        assert proc.restarts == 1
    finally:
        await proc.stop()


async def test_single_missed_ping_does_not_restart(monkeypatch):
    monkeypatch.setattr(stdio_process, "_PING_INTERVAL_SECONDS", 0.3)
    monkeypatch.setattr(stdio_process, "_PING_TIMEOUT_SECONDS", 0.3)
    monkeypatch.setattr(stdio_process, "_PING_FAILURES_TO_RESTART", 3)
    proc = _make_proc()
    try:
        assert await proc.start(wait=10) is True
        async with proc.client() as client:
            result = await client.call_tool("block", {"seconds": 0.5})
        assert "unblocked" in result.content[0].text
        assert proc.restarts == 0
        assert proc.state == "running"
    finally:
        await proc.stop()


async def test_stop_with_inflight_call_returns_quickly():
    proc = _make_proc()
    try:
        assert await proc.start(wait=10) is True
        async with proc.client() as client:
            pid = int((await client.call_tool("pid", {})).content[0].text)
            task = asyncio.create_task(client.call_tool("block", {"seconds": 30}))
            await anyio.sleep(0.05)
            t0 = anyio.current_time()
            with anyio.fail_after(6):
                await proc.stop()
            assert anyio.current_time() - t0 < 6.0
            task.cancel()
            with contextlib.suppress(Exception):
                await task
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    finally:
        with contextlib.suppress(Exception), anyio.fail_after(5):
            await proc.stop()


async def test_stderr_is_rate_limited(monkeypatch, caplog):
    monkeypatch.setattr(stdio_process, "_STDERR_LINES_PER_SECOND", 50.0)
    monkeypatch.setattr(stdio_process, "_STDERR_BURST", 200)
    proc = _make_proc()
    try:
        assert await proc.start(wait=10) is True
        with caplog.at_level(logging.INFO, logger="keystone_mcp.upstream.stderr"):
            async with proc.client() as client:
                await client.call_tool("spam", {"lines": 1000})
            with anyio.fail_after(3):
                await anyio.sleep(1.1)
        info_records = [
            r
            for r in caplog.records
            if r.levelno == logging.INFO and r.name == "keystone_mcp.upstream.stderr"
        ]
        assert len(info_records) <= 260
        assert "suppressed" in caplog.text
        sample = REGISTRY.get_sample_value(
            "keystone_mcp_upstream_stderr_suppressed_total",
            {"namespace": "notes"},
        )
        assert sample is not None and sample > 0
    finally:
        await proc.stop()


async def test_stderr_masks_entry_env_values(caplog):
    proc = _make_proc(env={"NOTES_TOKEN": "s3cr3t-value-123"})
    try:
        assert await proc.start(wait=10) is True
        with caplog.at_level(logging.INFO, logger="keystone_mcp.upstream.stderr"):
            async with proc.client() as client:
                await client.call_tool("spam", {"lines": 5})
            with anyio.fail_after(3):
                while "token-dump" not in caplog.text and "spam-line" not in caplog.text:
                    await anyio.sleep(0.05)
        assert "s3cr3t-value-123" not in caplog.text
        assert "***REDACTED***" in caplog.text
    finally:
        await proc.stop()
