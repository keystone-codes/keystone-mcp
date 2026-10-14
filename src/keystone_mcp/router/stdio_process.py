"""Supervises one ``transport: stdio`` upstream subprocess.

:class:`StdioUpstreamProcess` starts the child process, keeps a single
``fastmcp.Client`` session open against it for as long as it is healthy,
detects a crash or a hang, and restarts it with a rate-limited backoff. It
owns nothing else: wiring this into :class:`~keystone_mcp.router.registry
.UpstreamRegistry`, discovery, the proxy, ``/readyz``, or metrics is stdio upstream wiring
job, not this module's.

Health is driven by two independent signals while the session is open:

- the stderr pipe reaching end-of-file, which happens exactly when the child
  process exits (see ``_read_stderr_until_eof``);
- a periodic ``client.ping()`` that must complete within a short timeout,
  catching a child that is still alive but no longer answering requests.

The internal client is created with ``mode="legacy"``, pinning the MCP
handshake-era protocol: most ready-made stdio servers (the npm/pip packages
this feature exists for) speak that era, and — unlike the modern
``2026-07-28`` era — it is the one in which ``ping`` exists at all.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Literal

import anyio
import fastmcp
from fastmcp.client.transports import StdioTransport

from keystone_mcp.observability.logging.redact import redact_string
from keystone_mcp.observability.metrics import record_upstream_stderr_suppressed

logger = logging.getLogger(__name__)
_stderr_logger = logging.getLogger("keystone_mcp.upstream.stderr")

ProcessState = Literal["stopped", "starting", "running", "stopping", "backoff"]
StateCallback = Callable[[ProcessState, str | None], None]

#: Restart delay schedule in seconds: 1, 2, 4, 8, 16, 32, then 60 forever.
#: Resets to the start of this schedule once a run has been stable (see
#: ``_STABLE_RUN_SECONDS``) — there is no permanent give-up.
_BACKOFF_SCHEDULE: tuple[float, ...] = (1, 2, 4, 8, 16, 32, 60)

#: A run that stayed healthy at least this long resets the backoff schedule.
_STABLE_RUN_SECONDS = 60.0

#: How often to ping a running process to notice a hang (not a crash).
_PING_INTERVAL_SECONDS = 15.0

#: Max time to wait for one ping to answer before treating it as a hang.
_PING_TIMEOUT_SECONDS = 5.0

#: Consecutive missed pings before the process is restarted.
_PING_FAILURES_TO_RESTART = 3

#: Max time to wait for the supervisor task to wind down in ``stop()``.
_STOP_TIMEOUT_SECONDS = 5.0

#: Stderr lines are logged truncated, matching the redaction module's cap for
#: one log field; a runaway writer cannot blow up log storage.
_MAX_STDERR_LINE_CHARS = 2000

#: Token-bucket rate for stderr log lines (sustained rate and burst capacity).
_STDERR_LINES_PER_SECOND = 50.0
_STDERR_BURST = 200

#: ``asyncio.StreamReader`` buffer limit for one stderr line. Generous on
#: purpose: the asyncio default (64 KiB) is tight enough that a single long
#: diagnostic line with no newline could raise out of ``readline()`` (see
#: ``_read_stderr_until_eof``) well before ``_MAX_STDERR_LINE_CHARS`` would
#: ever truncate it for logging.
_STDERR_READER_LIMIT = 1 << 20  # 1 MiB


class UpstreamProcessUnavailableError(RuntimeError):
    """Raised by :meth:`StdioUpstreamProcess.client` when not ``running``."""


class _StderrRateLimiter:
    def __init__(self, *, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._tokens = float(_STDERR_BURST)
        self._last_refill = clock()
        self._suppressed_since_report = 0

    def take_line(self) -> bool:
        now = self._clock()
        elapsed = now - self._last_refill
        if elapsed > 0:
            self._tokens = min(
                float(_STDERR_BURST),
                self._tokens + elapsed * _STDERR_LINES_PER_SECOND,
            )
            self._last_refill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        self._suppressed_since_report += 1
        return False

    def flush_suppressed_report(self) -> int:
        count = self._suppressed_since_report
        self._suppressed_since_report = 0
        return count


def _mask_process_env_values(text: str, env: Mapping[str, str]) -> str:
    out = text
    for value in env.values():
        if len(value) >= 8 and value in out:
            out = out.replace(value, "***REDACTED***")
    return redact_string(out)


class StdioUpstreamProcess:
    """Keeps one stdio upstream process alive and exposes its MCP client.

    ``env`` must already be the resolved child environment (name -> value);
    this class does not read ``KEYSTONE_MCP_*`` itself — resolving an
 entry's ``env_from`` pairs into values is stdio upstream wiring job, at the call site
    that constructs this object.

    ``start()`` after ``stop()`` is not supported: it returns ``False`` and
    does nothing.
    """

    def __init__(
        self,
        *,
        namespace: str,
        command: str,
        args: Sequence[str],
        env: Mapping[str, str],
        cwd: str | None,
        init_timeout: float,
        on_state: StateCallback | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = anyio.sleep,
    ) -> None:
        self._namespace = namespace
        self._command = command
        self._args = tuple(args)
        self._env = dict(env)
        self._cwd = cwd
        self._init_timeout = init_timeout
        self._on_state = on_state
        self._clock = clock
        self._sleep = sleep

        self._state: ProcessState = "stopped"
        self._restarts = 0
        self._backoff_index = 0
        self._client: fastmcp.Client | None = None

        self._task_handle: asyncio.Task[None] | None = None
        self._stop_requested = False
        self._stop_event = anyio.Event()
        self._first_attempt_done = anyio.Event()

    @property
    def state(self) -> ProcessState:
        return self._state

    @property
    def restarts(self) -> int:
        """Number of restarts after the first start (one per crash/hang/failed start)."""
        return self._restarts

    def client(self) -> fastmcp.Client:
        """Return the live client. Raises when the process is not ``running``.

        The returned object is the same :class:`fastmcp.Client` the
        supervisor itself holds open; callers enter it with a nested
        ``async with client():`` and share its one session.
        """
        if self._state != "running" or self._client is None:
            raise UpstreamProcessUnavailableError(
                f"upstream process {self._namespace!r} is not running (state={self._state})"
            )
        return self._client

    async def start(self, *, wait: float) -> bool:
        """Start the supervisor loop; wait up to ``wait`` seconds for ``running``.

        Returns whether the process reached ``running`` within that window.
        Starting again while already started is a no-op. After ``stop()``, returns
        ``False`` without starting again.
        """
        if self._task_handle is not None:
            return self._state == "running"

        self._task_handle = asyncio.create_task(self._run())
        with anyio.move_on_after(wait):
            await self._first_attempt_done.wait()
        return self._state == "running"

    async def stop(self) -> None:
        """Stop the supervisor and the child process it is running, if any."""
        if self._task_handle is None or self._stop_requested:
            return
        self._stop_requested = True
        self._stop_event.set()
        task = self._task_handle
        with anyio.CancelScope(shield=True):
            with anyio.move_on_after(_STOP_TIMEOUT_SECONDS):
                await task
            if not task.done():
                task.cancel()
                with contextlib.suppress(Exception):
                    await task
        self._set_state("stopped", None)

    def _set_state(self, state: ProcessState, reason: str | None) -> None:
        self._state = state
        # Signal start()'s waiter the first time the initial attempt resolves
        # one way or the other. _run_once() itself does not return until the
        # process stops (it supervises a healthy run indefinitely), so this
        # cannot wait for _run_once() to return -- only for the state it sets.
        if state in ("running", "backoff") and not self._first_attempt_done.is_set():
            self._first_attempt_done.set()
        if self._on_state is not None:
            self._on_state(state, reason)

    async def _run(self) -> None:
        try:
            while not self._stop_requested:
                self._set_state("starting", None)
                reason, started_at = await self._run_once()
                if self._stop_requested:
                    break

                if started_at is not None and (self._clock() - started_at) >= _STABLE_RUN_SECONDS:
                    self._backoff_index = 0

                delay = _BACKOFF_SCHEDULE[min(self._backoff_index, len(_BACKOFF_SCHEDULE) - 1)]
                self._backoff_index += 1
                self._restarts += 1
                self._set_state("backoff", reason)
                logger.warning(
                    "upstream process down namespace=%s: %s; restart %d in %ds",
                    self._namespace,
                    reason,
                    self._restarts,
                    delay,
                )
                await self._sleep_interruptibly(delay)
        finally:
            if not self._first_attempt_done.is_set():
                self._first_attempt_done.set()

    async def _sleep_interruptibly(self, delay: float) -> None:
        """Sleep for ``delay`` seconds, but return as soon as ``stop()`` runs.

        Without this, calling ``stop()`` while the supervisor is paused
        between restart attempts would have to wait out the rest of that
        pause -- up to 60 seconds -- before it could return.
        """
        if self._stop_requested:
            return

        async def _cancel_on_stop(tg: anyio.abc.TaskGroup) -> None:
            await self._stop_event.wait()
            tg.cancel_scope.cancel()

        async with anyio.create_task_group() as tg:
            tg.start_soon(_cancel_on_stop, tg)
            await self._sleep(delay)
            tg.cancel_scope.cancel()

    async def _teardown_client(self, client: fastmcp.Client, reason: str) -> None:
        self._client = None
        self._set_state("stopping", None if reason == "stopped" else reason)
        with anyio.move_on_after(_STOP_TIMEOUT_SECONDS):
            with contextlib.suppress(Exception):
                await client.close()

    async def _run_once(self) -> tuple[str, float | None]:
        """Run one attempt: start the process, serve while healthy, return why it stopped.

        Stderr is drained from the moment the pipe exists, *before* the
        child process is even spawned -- not only once ``initialize`` has
        succeeded. A server that writes a lot to stderr before it answers
        ``initialize`` would otherwise fill the pipe's kernel buffer and
        block on ``write()``, hanging startup forever with nothing reading
        the other end; and a server that crashes during startup would have
        its diagnostic output discarded instead of logged. The stderr
        reader keeps running for the rest of this attempt, wrapped around
        everything else below, so its task group only finishes -- letting
        this method actually return -- once stderr has reached EOF (the
        child exited) or this attempt has nothing left to read.
        """
        read_fd, write_fd = os.pipe()
        writer: Any = os.fdopen(write_fd, "w", buffering=1)
        started_at: float | None = None
        eof_event = anyio.Event()
        client: fastmcp.Client | None = None

        async def watch_stderr() -> None:
            await self._read_stderr_until_eof(read_fd)
            eof_event.set()

        async with anyio.create_task_group() as stderr_tg:
            stderr_tg.start_soon(watch_stderr)
            try:
                transport = StdioTransport(
                    self._command,
                    list(self._args),
                    env=dict(self._env),
                    cwd=self._cwd,
                    keep_alive=False,
                    log_file=writer,
                )
                client = fastmcp.Client(transport, init_timeout=self._init_timeout, mode="legacy")
                await client.__aenter__()
                writer.close()
                writer = None
                self._client = client
                started_at = self._clock()
                self._set_state("running", None)
                reason = await self._supervise_running(client, eof_event)
                assert client is not None
                await self._teardown_client(client, reason)
                return reason, started_at
            except Exception as exc:  # noqa: BLE001 - becomes a logged restart reason
                if client is not None:
                    await self._teardown_client(client, "start failed")
                return (
                    f"start failed: {type(exc).__name__} running {os.path.basename(self._command)}",
                    started_at,
                )
            finally:
                if writer is not None:
                    with contextlib.suppress(OSError):
                        writer.close()

    async def _supervise_running(self, client: fastmcp.Client, eof_event: anyio.Event) -> str:
        """Wait until the process exits, hangs, or ``stop()`` is called.

        ``eof_event`` is set by the stderr reader that ``_run_once`` already
        started before this process was even spawned; this method only
        watches it, it does not own stderr.
        """
        outcome: dict[str, str] = {}
        ping_failures = 0

        async def watch_eof(tg: anyio.abc.TaskGroup) -> None:
            await eof_event.wait()
            outcome.setdefault("reason", "process exited")
            tg.cancel_scope.cancel()

        async def watch_ping(tg: anyio.abc.TaskGroup) -> None:
            nonlocal ping_failures
            while True:
                await self._sleep(_PING_INTERVAL_SECONDS)
                if eof_event.is_set() or self._stop_requested:
                    return
                try:
                    with anyio.fail_after(_PING_TIMEOUT_SECONDS):
                        ok = await client.ping()
                    if not ok:
                        raise RuntimeError("ping returned a falsy result")
                except Exception as exc:  # noqa: BLE001 - count toward restart threshold
                    ping_failures += 1
                    logger.warning(
                        "upstream process namespace=%s missed ping %d/%d",
                        self._namespace,
                        ping_failures,
                        _PING_FAILURES_TO_RESTART,
                    )
                    if ping_failures >= _PING_FAILURES_TO_RESTART:
                        outcome["reason"] = (
                            f"ping failed {_PING_FAILURES_TO_RESTART} times: {type(exc).__name__}"
                        )
                        tg.cancel_scope.cancel()
                        return
                else:
                    ping_failures = 0

        async def watch_stop(tg: anyio.abc.TaskGroup) -> None:
            await self._stop_event.wait()
            tg.cancel_scope.cancel()

        async with anyio.create_task_group() as tg:
            tg.start_soon(watch_eof, tg)
            tg.start_soon(watch_ping, tg)
            tg.start_soon(watch_stop, tg)

        if self._stop_requested:
            return "stopped"
        return outcome.get("reason", "process exited")

    async def _read_stderr_until_eof(self, read_fd: int) -> None:
        """Log the child's stderr, one line at a time, until the pipe closes.

        Takes ownership of ``read_fd`` and closes it on every path (EOF,
        cancellation, exception).
        """
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=_STDERR_READER_LIMIT)
        protocol = asyncio.StreamReaderProtocol(reader)
        read_file = os.fdopen(read_fd, "rb", buffering=0)
        transport, _ = await loop.connect_read_pipe(lambda: protocol, read_file)
        limiter = _StderrRateLimiter(clock=self._clock)

        async def _emit_suppressed_report() -> None:
            while True:
                await asyncio.sleep(1.0)
                suppressed = limiter.flush_suppressed_report()
                if suppressed:
                    _stderr_logger.warning(
                        "namespace=%s suppressed %d stderr line(s)",
                        self._namespace,
                        suppressed,
                    )
                    record_upstream_stderr_suppressed(namespace=self._namespace, count=suppressed)

        try:
            async with anyio.create_task_group() as report_tg:
                report_tg.start_soon(_emit_suppressed_report)
                while True:
                    try:
                        line = await reader.readline()
                    except ValueError:
                        _stderr_logger.warning(
                            "namespace=%s <stderr line exceeded %d bytes without a newline; skipped>",
                            self._namespace,
                            _STDERR_READER_LIMIT,
                        )
                        continue
                    if not line:
                        report_tg.cancel_scope.cancel()
                        suppressed = limiter.flush_suppressed_report()
                        if suppressed:
                            _stderr_logger.warning(
                                "namespace=%s suppressed %d stderr line(s)",
                                self._namespace,
                                suppressed,
                            )
                            record_upstream_stderr_suppressed(
                                namespace=self._namespace, count=suppressed
                            )
                        return
                    if not limiter.take_line():
                        continue
                    text = line.decode("utf-8", errors="replace")[:_MAX_STDERR_LINE_CHARS].rstrip(
                        "\n"
                    )
                    text = _mask_process_env_values(text, self._env)
                    _stderr_logger.info("namespace=%s %s", self._namespace, text)
        finally:
            transport.close()
