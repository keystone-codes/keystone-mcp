"""Per-upstream concurrency, shared rate, and circuit breaker (registry ``limits``)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Literal

import anyio
import httpx
import httpx2
from fastmcp.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from mcp_types.jsonrpc import REQUEST_TIMEOUT

from keystone_mcp.auth.rate_window import SlidingWindow
from keystone_mcp.config import UpstreamLimits
from keystone_mcp.router.stdio_process import UpstreamProcessUnavailableError
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker

if TYPE_CHECKING:
    from keystone_mcp.observability.service import RbacObservability

logger = logging.getLogger(__name__)

_CONCURRENCY_WAIT_CAP_SECONDS = 30.0

LimitReason = Literal["rate", "concurrency", "circuit_open"]


class UpstreamLimitError(ToolError):
    """Upstream refused the call before reaching the downstream service."""

    def __init__(self, message: str, *, reason: LimitReason) -> None:
        super().__init__(message)
        self.reason = reason


def is_upstream_failure(exc: BaseException) -> bool:
    """Whether an exception counts as a transport/time failure for the breaker."""
    if isinstance(exc, UpstreamProcessUnavailableError):
        return True
    if isinstance(exc, asyncio.CancelledError):
        return False
    try:
        cancelled = anyio.get_cancelled_exc_class()
    except anyio.NoEventLoopError:
        cancelled = None
    if cancelled is not None and isinstance(exc, cancelled):
        return False
    if isinstance(exc, TimeoutError):
        return True
    if type(exc).__name__ == "TimeoutError" and type(exc).__module__.startswith("anyio"):
        return True
    if isinstance(exc, (httpx.TransportError, httpx2.TransportError)):
        return True
    if isinstance(exc, MCPError) and exc.code == REQUEST_TIMEOUT:
        return True
    if isinstance(exc, ToolError):
        if exc.__cause__ is not None and is_upstream_failure(exc.__cause__):
            return True
        if "failed to connect" in str(exc).lower():
            return True
        return False
    if isinstance(exc, RuntimeError) and "failed to connect" in str(exc).lower():
        return True
    return False


def limits_are_effective(limits: UpstreamLimits) -> bool:
    return (
        limits.concurrency is not None
        or limits.rate is not None
        or limits.breaker_failures is not None
    )


def build_upstream_guard(
    namespace: str,
    limits: UpstreamLimits,
    *,
    window: SlidingWindow,
    observability: RbacObservability | None,
) -> UpstreamGuard:
    return UpstreamGuard(namespace, limits, window=window, observability=observability)


class UpstreamGuard:
    """Serializes and rate-limits proxied calls for one upstream namespace.

    F03 may replace the guard when registry ``limits`` change; calls already
    inside ``call()`` finish on the guard instance they entered.
    """

    def __init__(
        self,
        namespace: str,
        limits: UpstreamLimits,
        *,
        window: SlidingWindow,
        observability: RbacObservability | None,
    ) -> None:
        self._namespace = namespace
        self._limits = limits
        self._window = window
        self._observability = observability
        self._inflight = 0
        self._breaker: CircuitBreaker | None = None
        if limits.breaker_failures is not None:
            self._breaker = CircuitBreaker(
                failure_threshold=limits.breaker_failures,
                recovery_seconds=float(limits.breaker_recovery_seconds),
            )
        self._semaphore: asyncio.Semaphore | None = None
        if limits.concurrency is not None:
            self._semaphore = asyncio.Semaphore(limits.concurrency)

    def state(self) -> dict[str, object]:
        circuit = self._breaker.state() if self._breaker is not None else "closed"
        return {"circuit": circuit, "inflight": self._inflight}

    @asynccontextmanager
    async def call(
        self,
        *,
        timeout: float,
        slot_wait_timeout: float | None = None,
    ) -> AsyncIterator[None]:
        half_open_probe = False
        call_error: BaseException | None = None
        if self._breaker is not None:
            if not self._breaker.allow_request():
                self._record_rejection("circuit_open")
                raise UpstreamLimitError(
                    f"upstream {self._namespace} is temporarily unavailable after "
                    "repeated failures; retry later",
                    reason="circuit_open",
                )
            half_open_probe = self._breaker.state() == "half_open"
            self._sync_circuit_gauge()

        if self._limits.rate is not None:
            decision = await self._window.hit(
                f"upstream:{self._namespace}",
                limit=self._limits.rate,
                window_seconds=int(self._limits.window_seconds),
            )
            if not decision.allowed:
                self._record_rejection("rate")
                self._release_half_open_probe(half_open_probe)
                raise UpstreamLimitError(
                    f"upstream {self._namespace} is over its call limit; "
                    f"retry in {decision.retry_after}s",
                    reason="rate",
                )

        acquired = False
        if self._semaphore is not None:
            wait_for_slot = slot_wait_timeout if slot_wait_timeout is not None else timeout
            wait_budget = min(wait_for_slot, _CONCURRENCY_WAIT_CAP_SECONDS)
            try:
                await asyncio.wait_for(self._semaphore.acquire(), timeout=wait_budget)
            except TimeoutError:
                self._record_rejection("concurrency")
                self._release_half_open_probe(half_open_probe)
                raise UpstreamLimitError(
                    f"upstream {self._namespace} is busy; retry later",
                    reason="concurrency",
                ) from None
            acquired = True

        self._inflight += 1
        self._set_inflight_gauge()
        try:
            yield
        except asyncio.CancelledError as exc:
            call_error = exc
            if half_open_probe and self._breaker is not None:
                self._breaker.record_failure()
                self._sync_circuit_gauge()
            raise
        except BaseException as exc:
            call_error = exc
            raise
        finally:
            if self._breaker is not None and call_error is None:
                self._breaker.record_success()
                self._sync_circuit_gauge()
            elif self._breaker is not None and call_error is not None:
                if call_error is asyncio.CancelledError:
                    pass
                elif is_upstream_failure(call_error):
                    self._breaker.record_failure()
                    self._sync_circuit_gauge()
                else:
                    self._release_half_open_probe(half_open_probe)
            self._inflight -= 1
            self._set_inflight_gauge()
            if acquired and self._semaphore is not None:
                self._semaphore.release()

    def _release_half_open_probe(self, half_open_probe: bool) -> None:
        if half_open_probe and self._breaker is not None:
            self._breaker.release_half_open_probe()
            self._sync_circuit_gauge()

    def _record_rejection(self, reason: LimitReason) -> None:
        if self._observability is None:
            return
        try:
            self._observability.metrics.record_upstream_limit_rejection(
                namespace=self._namespace,
                reason=reason,
            )
        except Exception:
            logger.warning("upstream limit rejection metric failed", exc_info=True)

    def _set_inflight_gauge(self) -> None:
        if self._observability is None:
            return
        try:
            self._observability.metrics.set_upstream_inflight(
                namespace=self._namespace,
                inflight=self._inflight,
            )
        except Exception:
            logger.warning("upstream inflight metric failed", exc_info=True)

    def _sync_circuit_gauge(self) -> None:
        if self._observability is None or self._breaker is None:
            return
        try:
            self._observability.metrics.set_upstream_circuit_state(
                namespace=self._namespace,
                state=self._breaker.state(),
            )
        except Exception:
            logger.warning("upstream circuit gauge failed", exc_info=True)
