"""Simple consecutive-failure circuit breaker for the users directory."""

from __future__ import annotations

import threading
import time


class CircuitBreaker:
    """Opens after consecutive failures; half-opens after recovery timeout."""

    def __init__(self, *, failure_threshold: int, recovery_seconds: float) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        self._failure_threshold = failure_threshold
        self._recovery_seconds = recovery_seconds
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self._probe_started_at: float | None = None
        self._lock = threading.Lock()

    def is_open(self) -> bool:
        if self._opened_at is None:
            return False
        elapsed = time.monotonic() - self._opened_at
        if elapsed >= self._recovery_seconds:
            return False
        return True

    def state(self) -> str:
        with self._lock:
            return self._state_locked()

    def _state_locked(self) -> str:
        if self._opened_at is None:
            return "closed"
        elapsed = time.monotonic() - self._opened_at
        if elapsed < self._recovery_seconds:
            return "open"
        return "half_open"

    def _half_open_locked(self) -> bool:
        if self._opened_at is None:
            return False
        elapsed = time.monotonic() - self._opened_at
        return elapsed >= self._recovery_seconds

    def _probe_slot_taken_locked(self) -> bool:
        if self._probe_started_at is None:
            return False
        return time.monotonic() - self._probe_started_at < self._recovery_seconds

    def allow_request(self) -> bool:
        """Whether a new upstream call may start (half-open allows one probe)."""
        with self._lock:
            if self._opened_at is None:
                return True
            elapsed = time.monotonic() - self._opened_at
            if elapsed < self._recovery_seconds:
                return False
            if self._probe_slot_taken_locked():
                return False
            self._probe_started_at = time.monotonic()
            return True

    def record_success(self) -> None:
        with self._lock:
            self._consecutive_failures = 0
            self._opened_at = None
            self._probe_started_at = None

    def release_half_open_probe(self) -> None:
        """Drop a taken half-open probe without changing open/recovery state."""
        with self._lock:
            if self._half_open_locked():
                self._probe_started_at = None

    def record_failure(self) -> None:
        with self._lock:
            if self._half_open_locked():
                self._probe_started_at = None
                self._opened_at = time.monotonic()
                return
            self._probe_started_at = None
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._failure_threshold:
                self._opened_at = time.monotonic()

    def reset(self) -> None:
        with self._lock:
            self._consecutive_failures = 0
            self._opened_at = None
            self._probe_started_at = None
