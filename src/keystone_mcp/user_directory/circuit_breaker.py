"""Simple consecutive-failure circuit breaker for the users directory."""

from __future__ import annotations

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

    def is_open(self) -> bool:
        if self._opened_at is None:
            return False
        elapsed = time.monotonic() - self._opened_at
        if elapsed >= self._recovery_seconds:
            return False
        return True

    def record_success(self) -> None:
        self._consecutive_failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._failure_threshold:
            self._opened_at = time.monotonic()

    def reset(self) -> None:
        self._consecutive_failures = 0
        self._opened_at = None
