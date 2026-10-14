"""Unit tests for the users-directory circuit breaker."""

from __future__ import annotations

import time

from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker


def test_half_open_allows_exactly_one_probe() -> None:
    breaker = CircuitBreaker(failure_threshold=1, recovery_seconds=0.05)
    breaker.record_failure()
    time.sleep(0.06)

    results = [breaker.allow_request() for _ in range(10)]
    assert results.count(True) == 1
    assert results.count(False) == 9


def test_probe_success_closes() -> None:
    breaker = CircuitBreaker(failure_threshold=1, recovery_seconds=0.05)
    breaker.record_failure()
    time.sleep(0.06)
    assert breaker.allow_request() is True
    assert breaker.state() == "half_open"

    breaker.record_success()
    assert breaker.state() == "closed"
    assert breaker.allow_request() is True


def test_probe_failure_reopens_for_full_pause() -> None:
    breaker = CircuitBreaker(failure_threshold=1, recovery_seconds=0.2)
    breaker.record_failure()
    time.sleep(0.25)
    assert breaker.allow_request() is True

    breaker.record_failure()
    assert breaker.is_open() is True
    assert breaker.allow_request() is False


def test_stale_probe_slot_is_released_after_recovery_seconds() -> None:
    breaker = CircuitBreaker(failure_threshold=1, recovery_seconds=0.05)
    breaker.record_failure()
    time.sleep(0.06)
    assert breaker.allow_request() is True
    assert breaker.allow_request() is False

    time.sleep(0.06)
    assert breaker.allow_request() is True


def test_is_open_kept_for_compatibility() -> None:
    breaker = CircuitBreaker(failure_threshold=1, recovery_seconds=0.2)
    assert breaker.is_open() is False

    breaker.record_failure()
    assert breaker.is_open() is True

    time.sleep(0.25)
    assert breaker.is_open() is False
    assert breaker.state() == "half_open"
