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


def test_probe_slot_is_not_released_by_the_clock(monkeypatch) -> None:
    clock = {"t": 1000.0}
    monkeypatch.setattr(
        "keystone_mcp.user_directory.circuit_breaker.time.monotonic",
        lambda: clock["t"],
    )
    breaker = CircuitBreaker(failure_threshold=1, recovery_seconds=5.0)
    breaker.record_failure()

    clock["t"] = 1005.0
    assert breaker.allow_request() is True
    clock["t"] = 1006.0
    assert breaker.allow_request() is False
    clock["t"] = 1060.0
    assert breaker.allow_request() is False

    breaker.record_success()
    assert breaker.state() == "closed"

    breaker.record_failure()
    clock["t"] += 5.0
    assert breaker.allow_request() is True
    breaker.record_failure()
    assert breaker.is_open() is True
    assert breaker.state() == "open"
    clock["t"] += 5.0
    assert breaker.allow_request() is True

    breaker.release_half_open_probe()
    assert breaker.allow_request() is True


def test_hanging_probe_blocks_second_probe_past_recovery_window(monkeypatch) -> None:
    clock = {"t": 1000.0}
    monkeypatch.setattr(
        "keystone_mcp.user_directory.circuit_breaker.time.monotonic",
        lambda: clock["t"],
    )
    breaker = CircuitBreaker(failure_threshold=1, recovery_seconds=5.0)
    assert breaker.allow_request() is True
    breaker.record_failure()
    clock["t"] += 5.0
    assert breaker.allow_request() is True
    clock["t"] += 1.0
    assert breaker.allow_request() is False
    clock["t"] += 5.0
    assert breaker.allow_request() is False


def test_is_open_kept_for_compatibility() -> None:
    breaker = CircuitBreaker(failure_threshold=1, recovery_seconds=0.2)
    assert breaker.is_open() is False

    breaker.record_failure()
    assert breaker.is_open() is True

    time.sleep(0.25)
    assert breaker.is_open() is False
    assert breaker.state() == "half_open"
