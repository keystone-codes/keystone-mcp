"""`LoginAttemptThrottle._ip_hits` does not grow without bound (A11 finding #6).

Before this fix, every distinct source IP that ever called `check_ip` left a
bucket behind in `_ip_hits` forever: the sliding-window prune only runs on the
bucket for the key being looked up, so a key that is never looked up again
(trivial to arrange with IPv6, which offers an effectively unlimited pool of
addresses) was never cleaned up. An attacker who never repeats an address
could grow the dict without bound.

The fix adds two independent bounds: a periodic sweep that drops buckets
whose most recent hit has aged out of the window, and a hard cap on how many
distinct addresses are tracked at once (oldest evicted first).
"""

from __future__ import annotations

from keystone_mcp.auth.throttle import (
    _MAX_TRACKED_IPS,
    _SWEEP_EVERY_N_CALLS,
    LoginAttemptThrottle,
)


def test_stale_ip_bucket_disappears_after_a_sweep() -> None:
    throttle = LoginAttemptThrottle(ip_max=5, email_max=0, window_seconds=60)

    allowed, _retry = throttle.check_ip("198.51.100.1", now=0.0)
    assert allowed is True
    assert "198.51.100.1" in throttle._ip_hits

    # Enough further calls (from other addresses, well past the window) to
    # trigger the periodic sweep without touching "198.51.100.1" again.
    for i in range(_SWEEP_EVERY_N_CALLS):
        throttle.check_ip(f"203.0.113.{i % 250}", now=1000.0)

    assert "198.51.100.1" not in throttle._ip_hits


def test_sweep_does_not_drop_a_bucket_still_inside_the_window() -> None:
    throttle = LoginAttemptThrottle(ip_max=5, email_max=0, window_seconds=600)

    throttle.check_ip("198.51.100.1", now=0.0)
    for i in range(_SWEEP_EVERY_N_CALLS):
        # Still within the 600s window.
        throttle.check_ip(f"203.0.113.{i % 250}", now=10.0)

    assert "198.51.100.1" in throttle._ip_hits


def test_direct_sweep_call_drops_only_buckets_outside_the_window() -> None:
    throttle = LoginAttemptThrottle(ip_max=5, email_max=0, window_seconds=60)
    throttle.check_ip("198.51.100.1", now=0.0)
    throttle.check_ip("198.51.100.2", now=50.0)

    throttle._sweep_ip_hits(ts=61.0)

    assert "198.51.100.1" not in throttle._ip_hits
    assert "198.51.100.2" in throttle._ip_hits


def test_tracked_ip_count_is_capped_with_oldest_evicted_first(monkeypatch) -> None:
    monkeypatch.setattr("keystone_mcp.auth.throttle._MAX_TRACKED_IPS", 3)
    monkeypatch.setattr("keystone_mcp.auth.throttle._SWEEP_EVERY_N_CALLS", 1_000_000)
    throttle = LoginAttemptThrottle(ip_max=100, email_max=0, window_seconds=600)

    for i in range(5):
        throttle.check_ip(f"198.51.100.{i}", now=float(i))

    assert len(throttle._ip_hits) == 3
    # The two oldest (never looked up again) are gone; the three most recent
    # survive.
    assert "198.51.100.0" not in throttle._ip_hits
    assert "198.51.100.1" not in throttle._ip_hits
    assert "198.51.100.2" in throttle._ip_hits
    assert "198.51.100.3" in throttle._ip_hits
    assert "198.51.100.4" in throttle._ip_hits


def test_capacity_eviction_respects_recently_checked_addresses(monkeypatch) -> None:
    """Re-checking an address refreshes its place, so it is not evicted first."""
    monkeypatch.setattr("keystone_mcp.auth.throttle._MAX_TRACKED_IPS", 3)
    monkeypatch.setattr("keystone_mcp.auth.throttle._SWEEP_EVERY_N_CALLS", 1_000_000)
    throttle = LoginAttemptThrottle(ip_max=100, email_max=0, window_seconds=600)

    throttle.check_ip("198.51.100.0", now=0.0)
    throttle.check_ip("198.51.100.1", now=1.0)
    throttle.check_ip("198.51.100.2", now=2.0)
    # Touch the oldest address again before a fourth, different address
    # arrives: it should not be the one evicted.
    throttle.check_ip("198.51.100.0", now=3.0)
    throttle.check_ip("198.51.100.3", now=4.0)

    assert len(throttle._ip_hits) == 3
    assert "198.51.100.0" in throttle._ip_hits
    assert "198.51.100.1" not in throttle._ip_hits


def test_defaults_are_generous_enough_for_normal_traffic() -> None:
    """Pin the defaults so a future change does not silently shrink them."""
    assert _MAX_TRACKED_IPS == 20_000
    assert _SWEEP_EVERY_N_CALLS == 2_000
