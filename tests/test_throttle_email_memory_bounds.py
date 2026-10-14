"""`LoginAttemptThrottle._email_failures` does not grow without bound (email throttle).

Before this fix, `check_email_failures` read `self._email_failures[normalized]`
on a `defaultdict`: merely *checking* an email (no prior failure recorded)
created a permanent empty bucket for it. An attacker who tries one login per
email address, never repeating one, could grow the dict without bound purely
by probing — no failed login, nor any throttling, was required to plant an
entry.

The fix mirrors `_ip_hits` : an `OrderedDict` with a periodic
sweep that drops buckets that aged out of the window, and a hard cap on how
many distinct emails are tracked at once (oldest evicted first) — plus two
narrower points this finding also calls out: a bare *check* never creates an
entry (only `record_login_failure` does), and an excessively long email is
capped before it is ever used as a dict key.
"""

from __future__ import annotations

from keystone_mcp.auth.throttle import (
    _MAX_EMAIL_LEN,
    _MAX_TRACKED_EMAILS,
    LoginAttemptThrottle,
)


def test_checking_an_email_with_no_failures_creates_no_entry() -> None:
    throttle = LoginAttemptThrottle(ip_max=0, email_max=5, window_seconds=60)

    allowed, retry = throttle.check_email_failures("nobody@example.com", now=0.0)

    assert allowed is True
    assert retry == 0
    assert "nobody@example.com" not in throttle._email_failures


def test_probing_many_emails_with_no_failures_never_grows_the_table() -> None:
    """The exact attack the email throttle bounds close: one check per distinct email."""
    throttle = LoginAttemptThrottle(ip_max=0, email_max=5, window_seconds=60)

    for i in range(50_000):
        throttle.check_email_failures(f"probe-{i}@example.com", now=0.0)

    assert len(throttle._email_failures) == 0


def test_recording_a_failure_does_create_an_entry() -> None:
    throttle = LoginAttemptThrottle(ip_max=0, email_max=5, window_seconds=60)

    throttle.record_login_failure("someone@example.com", now=0.0)

    assert "someone@example.com" in throttle._email_failures
    allowed, _retry = throttle.check_email_failures("someone@example.com", now=0.0)
    assert allowed is True  # one failure, well under email_max=5


def test_stale_email_bucket_disappears_after_a_sweep(monkeypatch) -> None:
    monkeypatch.setattr("keystone_mcp.auth.throttle._EMAIL_SWEEP_EVERY_N_CALLS", 100)
    throttle = LoginAttemptThrottle(ip_max=0, email_max=5, window_seconds=60)

    throttle.record_login_failure("stale@example.com", now=0.0)
    assert "stale@example.com" in throttle._email_failures

    for i in range(100):
        throttle.record_login_failure(f"other-{i}@example.com", now=1000.0)

    assert "stale@example.com" not in throttle._email_failures


def test_tracked_email_count_is_capped_with_oldest_evicted_first(monkeypatch) -> None:
    monkeypatch.setattr("keystone_mcp.auth.throttle._MAX_TRACKED_EMAILS", 3)
    monkeypatch.setattr("keystone_mcp.auth.throttle._EMAIL_SWEEP_EVERY_N_CALLS", 1_000_000)
    throttle = LoginAttemptThrottle(ip_max=0, email_max=100, window_seconds=600)

    for i in range(5):
        throttle.record_login_failure(f"user{i}@example.com", now=float(i))

    assert len(throttle._email_failures) == 3
    assert "user0@example.com" not in throttle._email_failures
    assert "user1@example.com" not in throttle._email_failures
    assert "user2@example.com" in throttle._email_failures
    assert "user3@example.com" in throttle._email_failures
    assert "user4@example.com" in throttle._email_failures


def test_defaults_are_generous_enough_for_normal_traffic() -> None:
    assert _MAX_TRACKED_EMAILS == 20_000
    assert _MAX_EMAIL_LEN == 320


def test_overlong_email_is_capped_before_being_used_as_a_key() -> None:
    throttle = LoginAttemptThrottle(ip_max=0, email_max=5, window_seconds=60)
    long_local = "a" * 1000
    email = f"{long_local}@example.com"

    throttle.record_login_failure(email, now=0.0)

    assert len(throttle._email_failures) == 1
    (stored_key,) = throttle._email_failures.keys()
    assert len(stored_key) <= _MAX_EMAIL_LEN


def test_two_overlong_emails_sharing_a_prefix_share_one_bucket() -> None:
    """Truncating merges keys rather than refusing them: safe, since it can

    only make the limit *more* conservative (two attacker-controlled long
    strings now share one budget), never less.
    """
    throttle = LoginAttemptThrottle(ip_max=0, email_max=1, window_seconds=60)
    prefix = "a" * 400
    throttle.record_login_failure(f"{prefix}1@example.com", now=0.0)

    allowed, _retry = throttle.check_email_failures(f"{prefix}2@example.com", now=0.0)

    assert allowed is False  # same truncated key, budget already spent
