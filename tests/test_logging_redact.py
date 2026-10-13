"""Tests for log redaction helpers."""

from __future__ import annotations

from keystone_mcp.observability.logging.redact import (
    redact_dict,
    redact_string,
    redact_url_credentials,
)


def test_redact_bearer_token() -> None:
    raw = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
    redacted = redact_string(raw)
    assert "eyJ" not in redacted
    assert "payload" not in redacted


def test_redact_redis_url_password() -> None:
    url = "redis://:s3cret@redis.internal:6379/0"
    redacted = redact_url_credentials(url)
    assert "s3cret" not in redacted
    assert "redis.internal" in redacted


def test_redact_email() -> None:
    redacted = redact_string("user@example.com failed login")
    assert "user@example.com" not in redacted
    assert "example.com" not in redacted


def test_redact_dict_sensitive_keys() -> None:
    payload = {"authorization": "Bearer x", "path": "/mcp", "nested": {"token": "abc"}}
    out = redact_dict(payload)
    assert out["authorization"] == "***REDACTED***"
    assert out["nested"]["token"] == "***REDACTED***"
    assert out["path"] == "/mcp"


def test_redact_dict_keystone_identity_header() -> None:
    payload = {"x-keystone-identity": "eyJhbGciOiJIUzI1NiJ9.payload.sig", "path": "/mcp"}
    out = redact_dict(payload)
    assert out["x-keystone-identity"] == "***REDACTED***"
    assert out["path"] == "/mcp"


def test_api_key_is_masked_keeping_key_id() -> None:
    key_id = "a" * 12
    secret = "A" * 43
    raw = f"Authorization: Bearer ksk_{key_id}_{secret}"
    redacted = redact_string(raw)
    assert secret not in redacted
    assert f"ksk_{key_id}_***" in redacted


def test_redact_bare_jwt_outside_bearer_prefix() -> None:
    """A JWT logged as a raw header value (no "Bearer " prefix, no key=value

    form) still gets redacted -- e.g. a dumped headers dict rendered as text.
    """
    raw = "X-Keystone-Identity: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbm4ifQ.c2ln"
    redacted = redact_string(raw)
    assert "eyJ" not in redacted
    assert "***REDACTED***" in redacted
