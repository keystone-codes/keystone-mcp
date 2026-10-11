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
