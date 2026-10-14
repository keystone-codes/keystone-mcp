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


def test_well_known_tokens_are_masked() -> None:
    samples = [
        "ghp_" + "a" * 36,
        "gho_" + "b" * 36,
        "ghu_" + "c" * 36,
        "ghs_" + "d" * 36,
        "ghr_" + "e" * 36,
        "github_pat_" + "f" * 36,
        "glpat-" + "g" * 36,
        "xoxb-" + "h" * 36,
        "sk-" + "i" * 36,
        "sk-proj-" + "j" * 36,
        "sk-ant-" + "k" * 36,
        "AKIA" + "L" * 16,
    ]
    for token in samples:
        assert token not in redact_string(f"leak {token} end")


def test_ordinary_words_are_not_masked() -> None:
    assert redact_string("use sk-learn for risk-free modeling") == (
        "use sk-learn for risk-free modeling"
    )


def test_api_key_ending_with_dash_is_masked() -> None:
    key_id = "0123456789ab"
    secret = "A" * 42 + "-"
    raw = f"issued ksk_{key_id}_{secret} done"
    redacted = redact_string(raw)
    assert secret not in redacted
    assert f"ksk_{key_id}_***" in redacted


def test_api_key_ending_with_underscore_is_masked() -> None:
    key_id = "0123456789ab"
    secret = "A" * 42 + "_"
    raw = f"token ksk_{key_id}_{secret}"
    redacted = redact_string(raw)
    assert secret not in redacted
    assert f"ksk_{key_id}_***" in redacted


def test_keystone_access_and_refresh_tokens_are_masked() -> None:
    at = "km_at_" + "x" * 43
    rt = "km_rt_" + ("y" * 42) + "-"
    for token in (at, rt):
        redacted = redact_string(f"prefix {token}")
        assert token not in redacted
        assert token[:6] + "***" in redacted
    end_line = redact_string(f"done {rt}")
    assert rt not in end_line
    assert "km_rt_***" in end_line


def test_bearer_token_ending_with_dash_is_masked() -> None:
    token = "a" * 20 + "-"
    raw = f"Authorization: Bearer {token}"
    redacted = redact_string(raw)
    assert token not in redacted
    assert "***REDACTED***" in redacted


def test_jwt_and_identity_header_are_masked() -> None:
    jwt_line = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbm4ifQ.c2ln"
    assert jwt_line not in redact_string(f"log {jwt_line} end")
    payload = {"x-keystone-identity": jwt_line, "path": "/mcp"}
    out = redact_dict(payload)
    assert out["x-keystone-identity"] == "***REDACTED***"


def test_longer_random_string_is_not_masked_as_key() -> None:
    key_id = "0123456789ab"
    too_long = "A" * 44
    raw = f"ksk_{key_id}_{too_long}"
    assert raw in redact_string(raw)


def test_redact_bare_jwt_outside_bearer_prefix() -> None:
    """A JWT logged as a raw header value (no "Bearer " prefix, no key=value

    form) still gets redacted -- e.g. a dumped headers dict rendered as text.
    """
    raw = "X-Keystone-Identity: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbm4ifQ.c2ln"
    redacted = redact_string(raw)
    assert "eyJ" not in redacted
    assert "***REDACTED***" in redacted
