"""Refresh session marker and auth-code envelope format (0.6.0)."""

from __future__ import annotations

from mcp.server.auth.provider import AuthorizationCode

from keystone_mcp.auth.keystone_oauth_provider import (
    RefreshMeta,
    _encode_auth_code_envelope,
    encode_refresh_meta,
    parse_refresh_meta,
)
from support.legacy_markers import legacy_parse_auth_code_envelope, legacy_read_refresh_meta


def test_marker_roundtrip_new_fields():
    meta = RefreshMeta(
        auth_method="api_key",
        resource=None,
        interactive=False,
        auth_time=1_700_000_000,
        key_id=None,
        key_id_known=True,
        key_expires_at=1_800_000_000,
    )
    raw = encode_refresh_meta(meta)
    parsed = parse_refresh_meta(raw)
    assert parsed == meta
    assert '"key_id":null' in raw


def test_marker_0_5_0_is_readable():
    raw = '{"auth_method":"google","resource":"https://ks.example/","interactive":true}'
    meta = parse_refresh_meta(raw)
    assert meta is not None
    assert meta.auth_time is None
    assert meta.key_id_known is False


def test_marker_0_4_0_is_readable():
    raw = '{"auth_method":"google","resource":null}'
    meta = parse_refresh_meta(raw)
    assert meta is not None
    assert meta.interactive is True


def test_marker_bare_string_is_readable():
    meta = parse_refresh_meta("api_key")
    assert meta is not None
    assert meta.auth_method == "api_key"
    assert meta.interactive is False


def test_missing_or_broken_marker_is_none():
    for raw in (None, "", "{}", '{"auth_method": 5}'):
        assert parse_refresh_meta(raw) is None


def test_new_marker_is_readable_by_0_5_0_parser():
    meta = RefreshMeta(
        auth_method="api_key",
        resource="https://ks.example/mcp",
        interactive=False,
        auth_time=1_700_000_000,
        key_id="abc123",
        key_id_known=True,
        key_expires_at=1_800_000_000,
    )
    raw = encode_refresh_meta(meta)
    auth_method, resource, interactive = legacy_read_refresh_meta(raw)
    assert auth_method == "api_key"
    assert resource == "https://ks.example/mcp"
    assert interactive is False


def test_new_auth_code_envelope_is_readable_by_0_5_0_parser():
    code = AuthorizationCode(
        code="km_code_test",
        scopes=["keystone"],
        expires_at=1_800_000_000.0,
        client_id="client-1",
        code_challenge="challenge",
        redirect_uri="http://localhost/callback",
        redirect_uri_provided_explicitly=True,
        subject="user@example.com",
    )
    raw = _encode_auth_code_envelope(
        code,
        "api_key",
        False,
        auth_time=1_700_000_000,
        key_id="kid1",
        key_id_known=True,
        key_expires_at=1_800_000_000,
    )
    parsed = legacy_parse_auth_code_envelope(raw)
    assert parsed is not None
    envelope_code, auth_method, interactive = parsed
    assert envelope_code.code == "km_code_test"
    assert auth_method == "api_key"
    assert interactive is False
