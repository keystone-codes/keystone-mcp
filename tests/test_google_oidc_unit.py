"""Unit tests for Google OIDC helper primitives."""

from __future__ import annotations

import base64
import json
import time

import pytest

from keystone_mcp.auth.google_oidc import (
    GoogleIdTokenError,
    email_matches_allowed_domain,
)
from support.google_oidc_fixtures import (
    build_mock_google_oidc,
    generate_google_test_keys,
    sign_google_id_token,
)


def test_email_matches_allowed_domain_requires_hd_and_email_suffix():
    assert email_matches_allowed_domain(
        "user@example.com", "example.com", hosted_domain="example.com"
    )
    assert not email_matches_allowed_domain("user@example.com", "example.com")
    assert not email_matches_allowed_domain(
        "user@other.com", "example.com", hosted_domain="example.com"
    )
    assert not email_matches_allowed_domain(
        "user@other.com", "example.com", hosted_domain="other.com"
    )
    assert email_matches_allowed_domain("user@example.com", "")


def test_verify_id_token_happy_path():
    mock = build_mock_google_oidc("http://localhost/login/google/callback")
    nonce = mock.client.new_nonce()
    token = sign_google_id_token(mock.keys, email="alice@example.com", nonce=nonce)
    identity = mock.client.verify_id_token(token, nonce)
    assert identity.email == "alice@example.com"
    assert identity.email_verified is True


def test_verify_id_token_rejects_wrong_nonce():
    keys = generate_google_test_keys()
    mock = build_mock_google_oidc("http://localhost/login/google/callback")
    nonce = mock.client.new_nonce()
    token = sign_google_id_token(keys, email="alice@example.com", nonce="other")
    with pytest.raises(GoogleIdTokenError):
        mock.client.verify_id_token(token, nonce)


def test_verify_id_token_rejects_hs256_and_alg_none():
    mock = build_mock_google_oidc("http://localhost/login/google/callback")
    nonce = mock.client.new_nonce()
    hs_token = sign_google_id_token(
        mock.keys,
        email="alice@example.com",
        nonce=nonce,
        algorithm="HS256",
        signing_key="test-secret",
    )
    with pytest.raises(GoogleIdTokenError):
        mock.client.verify_id_token(hs_token, nonce)

    header = (
        base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        .rstrip(b"=")
        .decode()
    )
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {
                    "iss": "https://accounts.google.com",
                    "aud": mock.keys.client_id,
                    "sub": "x",
                    "email": "alice@example.com",
                    "email_verified": True,
                    "nonce": nonce,
                    "exp": int(time.time()) + 3600,
                }
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    none_token = f"{header}.{payload}."
    with pytest.raises(GoogleIdTokenError):
        mock.client.verify_id_token(none_token, nonce)


def test_verify_id_token_azp_soft_check():
    mock = build_mock_google_oidc("http://localhost/login/google/callback")
    nonce = mock.client.new_nonce()
    ok_token = sign_google_id_token(
        mock.keys,
        email="alice@example.com",
        nonce=nonce,
        azp=mock.keys.client_id,
    )
    identity = mock.client.verify_id_token(ok_token, nonce)
    assert identity.email == "alice@example.com"

    bad_azp = sign_google_id_token(
        mock.keys,
        email="alice@example.com",
        nonce=nonce,
        azp="other-client",
    )
    with pytest.raises(GoogleIdTokenError) as exc_info:
        mock.client.verify_id_token(bad_azp, nonce)
    assert exc_info.value.code == "google_azp"


def test_build_authorization_url_includes_hd_when_configured():
    mock = build_mock_google_oidc("http://localhost/login/google/callback")
    url = mock.client.build_authorization_url(
        state="s",
        nonce="n",
        code_challenge="c",
        hosted_domain="example.com",
    )
    assert "hd=example.com" in url
