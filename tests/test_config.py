"""Tests for general settings parsing."""

from __future__ import annotations

import pytest

from keystone_mcp.config import ConfigError, Settings, load_settings, validate_settings


def test_login_brand_default():
    settings = Settings()
    assert settings.login_brand == "Keystone-MCP"


def test_login_brand_from_env(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_BRAND", "My Gateway")
    settings = load_settings()
    assert settings.login_brand == "My Gateway"


def test_login_brand_rejects_too_long(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_BRAND", "x" * 65)
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_LOGIN_BRAND"):
        load_settings()


def test_login_brand_rejects_newline(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_BRAND", "bad\nname")
    with pytest.raises(ConfigError, match="newline"):
        load_settings()


@pytest.mark.parametrize("value", [-1, 61])
def test_oauth_refresh_grace_seconds_rejects_out_of_range(monkeypatch, value: int):
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS", str(value))
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS"):
        validate_settings(load_settings())


@pytest.mark.parametrize("value", [0, 60])
def test_oauth_refresh_grace_seconds_accepts_bounds(monkeypatch, value: int):
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS", str(value))
    settings = load_settings()
    validate_settings(settings)
    assert settings.oauth_refresh_grace_seconds == value


def test_previous_signing_key_must_be_p256(monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    bad = ec.generate_private_key(ec.SECP384R1())
    pem = bad.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    settings = Settings(identity_signing_key_previous=pem)
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_IDENTITY_SIGNING_KEY_PREVIOUS"):
        validate_settings(settings)


def test_previous_without_current_warns():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    from keystone_mcp.config import startup_warnings

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    settings = Settings(identity_signing_key="", identity_signing_key_previous=pem)
    warnings = startup_warnings(settings)
    assert any(
        "KEYSTONE_MCP_IDENTITY_SIGNING_KEY_PREVIOUS" in w and "has no effect" in w for w in warnings
    )


def test_previous_key_not_in_repr():
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
    settings = Settings(identity_signing_key_previous=pem)
    rendered = repr(settings)
    assert "BEGIN PRIVATE KEY" not in rendered
    assert pem[:20] not in rendered
