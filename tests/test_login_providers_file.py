"""Tests for YAML login provider file loading and legacy env warnings."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.config import ConfigError, Settings, startup_warnings
from keystone_mcp.login.config import load_login_providers_file
from keystone_mcp.login.factory import build_login_providers
from keystone_mcp.login.oidc import OidcLoginProvider


def _write(tmp_path: Path, content: str) -> str:
    path = tmp_path / "providers.yaml"
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return str(path)


def test_valid_file_builds_providers_in_order(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_OKTA_SECRET", "okta-secret")
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_GOOGLE_SECRET", "google-secret")
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: okta
            type: oidc
            title: Okta
            issuer: https://example.okta.com/oauth2/default
            client_id: okta-cid
            client_secret_env: KEYSTONE_MCP_LOGIN_OKTA_SECRET
          - name: google
            type: google
            client_id: g-cid
            client_secret_env: KEYSTONE_MCP_LOGIN_GOOGLE_SECRET
          - name: api_key
            type: api_key
        """,
    )
    settings = Settings(login_providers_path=path)
    providers = build_login_providers(settings, identity_provider=StaticIdentityProvider(set()))
    assert [p.name for p in providers] == ["okta", "google", "api_key"]
    assert isinstance(providers[0], OidcLoginProvider)
    assert providers[0].title == "Okta"


def test_unknown_key_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_OKTA_SECRET", "secret")
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: okta
            type: oidc
            issuer: https://example.okta.com
            client_id: cid
            client_secret_env: KEYSTONE_MCP_LOGIN_OKTA_SECRET
            typo_field: x
        """,
    )
    with pytest.raises(ConfigError, match="unknown key"):
        load_login_providers_file(path, deployment_profile="local")


def test_secret_in_file_is_refused(tmp_path):
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: okta
            type: oidc
            issuer: https://example.okta.com
            client_id: cid
            client_secret: embedded
        """,
    )
    with pytest.raises(ConfigError, match="secrets must not be stored"):
        load_login_providers_file(path, deployment_profile="local")


def test_missing_secret_env_is_refused_without_value(tmp_path):
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: okta
            type: oidc
            issuer: https://example.okta.com
            client_id: cid
            client_secret_env: KEYSTONE_MCP_MISSING_SECRET
        """,
    )
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_MISSING_SECRET"):
        load_login_providers_file(path, deployment_profile="local", environ={})


def test_duplicate_names_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_OKTA_SECRET", "s1")
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: okta
            type: oidc
            issuer: https://example.okta.com
            client_id: cid
            client_secret_env: KEYSTONE_MCP_LOGIN_OKTA_SECRET
          - name: okta
            type: oidc
            issuer: https://example.okta.com
            client_id: cid2
            client_secret_env: KEYSTONE_MCP_LOGIN_OKTA_SECRET
        """,
    )
    with pytest.raises(ConfigError, match="duplicate"):
        load_login_providers_file(path, deployment_profile="local")


def test_two_api_keys_refused(tmp_path):
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: api_key
            type: api_key
          - name: other_key
            type: api_key
        """,
    )
    with pytest.raises(ConfigError, match="api_key"):
        load_login_providers_file(path, deployment_profile="local")


def test_http_issuer_refused_in_production_allowed_on_local_loopback(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_KC_SECRET", "secret")
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: kc
            type: oidc
            issuer: http://127.0.0.1:8180/realms/dev
            client_id: cid
            client_secret_env: KEYSTONE_MCP_LOGIN_KC_SECRET
        """,
    )
    with pytest.raises(ConfigError, match="local"):
        load_login_providers_file(path, deployment_profile="production")
    load_login_providers_file(path, deployment_profile="local")


def test_legacy_google_variables_build_google_preset(monkeypatch):
    monkeypatch.delenv("KEYSTONE_MCP_LOGIN_PROVIDERS_PATH", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "google,api_key")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_ID", "g-cid")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", "g-secret")
    settings = Settings()
    providers = build_login_providers(settings, identity_provider=StaticIdentityProvider(set()))
    assert any(p.name == "google" for p in providers)


def test_legacy_variables_warn_deprecated():
    settings = Settings(
        google_client_id="x",
        enabled_login_methods=frozenset({"google"}),
    )
    warnings = startup_warnings(settings, environ={"KEYSTONE_MCP_GOOGLE_CLIENT_ID": "x"})
    assert any("deprecated since 0.5.0" in w for w in warnings)


def test_invalid_yaml_does_not_leak_secret_in_error(tmp_path):
    secret = "super-secret-yaml-leak-value"
    path = tmp_path / "providers.yaml"
    path.write_text(
        f"version: 1\nproviders:\n  - name: okta\n    client_secret: {secret}\n    bad: [\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError) as exc:
        load_login_providers_file(str(path), deployment_profile="local")
    message = str(exc.value)
    assert secret not in message
    assert exc.value.__cause__ is None


def test_require_email_verified_false_without_domain_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_ENTRA_SECRET", "secret")
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: entra
            type: oidc
            issuer: https://login.microsoftonline.com/tenant/v2.0
            client_id: cid
            client_secret_env: KEYSTONE_MCP_LOGIN_ENTRA_SECRET
            require_email_verified: false
        """,
    )
    with pytest.raises(ConfigError, match="allowed_domains"):
        load_login_providers_file(path, deployment_profile="local")


def test_require_email_verified_false_with_allowed_domains_accepted(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_ENTRA_SECRET", "secret")
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: entra
            type: oidc
            issuer: https://login.microsoftonline.com/tenant/v2.0
            client_id: cid
            client_secret_env: KEYSTONE_MCP_LOGIN_ENTRA_SECRET
            require_email_verified: false
            allowed_domains:
              - example.com
        """,
    )
    entries = load_login_providers_file(path, deployment_profile="local")
    assert entries[0].require_email_verified is False
    assert entries[0].allowed_domains == ("example.com",)


def test_require_email_verified_true_without_domains_accepted(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_OKTA_SECRET", "secret")
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: okta
            type: oidc
            issuer: https://example.okta.com
            client_id: cid
            client_secret_env: KEYSTONE_MCP_LOGIN_OKTA_SECRET
            require_email_verified: true
        """,
    )
    load_login_providers_file(path, deployment_profile="local")


def test_legacy_variables_ignored_when_file_set_warns(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_OKTA_SECRET", "secret")
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: okta
            type: oidc
            issuer: https://example.okta.com
            client_id: cid
            client_secret_env: KEYSTONE_MCP_LOGIN_OKTA_SECRET
        """,
    )
    settings = Settings(login_providers_path=path)
    warnings = startup_warnings(
        settings,
        environ={
            "KEYSTONE_MCP_GOOGLE_CLIENT_ID": "legacy",
            "KEYSTONE_MCP_LOGIN_PROVIDERS_PATH": path,
        },
    )
    assert any("ignored because KEYSTONE_MCP_LOGIN_PROVIDERS_PATH is set" in w for w in warnings)
