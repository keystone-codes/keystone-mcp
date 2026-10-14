"""Tests for YAML login provider file loading and legacy env warnings."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from keystone_mcp.config import ConfigError, Settings, load_settings, startup_warnings
from keystone_mcp.login.config import load_login_providers_file
from keystone_mcp.login.factory import build_login_providers
from keystone_mcp.login.oidc import OidcLoginProvider
from support.test_env import require_redis_url


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
    providers = build_login_providers(settings, resolver=None)
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
    entries = load_login_providers_file(path, deployment_profile="local")
    assert entries[0].options.get("typo_field") == "x"


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
    settings = Settings(login_providers_path=path)
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_MISSING_SECRET"):
        build_login_providers(settings, resolver=None)


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
    settings_prod = Settings(login_providers_path=path, deployment_profile="production")
    with pytest.raises(ConfigError, match="local"):
        build_login_providers(settings_prod, resolver=None)
    settings_local = Settings(login_providers_path=path, deployment_profile="local")
    build_login_providers(settings_local, resolver=None)


def test_legacy_google_variables_build_google_preset(monkeypatch):
    monkeypatch.delenv("KEYSTONE_MCP_LOGIN_PROVIDERS_PATH", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "google,api_key")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_ID", "g-cid")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", "g-secret")
    settings = Settings()
    providers = build_login_providers(settings, resolver=None)
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
    settings = Settings(login_providers_path=path)
    with pytest.raises(ConfigError, match="allowed_domains"):
        build_login_providers(settings, resolver=None)


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
    settings = Settings(login_providers_path=path)
    providers = build_login_providers(settings, resolver=None)
    assert providers[0].config.require_email_verified is False
    assert providers[0].config.allowed_domains == ("example.com",)


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


def _production_providers_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "https://mcp.example.com")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "local")
    monkeypatch.setenv(
        "KEYSTONE_MCP_USERS_DB_URL",
        "postgresql+psycopg://u:p@db:5432/keystone",
    )
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "salt")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())


def test_production_providers_file_api_key_with_interactive_refuses_despite_env_methods(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_GOOGLE_SECRET", "google-secret")
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: google
            type: google
            client_id: g-cid
            client_secret_env: KEYSTONE_MCP_LOGIN_GOOGLE_SECRET
          - name: api_key
            type: api_key
        """,
    )
    _production_providers_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_PROVIDERS_PATH", path)
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "google")
    monkeypatch.setenv("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", "google")
    with pytest.raises(ConfigError, match="interactive provider"):
        load_settings()


def test_production_providers_file_interactive_only_loads_when_env_defaults_api_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_GOOGLE_SECRET", "google-secret")
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: google
            type: google
            client_id: g-cid
            client_secret_env: KEYSTONE_MCP_LOGIN_GOOGLE_SECRET
        """,
    )
    _production_providers_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_PROVIDERS_PATH", path)
    monkeypatch.delenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", raising=False)
    settings = load_settings()
    assert settings.api_key_login_enabled is True


def test_production_providers_file_api_key_with_http_directory_refuses_despite_env_methods(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: api_key
            type: api_key
        """,
    )
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "https://mcp.example.com")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "http")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_URL", "http://users:8080")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_TOKEN", "token")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "salt")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_PROVIDERS_PATH", path)
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "google")
    monkeypatch.setenv("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", "google")
    with pytest.raises(ConfigError, match="API-key sign-in in production needs"):
        load_settings()


def test_email_claim_other_than_email_requires_verified_claim(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_ENTRA_SECRET", "secret")
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: entra
            type: oidc
            issuer: https://idp.test
            client_id: cid
            client_secret_env: KEYSTONE_MCP_LOGIN_ENTRA_SECRET
            email_claim: preferred_username
        """,
    )
    settings = Settings(login_providers_path=path)
    with pytest.raises(ConfigError) as exc_info:
        build_login_providers(settings, resolver=None)
    message = str(exc_info.value)
    assert "email_verified_claim" in message
    assert "require_email_verified: false" in message


@pytest.mark.asyncio
async def test_email_verified_claim_is_used(tmp_path, monkeypatch):
    from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
    from keystone_mcp.login.oidc import OidcLoginProvider

    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_ENTRA_SECRET", "secret")
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: entra
            type: oidc
            issuer: https://idp.test
            client_id: cid
            client_secret_env: KEYSTONE_MCP_LOGIN_ENTRA_SECRET
            email_claim: upn
            email_verified_claim: upn_verified
        """,
    )
    settings = Settings(login_providers_path=path)
    built = build_login_providers(settings, resolver=None)[0]
    assert isinstance(built, OidcLoginProvider)

    fake = FakeOidcIssuer(
        issuer=built.config.issuer,
        client_id=built.config.client_id,
        client_secret=built.config.client_secret,
    )
    provider = OidcLoginProvider(built.config, http_client_factory=fake.http_client)
    fake.user.extra_claims = {
        "upn": "alice@example.com",
        "upn_verified": True,
        "email_verified": True,
    }
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    params = await fake.authorize(redirect.url)
    identity = await provider.complete(
        params=params, callback_url="http://app/cb", attempt=redirect.attempt
    )
    assert identity.email == "alice@example.com"

    fake.user.extra_claims = {"upn": "alice@example.com", "email_verified": True}
    redirect2 = await provider.begin(state="st2", callback_url="http://app/cb")
    params2 = await fake.authorize(redirect2.url)
    from keystone_mcp.login.protocol import LoginRejected

    with pytest.raises(LoginRejected) as exc_info:
        await provider.complete(
            params=params2, callback_url="http://app/cb", attempt=redirect2.attempt
        )
    assert exc_info.value.reason == "email_unverified"


@pytest.mark.asyncio
async def test_email_claim_email_unchanged(tmp_path, monkeypatch):
    from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
    from keystone_mcp.login.oidc import OidcLoginProvider

    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_OKTA_SECRET", "secret")
    path = _write(
        tmp_path,
        """
        version: 1
        providers:
          - name: okta
            type: oidc
            issuer: https://idp.test
            client_id: cid
            client_secret_env: KEYSTONE_MCP_LOGIN_OKTA_SECRET
        """,
    )
    settings = Settings(login_providers_path=path)
    built = build_login_providers(settings, resolver=None)[0]
    assert isinstance(built, OidcLoginProvider)
    fake = FakeOidcIssuer(
        issuer="https://idp.test",
        client_id=built.config.client_id,
        client_secret=built.config.client_secret,
    )
    provider = OidcLoginProvider(built.config, http_client_factory=fake.http_client)
    fake.user.email = "alice@example.com"
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    params = await fake.authorize(redirect.url)
    identity = await provider.complete(
        params=params, callback_url="http://app/cb", attempt=redirect.attempt
    )
    assert identity.email == "alice@example.com"
