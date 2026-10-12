"""Tests for split login-method and RBAC configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from keystone_mcp.config import (
    ConfigError,
    Settings,
    load_settings,
    validate_settings,
)


def test_default_settings_preserve_pre_r4_api_key_mode():
    settings = Settings()
    validate_settings(settings)
    assert settings.primary_login_method == "api_key"
    assert settings.enabled_login_methods == frozenset({"api_key"})
    assert settings.rbac_enabled is False
    assert settings.api_key_login_enabled is True
    assert settings.google_login_enabled is False


def test_load_settings_defaults_from_env(monkeypatch):
    monkeypatch.delenv("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", raising=False)
    settings = load_settings()
    assert settings.primary_login_method == "api_key"
    assert settings.rbac_enabled is False


def test_login_methods_are_independent_from_rbac(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", "google")
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "google,api_key")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", "client-secret")
    # The built-in (local, default) users directory needs neither URL nor
    # token; this test is about login methods, not the users directory.
    # RBAC defaults to off, which is all this test needs.
    settings = load_settings()
    assert settings.primary_login_method == "google"
    assert settings.enabled_login_methods == frozenset({"google", "api_key"})
    assert settings.rbac_enabled is False


def test_google_login_requires_users_directory_without_rbac(monkeypatch):
    # The built-in (local) users directory needs neither URL nor token, so this
    # check only bites with the http backend (fork-only; see docs/users.md).
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "http")
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "google,api_key")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", "client-secret")
    with pytest.raises(ConfigError, match="Users directory"):
        load_settings()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("GOOGLE,Api_Key", frozenset({"google", "api_key"})),
        ("google,,api_key,", frozenset({"google", "api_key"})),
        ("google,google,api_key", frozenset({"google", "api_key"})),
    ],
)
def test_enabled_login_methods_csv_edge_cases(monkeypatch, raw: str, expected):
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", raw)
    settings = Settings()
    assert settings.enabled_login_methods == expected


def test_rbac_enabled_without_changing_login_methods(monkeypatch, tmp_path: Path):
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "test-salt")
    settings = load_settings()
    assert settings.rbac_mode == "enforce"
    assert settings.rbac_enabled is True
    assert settings.rbac_enforcing is True
    assert settings.primary_login_method == "api_key"


def test_rbac_mode_observe_requires_redis_and_policy(monkeypatch, tmp_path: Path):
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "observe")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "test-salt")
    settings = load_settings()
    assert settings.rbac_mode == "observe"
    assert settings.rbac_enabled is True
    assert settings.rbac_enforcing is False


def test_rbac_mode_observe_requires_redis(monkeypatch, tmp_path: Path):
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "observe")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.delenv("KEYSTONE_MCP_REDIS_URL", raising=False)
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_REDIS_URL"):
        load_settings()


def test_invalid_rbac_mode_rejected(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "shadow")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_RBAC_MODE"):
        load_settings()


def test_policy_tools_defaults_to_full():
    assert Settings().policy_tools == "full"


@pytest.mark.parametrize("value", ["full", "read-only", "off"])
def test_policy_tools_accepts_its_three_values(monkeypatch, value: str):
    monkeypatch.setenv("KEYSTONE_MCP_POLICY_TOOLS", value)
    assert load_settings().policy_tools == value


def test_policy_tools_rejects_unknown_value(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_POLICY_TOOLS", "read-write")
    with pytest.raises(
        ConfigError, match=r"KEYSTONE_MCP_POLICY_TOOLS must be one of: full, read-only, off"
    ):
        load_settings()


def test_primary_login_method_must_be_enabled(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", "google")
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "api_key")
    with pytest.raises(ConfigError, match="PRIMARY_LOGIN_METHOD"):
        load_settings()


def test_invalid_login_method_rejected(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", "ldap")
    with pytest.raises(ConfigError, match="PRIMARY_LOGIN_METHOD"):
        load_settings()


def test_google_login_requires_client_credentials(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "google,api_key")
    monkeypatch.setenv("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", "api_key")
    with pytest.raises(ConfigError, match="GOOGLE_CLIENT"):
        load_settings()


def test_rbac_enabled_requires_users_and_policy(monkeypatch):
    # Same as above: this check is specific to the http backend.
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "http")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    with pytest.raises(ConfigError, match="Users directory"):
        load_settings()


def test_rbac_enabled_requires_existing_policy_file(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "test-salt")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", "/no/such/rbac-policy.yaml")
    with pytest.raises(ConfigError, match="does not exist"):
        load_settings()


def test_rbac_enabled_requires_redis_url(monkeypatch, tmp_path: Path):
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.delenv("KEYSTONE_MCP_REDIS_URL", raising=False)
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_REDIS_URL"):
        load_settings()


def test_rbac_disabled_allows_missing_google_and_users_settings(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "off")
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "api_key")
    settings = load_settings()
    assert settings.google_client_id == ""
    assert settings.users_service_url == ""


def test_google_redirect_uri_uses_public_base_url():
    settings = Settings(base_url="https://mcp.example.com")
    assert settings.google_redirect_uri == "https://mcp.example.com/login/google/callback"


def test_users_and_policy_settings_are_readable(monkeypatch, tmp_path: Path):
    policy = tmp_path / "policy.yaml"
    policy.write_text("default_deny: true\n", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    # This test is specifically about reading USERS_SERVICE_* back, which only
    # applies to the http backend (local never requires it).
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "http")
    monkeypatch.setenv(
        "KEYSTONE_MCP_USERS_SERVICE_URL", "http://users-directory.internal.example:8080"
    )
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_TOKEN", "secret-token")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "test-salt")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_ALLOWED_DOMAIN", "example.com")
    settings = load_settings()
    assert settings.users_service_url == "http://users-directory.internal.example:8080"
    assert settings.users_service_token == "secret-token"
    assert settings.rbac_policy_path == str(policy)
    assert settings.google_allowed_domain == "example.com"


def test_catalog_snapshot_path_defaults_to_unset():
    assert Settings().rbac_catalog_snapshot_path == ""


def test_catalog_snapshot_path_read_from_env(monkeypatch, tmp_path: Path):
    snapshot = tmp_path / "catalog-snapshot.yaml"
    snapshot.write_text('active: ["reports_read"]\n', encoding="utf-8")
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text(
        'version: "0.1"\ndefault_deny: true\nroles:\n  administrator:\n    allow: ["*"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "test-salt")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_CATALOG_SNAPSHOT", str(snapshot))
    settings = load_settings()
    assert settings.rbac_catalog_snapshot_path == str(snapshot)


def test_missing_catalog_snapshot_file_is_refused(monkeypatch, tmp_path: Path):
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text(
        'version: "0.1"\ndefault_deny: true\nroles:\n  administrator:\n    allow: ["*"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "test-salt")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_CATALOG_SNAPSHOT", str(tmp_path / "absent.yaml"))
    with pytest.raises(ConfigError, match="CATALOG_SNAPSHOT"):
        load_settings()


def test_catalog_snapshot_not_required_when_rbac_off(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "off")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_CATALOG_SNAPSHOT", "/no/such/snapshot.yaml")
    settings = load_settings()
    assert settings.rbac_enabled is False


# ── Numeric env parsing (fail-fast, never a silent default) ─────────────────
@pytest.mark.parametrize(
    "name",
    [
        "KEYSTONE_MCP_PORT",
        "KEYSTONE_MCP_TOKEN_TTL",
        "KEYSTONE_MCP_THROTTLE_MAX",
        "KEYSTONE_MCP_UPSTREAM_DISCOVERY_RETRIES",
    ],
)
def test_malformed_integer_env_var_is_refused(monkeypatch, name: str):
    monkeypatch.setenv(name, "not-a-number")
    with pytest.raises(ConfigError, match=name):
        Settings()


@pytest.mark.parametrize(
    "name",
    [
        "KEYSTONE_MCP_USERS_SERVICE_TIMEOUT_SECONDS",
        "KEYSTONE_MCP_UPSTREAM_DISCOVERY_TIMEOUT",
        "KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUT_SECONDS",
        "KEYSTONE_MCP_RBAC_AUDIT_LIST_TOOLS_SAMPLE_RATE",
    ],
)
def test_malformed_float_env_var_is_refused(monkeypatch, name: str):
    monkeypatch.setenv(name, "abc")
    with pytest.raises(ConfigError, match=name):
        Settings()


def test_float_typed_timeouts_accept_fractional_values(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_TIMEOUT_SECONDS", "2.5")
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_DISCOVERY_TIMEOUT", "7.5")
    settings = Settings()
    assert settings.users_service_timeout_seconds == 2.5
    assert settings.upstream_discovery_timeout_seconds == 7.5


def test_audit_sample_rate_parsed_as_float(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_LIST_TOOLS_SAMPLE_RATE", "0.25")
    assert Settings().rbac_audit_list_tools_sample_rate == 0.25


# ── Per-tool upstream timeout overrides ─────────────────────────────────────
def test_upstream_tool_timeouts_default_to_empty(monkeypatch):
    monkeypatch.delenv("KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS", raising=False)
    assert Settings().upstream_tool_timeouts == {}


def test_upstream_tool_timeouts_parsed_from_json(monkeypatch):
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS",
        '{"reports_build": 30, "catalog_export": 12.5}',
    )
    timeouts = Settings().upstream_tool_timeouts
    assert timeouts == {"reports_build": 30.0, "catalog_export": 12.5}
    assert all(isinstance(value, float) for value in timeouts.values())


def test_upstream_tool_timeouts_rejects_malformed_json(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS", "{not json")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS"):
        Settings()


def test_upstream_tool_timeouts_rejects_non_object(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS", '["reports_build"]')
    with pytest.raises(ConfigError, match="must be a JSON object"):
        Settings()


@pytest.mark.parametrize("value", ['"30"', "null", "true", "-5", "0"])
def test_upstream_tool_timeouts_rejects_non_positive_numbers(monkeypatch, value: str):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS", '{"reports_build": %s}' % value)
    with pytest.raises(ConfigError, match="reports_build"):
        Settings()


# ── Login page default language ─────────────────────────────────────────────
def test_login_default_lang_defaults_to_english(monkeypatch):
    monkeypatch.delenv("KEYSTONE_MCP_LOGIN_DEFAULT_LANG", raising=False)
    assert Settings().login_default_lang == "en"


@pytest.mark.parametrize("lang", ["he", "en", "ru", "ar"])
def test_login_default_lang_accepts_every_shipped_translation(monkeypatch, lang: str):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_DEFAULT_LANG", lang.upper())
    assert Settings().login_default_lang == lang


def test_login_default_lang_rejects_untranslated_language(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_DEFAULT_LANG", "fr")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_LOGIN_DEFAULT_LANG"):
        Settings()


def test_login_langs_match_the_shipped_translation_table():
    """LOGIN_LANGS is validated against, so it must not drift from TRANSLATIONS."""
    from keystone_mcp.auth.keystone_oauth_provider import TRANSLATIONS
    from keystone_mcp.config import LOGIN_LANGS

    assert set(TRANSLATIONS) == set(LOGIN_LANGS)


# ── Audit subject salt is required, not merely advised ──────────────────────
def _rbac_env(monkeypatch, tmp_path: Path) -> None:
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis://localhost:6379/0")


@pytest.mark.parametrize("salt", ["", "   "])
def test_rbac_audit_without_a_salt_is_refused(monkeypatch, tmp_path: Path, salt: str):
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_ENABLED", "true")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", salt)
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT"):
        load_settings()


def test_unset_salt_is_refused_too(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.delenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", raising=False)
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT"):
        load_settings()


def test_salt_not_required_when_audit_is_off(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_ENABLED", "false")
    monkeypatch.delenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", raising=False)
    settings = load_settings()
    assert settings.rbac_audit_enabled is False


def test_salt_not_required_when_rbac_is_off(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "off")
    monkeypatch.delenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", raising=False)
    settings = load_settings()
    assert settings.rbac_enabled is False


def test_salt_satisfies_validation(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "a-random-secret")
    settings = load_settings()
    assert settings.rbac_audit_subject_salt == "a-random-secret"


def test_dev_tokens_are_refused_in_production(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "test-salt")
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "local-dev-token")
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_URL", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_TOKEN", raising=False)
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_DEV_TOKENS is local-only"):
        load_settings()


def test_dev_tokens_with_enforce_allowed_when_auth_service_configured(
    monkeypatch,
    tmp_path: Path,
):
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "local-dev-token")
    monkeypatch.setenv("KEYSTONE_MCP_AUTH_SERVICE_URL", "http://auth:9000/introspect")
    monkeypatch.setenv("KEYSTONE_MCP_AUTH_SERVICE_TOKEN", "auth-token")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "test-salt")
    load_settings()


def test_dev_tokens_with_enforce_allowed_in_local(monkeypatch, tmp_path: Path):
    """L2: `local` allows DEV tokens under any RBAC_MODE, including enforce."""
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "test-salt")
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "local-dev-token")
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_URL", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_TOKEN", raising=False)
    settings = load_settings()
    assert settings.dev_tokens == "local-dev-token"


def test_negative_client_id_limit_refused(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_METRICS_OAUTH_CLIENT_ID_LIMIT", "-1")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_METRICS_OAUTH_CLIENT_ID_LIMIT"):
        load_settings()


def test_client_id_limit_defaults_to_fifty():
    settings = Settings()
    assert settings.metrics_oauth_client_id_limit == 50
