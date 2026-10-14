"""`KEYSTONE_MCP_DEPLOYMENT_PROFILE` (`local` | `production`, A04).

`local` is a developer's own machine: a loopback-only ``KEYSTONE_MCP_BASE_URL``
and DEV tokens allowed under any RBAC mode. `production` (the default) is a
public host: RBAC must be ``enforce``, DEV tokens are refused outright,
API-key sign-in needs an external key-verification service, and a plain
``http`` base URL on a publicly reachable host is refused. See
``docs/environment.md#deployment-profile`` for the full rule table.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from keystone_mcp.config import (
    ConfigError,
    Settings,
    _is_public_host,
    load_settings,
    startup_warnings,
)
from support.test_env import UNUSED_REDIS_URL


def _rbac_env(monkeypatch, tmp_path: Path) -> None:
    """Minimal settings for `KEYSTONE_MCP_RBAC_MODE=enforce` to validate."""
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    # The built-in (local, default) users directory needs neither URL nor
    # token; these tests exercise the deployment profile, not the users
    # directory backend, so they leave KEYSTONE_MCP_USERS_BACKEND unset.
    monkeypatch.delenv("KEYSTONE_MCP_USERS_SERVICE_URL", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_USERS_SERVICE_TOKEN", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", UNUSED_REDIS_URL)
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "test-salt")
    # P5 (production refuses a SQLite users directory) only matters to the
    # tests in that section below; every other test that reaches this helper
    # and ends up accepted under `production` needs a Postgres-shaped URL so
    # it is not the users directory that trips it up. Schema only is checked
    # here, never connectivity, so this URL is never actually dialed.
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", "postgresql+psycopg://u:p@db:5432/keystone")


def _production_login_env(monkeypatch) -> None:
    """Satisfy production api_key sign-in with a local Postgres-backed directory."""
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_URL", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "local")
    monkeypatch.setenv(
        "KEYSTONE_MCP_USERS_DB_URL",
        "postgresql+psycopg://user:pass@localhost:5432/keystone_users",
    )


# ── Default and parsing ──────────────────────────────────────────────────────


def test_profile_defaults_to_production(monkeypatch):
    monkeypatch.delenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", raising=False)
    assert Settings().deployment_profile == "production"


def test_unknown_profile_is_refused(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "staging")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_DEPLOYMENT_PROFILE"):
        Settings()


# ── L1: local requires a loopback base URL ───────────────────────────────────


def test_local_refuses_non_loopback_base_url(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "https://mcp.example.com")
    with pytest.raises(ConfigError, match="serves only a loopback"):
        load_settings()


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "http://demo.localhost:8080",
    ],
)
def test_local_accepts_localhost_127_and_ipv6_loopback(monkeypatch, base_url: str):
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", base_url)
    settings = load_settings()
    assert settings.base_url == base_url


# ── L2: local allows DEV tokens with enforce (warning, not a refusal) ───────


def test_local_allows_dev_tokens_with_enforce(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "local-dev-token")
    settings = load_settings()
    warnings = startup_warnings(settings)
    assert any("KEYSTONE_MCP_DEV_TOKENS is set" in w for w in warnings)


# ── Production refusals (P1-P4) ──────────────────────────────────────────────


def test_production_refuses_dev_tokens(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "a-dev-token")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_DEV_TOKENS is local-only"):
        load_settings()


def test_production_refuses_rbac_off(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "off")
    _production_login_env(monkeypatch)
    with pytest.raises(ConfigError, match="requires KEYSTONE_MCP_RBAC_MODE=enforce"):
        load_settings()


def test_production_refuses_rbac_observe(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "observe")
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    with pytest.raises(ConfigError, match="requires KEYSTONE_MCP_RBAC_MODE=enforce"):
        load_settings()


def test_production_refuses_api_key_with_http_users_directory(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "http")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_URL", "http://users:8080")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_TOKEN", "token")
    with pytest.raises(ConfigError, match="API-key sign-in in production needs"):
        load_settings()


def test_production_accepts_google_only(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "google")
    monkeypatch.setenv("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", "google")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", "client-secret")
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_URL", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_TOKEN", raising=False)
    settings = load_settings()
    assert settings.google_login_enabled is True
    assert settings.api_key_login_enabled is False


def test_production_accepts_api_key_with_local_directory(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    settings = load_settings()
    assert settings.api_key_login_enabled is True


def test_production_refuses_public_http_base_url(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "http://mcp.example.com")
    with pytest.raises(ConfigError, match="public http address"):
        load_settings()


def test_production_accepts_https_base_url(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "https://mcp.example.com")
    settings = load_settings()
    assert settings.base_url == "https://mcp.example.com"


# ── P5: production refuses a SQLite users directory ──────────────────────────


@pytest.mark.parametrize(
    "users_db_url",
    [
        "sqlite:///./keystone-users.db",
        "sqlite:////data/u.db",
        "sqlite+pysqlite:///x.db",
        "",
    ],
)
def test_production_refuses_sqlite_users_db(monkeypatch, tmp_path: Path, users_db_url: str):
    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.delenv("KEYSTONE_MCP_USERS_BACKEND", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", users_db_url)
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_USERS_DB_URL"):
        load_settings()


def test_production_accepts_postgres_users_db(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.delenv("KEYSTONE_MCP_USERS_BACKEND", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", "postgresql+psycopg://u:p@db:5432/keystone")
    settings = load_settings()
    assert settings.users_db_url == "postgresql+psycopg://u:p@db:5432/keystone"


def test_local_accepts_sqlite_users_db(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.delenv("KEYSTONE_MCP_USERS_BACKEND", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{tmp_path}/keystone-users.db")
    settings = load_settings()
    assert startup_warnings(settings) == []


def test_production_http_backend_ignores_users_db_url(monkeypatch, tmp_path: Path):
    """`users_backend=http` manages its own storage; the SQLite rule does not apply."""
    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "http")
    monkeypatch.setenv(
        "KEYSTONE_MCP_USERS_SERVICE_URL", "http://users-directory.internal.example:8000"
    )
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_TOKEN", "users-token")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", "sqlite:///./keystone-users.db")
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "google")
    monkeypatch.setenv("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", "google")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", "client-secret")
    settings = load_settings()
    assert settings.users_backend == "http"


# ── Startup warnings ──────────────────────────────────────────────────────────


def test_startup_warnings_for_private_http_base_url(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "http://keystone:8080")
    settings = load_settings()
    warnings = startup_warnings(settings)
    assert any("uses http on a non-public host" in w for w in warnings)


def test_startup_warnings_for_insecure_upstream_flags(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP", "true")
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE", "true")
    settings = load_settings()
    warnings = startup_warnings(settings)
    assert any("UPSTREAM_ALLOW_INSECURE_HTTP" in w for w in warnings)
    assert any("UPSTREAM_EGRESS_ALLOW_PRIVATE" in w for w in warnings)


def test_startup_warns_for_upstream_without_identity_secret(monkeypatch, tmp_path: Path):
    """Y01 (W6): an upstream with no auth.identity_secret_env only ever proves

    who is calling via the unsigned X-Author-Email header."""
    import json

    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(
            [{"name": "docs-mcp", "url": "https://docs-mcp.example/mcp", "namespace": "docs"}]
        ),
    )
    settings = load_settings()
    warnings = startup_warnings(settings)
    assert any(
        "namespace=docs" in w and "identity_secret_env" in w and "X-Author-Email" in w
        for w in warnings
    )


def test_production_warns_for_stdio_upstream(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(
            [
                {
                    "name": "notes",
                    "namespace": "notes",
                    "transport": "stdio",
                    "command": sys.executable,
                }
            ]
        ),
    )
    settings = load_settings()
    warnings = startup_warnings(settings)
    assert any("no sandbox" in w and "namespace=notes" in w for w in warnings)


def test_local_does_not_warn_for_stdio_upstream(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(
            [
                {
                    "name": "notes",
                    "namespace": "notes",
                    "transport": "stdio",
                    "command": sys.executable,
                }
            ]
        ),
    )
    settings = load_settings()
    assert not any("no sandbox" in w for w in startup_warnings(settings))


def test_startup_warns_for_stdio_upstream_without_identity_secret(monkeypatch, tmp_path: Path):
    """D8: a stdio upstream never receives X-Author-Email at all (there are no

    HTTP headers to a child process), so its missing-secret warning must not
    claim it does.
    """
    import json
    import sys

    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(
            [
                {
                    "name": "notes",
                    "namespace": "notes",
                    "transport": "stdio",
                    "command": sys.executable,
                }
            ]
        ),
    )
    settings = load_settings()
    warnings = startup_warnings(settings)
    matching = [w for w in warnings if "namespace=notes" in w and "identity_secret_env" in w]
    assert matching, warnings
    assert "X-Author-Email" not in matching[0]


def test_startup_warning_absent_with_identity_secret_configured(monkeypatch, tmp_path: Path):
    import json

    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET", "x" * 40)
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(
            [
                {
                    "name": "docs-mcp",
                    "url": "https://docs-mcp.example/mcp",
                    "namespace": "docs",
                    "auth": {"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET"},
                }
            ]
        ),
    )
    settings = load_settings()
    warnings = startup_warnings(settings)
    assert not any("identity_secret_env" in w for w in warnings)


@pytest.mark.parametrize("dev_tokens", ["", "a-dev-token"])
def test_local_warnings_empty_with_rbac_off(monkeypatch, dev_tokens: str):
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "off")
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", dev_tokens)
    settings = load_settings()
    assert startup_warnings(settings) == []


def test_local_warnings_empty_with_rbac_observe_and_no_dev_tokens(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "observe")
    monkeypatch.delenv("KEYSTONE_MCP_DEV_TOKENS", raising=False)
    settings = load_settings()
    assert startup_warnings(settings) == []


def test_local_warnings_exactly_w4_with_dev_tokens_and_enforce(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "a-dev-token")
    settings = load_settings()
    warnings = startup_warnings(settings)
    assert len(warnings) == 1
    assert "KEYSTONE_MCP_DEV_TOKENS is set" in warnings[0]


# ── _is_public_host ───────────────────────────────────────────────────────────


# ── The planned stage configuration (coordinator decision) ──────────────────


def test_stage_like_production_configuration_is_accepted(monkeypatch, tmp_path: Path):
    """The planned stage deployment must pass `validate_settings` unchanged.

    `production`, `KEYSTONE_MCP_USERS_BACKEND=http` (HTTP users directory),
    Google sign-in for people, `RBAC_MODE=enforce`, no DEV tokens.
    """
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "https://mcp-stage.keystone.codes")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "http")
    monkeypatch.setenv(
        "KEYSTONE_MCP_USERS_SERVICE_URL", "http://users-directory.internal.example:8000"
    )
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_TOKEN", "users-token")
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "google")
    monkeypatch.setenv("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", "google")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", "client-secret")
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_URL", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_AUTH_SERVICE_TOKEN", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", UNUSED_REDIS_URL)
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "test-salt")
    monkeypatch.delenv("KEYSTONE_MCP_DEV_TOKENS", raising=False)

    settings = load_settings()

    assert settings.deployment_profile == "production"
    assert settings.rbac_enforcing is True
    assert settings.api_key_login_enabled is False
    assert settings.google_login_enabled is True
    # The two insecure-upstream warnings are expected here: the autouse fixture
    # `_allow_insecure_upstream_http_for_tests` sets both flags for every test
    # in this suite (unrelated to the deployment profile under test). What
    # matters is that https + enforce + Google-only sign-in produce no
    # *other* warning (e.g. no plain-http-base-url or DEV-token warning).
    warnings = startup_warnings(settings)
    assert all(
        "UPSTREAM_ALLOW_INSECURE_HTTP" in w
        or "UPSTREAM_EGRESS_ALLOW_PRIVATE" in w
        or "KEYSTONE_MCP_USERS_SERVICE_URL uses http" in w
        or "deprecated since 0.5.0" in w
        or "KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS is empty" in w
        for w in warnings
    )


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("8.8.8.8", True),
        ("10.0.0.1", False),
        ("localhost", False),
        ("keystone", False),
        ("mcp.example.com", True),
        ("::1", False),
        # finding #10 (second review): a legacy integer/hex IPv4 literal
        # (what a browser or curl would actually connect to) must classify
        # the same as its dotted-quad spelling, not fall through to the
        # bare-name "no dot -> private" rule.
        ("134744072", True),  # decimal for 8.8.8.8
        ("0x08080808", True),  # hex for 8.8.8.8
        ("0x0a000001", False),  # hex for 10.0.0.1 (private)
        ("2130706433", False),  # decimal for 127.0.0.1 (loopback, not public)
        ("not-a-number", False),  # still a bare name, not a legacy IP literal
    ],
)
def test_is_public_host(host: str, expected: bool):
    assert _is_public_host(host) is expected


def test_legacy_integer_ip_literal_refused_as_public_http_in_production(
    monkeypatch, tmp_path: Path
):
    """finding #10: `http://134744072` (decimal for 8.8.8.8) must trip P4."""
    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "http://134744072")
    with pytest.raises(ConfigError, match="public http address"):
        load_settings()


# ── P4's message for an internal-only DNS name ──────────────────────────────


def test_production_refuses_internal_dns_name_over_http_with_guidance(monkeypatch, tmp_path: Path):
    """finding #10: an internal-looking name (e.g. `*.svc.cluster.local`) is

    still classified public by `_is_public_host` (a DNS suffix is not a
    trust boundary) and P4 still refuses it — deliberately, not loosened —
    but the error now explains the remedy instead of just naming the rule.
    """
    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "http://keystone-mcp.svc.cluster.local")
    with pytest.raises(ConfigError) as exc_info:
        load_settings()
    message = str(exc_info.value)
    assert "public http address" in message
    assert "TLS" in message


# ── W5: `local` + listening on all interfaces + DEV tokens ──────────────────


def test_local_warns_when_listening_on_all_interfaces_with_dev_tokens(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_HOST", "0.0.0.0")
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "a-dev-token")
    settings = load_settings()
    warnings = startup_warnings(settings)
    assert any("listening on all interfaces" in w for w in warnings)


def test_local_warns_for_ipv6_unspecified_host_with_dev_tokens(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_HOST", "::")
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "a-dev-token")
    settings = load_settings()
    warnings = startup_warnings(settings)
    assert any("listening on all interfaces" in w for w in warnings)


def test_local_no_warning_for_all_interfaces_without_dev_tokens(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_HOST", "0.0.0.0")
    monkeypatch.delenv("KEYSTONE_MCP_DEV_TOKENS", raising=False)
    settings = load_settings()
    assert startup_warnings(settings) == []


def test_local_no_all_interfaces_warning_for_loopback_host_with_dev_tokens(
    monkeypatch, tmp_path: Path
):
    """The existing W4 still fires; W5 must not duplicate it for 127.0.0.1."""
    _rbac_env(monkeypatch, tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_HOST", "127.0.0.1")
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "a-dev-token")
    settings = load_settings()
    warnings = startup_warnings(settings)
    assert not any("listening on all interfaces" in w for w in warnings)
    assert any("KEYSTONE_MCP_DEV_TOKENS is set" in w for w in warnings)


# ── W7: policy file not writable while KEYSTONE_MCP_POLICY_TOOLS=full ───────


def test_w7_warns_when_policy_file_is_not_writable(monkeypatch, tmp_path: Path):
    import os

    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    policy_path = Path(os.environ["KEYSTONE_MCP_RBAC_POLICY_PATH"])
    os.chmod(policy_path, 0o444)
    try:
        if os.geteuid() == 0:
            pytest.skip("root can write a 0o444 file")
        settings = load_settings()
        warnings = startup_warnings(settings)
        assert any(
            "is not writable" in w and "policy_readonly" in w and str(policy_path) in w
            for w in warnings
        )
    finally:
        os.chmod(policy_path, 0o644)


def test_w7_absent_when_policy_tools_is_not_full(monkeypatch, tmp_path: Path):
    import os

    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_POLICY_TOOLS", "read-only")
    policy_path = Path(os.environ["KEYSTONE_MCP_RBAC_POLICY_PATH"])
    os.chmod(policy_path, 0o444)
    try:
        if os.geteuid() == 0:
            pytest.skip("root can write a 0o444 file")
        settings = load_settings()
        warnings = startup_warnings(settings)
        assert not any("is not writable" in w for w in warnings)
    finally:
        os.chmod(policy_path, 0o644)


def test_w7_absent_when_policy_file_is_writable(monkeypatch, tmp_path: Path):
    _rbac_env(monkeypatch, tmp_path)
    _production_login_env(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    settings = load_settings()
    warnings = startup_warnings(settings)
    assert not any("is not writable" in w for w in warnings)
