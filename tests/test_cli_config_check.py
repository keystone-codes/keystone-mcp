"""``keystone-mcp config check`` CLI."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from keystone_mcp import cli
from keystone_mcp.config import ConfigError, check_configuration, load_settings
from keystone_mcp.users import service
from keystone_mcp.users.db import create_users_engine, make_session_factory, session_scope
from keystone_mcp.users.migrate import upgrade_to_head
from keystone_mcp.users.models import UserRow
from support.d02_profile_cases import PROFILE_CASES
from support.test_env import UNUSED_REDIS_URL, require_redis_url

_POLICY_YAML = """\
version: "1.0.0"
default_deny: true
roles:
  administrator:
    description: "Full access."
    allow:
      - "*"
"""


@pytest.fixture(autouse=True)
def _quiet_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "configure_logging", lambda settings: None)


def _apply_clean_local(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_ENV_FILE", "")
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "http://localhost:8080")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "off")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "a" * 32)
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())


def test_clean_environment_exits_zero(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    _apply_clean_local(monkeypatch)
    code = cli.main(["config", "check"])
    captured = capsys.readouterr()
    assert code == 0
    lines = [line for line in captured.out.splitlines() if line.strip()]
    assert lines[-1] == "config check: 0 errors, 0 warnings"


def test_warnings_only_exit_zero_and_strict_exits_one(
    monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    _apply_clean_local(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_TOKEN_TTL", "172800")
    code = cli.main(["config", "check"])
    out = capsys.readouterr().out
    assert code == 0
    assert any(
        line.startswith("WARNING") and "KEYSTONE_MCP_TOKEN_TTL" in line for line in out.splitlines()
    )

    capsys.readouterr()
    code_strict = cli.main(["config", "check", "--strict"])
    assert code_strict == 1


def test_all_errors_are_listed_at_once(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    _apply_clean_local(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_PORT", "0")
    monkeypatch.setenv("KEYSTONE_MCP_OAUTH_DCR_ENABLED", "enabled")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "mcp.example.com")
    code = cli.main(["config", "check"])
    out = capsys.readouterr().out
    assert code == 1
    error_lines = [line for line in out.splitlines() if line.startswith("ERROR")]
    assert len(error_lines) == 3
    joined = "\n".join(error_lines)
    assert "KEYSTONE_MCP_PORT" in joined
    assert "KEYSTONE_MCP_OAUTH_DCR_ENABLED" in joined
    assert "KEYSTONE_MCP_BASE_URL" in joined


def test_removed_fatal_variable_is_an_error(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    _apply_clean_local(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_ENABLED", "true")
    code = cli.main(["config", "check"])
    out = capsys.readouterr().out
    assert code == 1
    assert any(
        line.startswith("ERROR") and "KEYSTONE_MCP_RBAC_ENABLED" in line
        for line in out.splitlines()
    )


def test_bad_upstream_registry_is_an_error(
    monkeypatch: pytest.MonkeyPatch, capsys, tmp_path: Path
) -> None:
    _apply_clean_local(monkeypatch)
    bad = tmp_path / "upstreams.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS_PATH", str(bad))
    code = cli.main(["config", "check"])
    out = capsys.readouterr().out
    assert code == 1
    assert any(
        line.startswith("ERROR") and "upstream registry" in line for line in out.splitlines()
    )


def test_bad_policy_file_is_an_error(
    monkeypatch: pytest.MonkeyPatch, capsys, tmp_path: Path
) -> None:
    _apply_clean_local(monkeypatch)
    policy = tmp_path / "policy.yaml"
    policy.write_text("not: valid: yaml: [", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    code = cli.main(["config", "check"])
    out = capsys.readouterr().out
    assert code == 1
    assert any(
        line.startswith("ERROR") and line.startswith("ERROR   policy:") for line in out.splitlines()
    )


def test_env_file_option_is_used(monkeypatch: pytest.MonkeyPatch, capsys, tmp_path: Path) -> None:
    _apply_clean_local(monkeypatch)
    env_file = tmp_path / "check.env"
    env_file.write_text("KEYSTONE_MCP_PORT=0\n", encoding="utf-8")
    code = cli.main(["config", "check", "--env-file", str(env_file)])
    out = capsys.readouterr().out
    assert code == 1
    assert any(line == f"env file: {env_file}" for line in out.splitlines())
    assert any(
        line.startswith("ERROR") and "KEYSTONE_MCP_PORT" in line for line in out.splitlines()
    )


def test_missing_env_file_exits_two(
    monkeypatch: pytest.MonkeyPatch, capsys, tmp_path: Path
) -> None:
    _apply_clean_local(monkeypatch)
    missing = tmp_path / "missing.env"
    code = cli.main(["config", "check", "--env-file", str(missing)])
    err = capsys.readouterr().err
    assert code == 2
    assert err.count("\n") <= 1 or len(err.strip().splitlines()) == 1
    assert "Traceback" not in err


def test_output_has_no_secrets(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    _apply_clean_local(monkeypatch)
    salt = "super-secret-audit-salt-value"
    redis_password = "redis-password-leak"
    dev_token = "dev-token-leak-value"
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", salt)
    monkeypatch.setenv(
        "KEYSTONE_MCP_REDIS_URL",
        f"redis://:{redis_password}@redis.example.com:6379/4",
    )
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", dev_token)
    cli.main(["config", "check"])
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert salt not in combined
    assert redis_password not in combined
    assert dev_token not in combined


def test_does_not_connect_to_redis(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    _apply_clean_local(monkeypatch)
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", UNUSED_REDIS_URL)
    start = time.monotonic()
    code = cli.main(["config", "check"])
    elapsed = time.monotonic() - start
    out = capsys.readouterr().out
    assert elapsed < 2.0
    assert "connection" not in out.lower()
    assert code in (0, 1)


def test_admins_flag_reports_missing_full_administrator(
    monkeypatch: pytest.MonkeyPatch, capsys, tmp_path: Path
) -> None:
    _apply_clean_local(monkeypatch)
    db_path = tmp_path / "users.db"
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_POLICY_YAML, encoding="utf-8")
    engine = create_users_engine(f"sqlite:///{db_path}")
    upgrade_to_head(engine)
    factory = make_session_factory(engine)
    with session_scope(factory) as session:
        service.create_user(
            session,
            email="admin@example.com",
            full_name="Admin",
            roles=["administrator"],
            note=None,
            created_by="setup",
            allowed_roles=None,
        )
        admin = session.get(UserRow, "admin@example.com")
        assert admin is not None
        admin.is_blocked = True
        session.flush()
    engine.dispose()

    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "local")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy_path))

    code = cli.main(["config", "check", "--admins"])
    out = capsys.readouterr().out
    assert code == 1
    assert any(
        line.startswith("ERROR") and "full administrator" in line.lower()
        for line in out.splitlines()
    )


def test_admins_flag_does_not_create_database(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    _apply_clean_local(monkeypatch)
    db_path = tmp_path / "missing-users.db"
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_POLICY_YAML, encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "local")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy_path))

    code = cli.main(["config", "check", "--admins"])
    assert code == 1
    assert not db_path.exists()


@pytest.mark.parametrize(
    "case", [c for c in PROFILE_CASES if c.expect == "config_error"], ids=lambda c: c.id
)
def test_check_configuration_matches_server_startup(
    case, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "a" * 32)
    for name in (
        "KEYSTONE_MCP_GOOGLE_CLIENT_ID",
        "KEYSTONE_MCP_GOOGLE_CLIENT_SECRET",
        "KEYSTONE_MCP_ENABLED_LOGIN_METHODS",
        "KEYSTONE_MCP_PRIMARY_LOGIN_METHOD",
        "FORWARDED_ALLOW_IPS",
    ):
        monkeypatch.delenv(name, raising=False)
    if case.profile == "local":
        monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
        monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "http://localhost:8080")
        monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "off")
    else:
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
        monkeypatch.delenv("KEYSTONE_MCP_DEV_TOKENS", raising=False)

    for name in case.unset:
        monkeypatch.delenv(name, raising=False)
    for name, value in case.env.items():
        monkeypatch.setenv(name, value)

    env_map = os.environ.copy()
    report = check_configuration(env_map)
    load_raises = False
    try:
        load_settings()
    except ConfigError:
        load_raises = True
    assert bool(report.errors) == load_raises
