"""Production profile rules for API keys (card step 8)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastmcp import Client

from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import ConfigError, Settings, load_settings
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.users import service
from keystone_mcp.users.db import session_scope
from support.service_bearer import service_bearer_harness
from support.test_env import require_redis_url
from support.users_store import make_users_store


def _production_enforce_settings(tmp_path: Path) -> Settings:
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text(
        "default_deny: true\nroles: {administrator: {allow: ['*']}}\n", encoding="utf-8"
    )
    return Settings(
        base_url="https://mcp.example.com",
        deployment_profile="production",
        rbac_mode="enforce",
        rbac_policy_path=str(policy),
        rbac_audit_subject_salt="prod-test",
        redis_url=require_redis_url(),
        users_backend="local",
        users_db_url="postgresql+psycopg://u:p@db:5432/keystone",
        enabled_login_methods=frozenset({"api_key"}),
        primary_login_method="api_key",
    )


def test_issue_tool_absent_in_production(tmp_path: Path) -> None:
    settings = _production_enforce_settings(tmp_path)

    async def _run() -> None:
        store, _ = await make_users_store(tmp_path)
        directory = LocalUserDirectory(store)
        reg = RouterRegistry(RouterEngine(settings))
        register_catalog(reg, settings, directory=directory)
        assert reg.get("api_keys_issue") is None
        assert reg.get("api_keys_list") is not None
        assert reg.get("api_keys_revoke") is not None
        store.dispose()

    import asyncio

    asyncio.run(_run())


def test_cli_issue_works_in_production(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_path = tmp_path / "users.db"
    monkeypatch.setenv("KEYSTONE_MCP_ENV_FILE", "")
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "https://mcp.example.com")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "local")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv(
        "KEYSTONE_MCP_RBAC_POLICY_PATH",
        str(tmp_path / "policy.yaml"),
    )
    (tmp_path / "policy.yaml").write_text(
        "default_deny: true\nroles: {administrator: {allow: ['*']}}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "cli-salt")
    monkeypatch.delenv("KEYSTONE_MCP_REDIS_URL", raising=False)

    from keystone_mcp.users.db import create_users_engine
    from keystone_mcp.users.db import make_session_factory as mk_sf
    from keystone_mcp.users.migrate import upgrade_to_head

    eng = create_users_engine(f"sqlite:///{db_path}")
    upgrade_to_head(eng)
    sf = mk_sf(eng)
    with session_scope(sf) as session:
        service.create_service_account(
            session,
            name="bot",
            description=None,
            roles=["member"],
            created_by="setup",
        )
    eng.dispose()

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "keystone_mcp.cli",
            "keys",
            "issue",
            "--subject",
            "svc:bot",
            "--days",
            "30",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["key"].startswith("ksk_")
    assert "key" in payload


def test_production_refuses_api_key_login_with_interactive_provider(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
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
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setenv("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "google,api_key")
    monkeypatch.setenv("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", "google")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "salt")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())
    with pytest.raises(ConfigError, match="interactive provider"):
        load_settings()


def test_production_allows_api_key_login_without_interactive_provider(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
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
    monkeypatch.setenv("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "api_key")
    monkeypatch.setenv("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", "api_key")
    monkeypatch.delenv("KEYSTONE_MCP_GOOGLE_CLIENT_ID", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "salt")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())
    settings = load_settings()
    assert settings.api_key_login_enabled is True


async def test_service_account_bearer_works_in_production(tmp_path: Path) -> None:
    async with service_bearer_harness(tmp_path, deployment_profile="production") as harness:
        async with Client(harness.bearer_transport(harness.service_key)) as client:
            result = await client.call_tool_mcp("hello_greet", {"name": "CI"})
        assert result.is_error is False
        assert harness.observed["headers"].get("x-keystone-subject") == "svc:ci"
