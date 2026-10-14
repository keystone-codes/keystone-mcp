"""keystone_mcp.server.main(): .env is loaded before Settings is built.

Only the one scenario A06 needs: `.env` in the working directory changes a
setting that reaches `mcp.run`. Everything past settings construction
(discovery, policy bootstrap, the actual HTTP server) is stubbed out, since
this card only cares about the very first step of `main()`.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from keystone_mcp import server


def test_main_loads_env_file_before_settings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KEYSTONE_MCP_ENV_FILE", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_PORT", raising=False)
    (tmp_path / ".env").write_text("KEYSTONE_MCP_PORT=9123\n", encoding="utf-8")

    fake_mcp = MagicMock()

    def _fake_build_server(*, settings):
        return (fake_mcp, None, None, None, None, None, None)

    async def _fake_bootstrap_users_store(*args, **kwargs):
        return None

    monkeypatch.setattr(server, "build_server", _fake_build_server)
    monkeypatch.setattr(server, "bootstrap_users_store", _fake_bootstrap_users_store)
    monkeypatch.setattr(server, "install_policy_reload_signal", lambda *a, **k: None)
    server._startup_failure_holder["error"] = None
    server._deferred_bootstrap_holder["factory"] = None

    server.main()

    assert fake_mcp.run.call_count == 1
    _, kwargs = fake_mcp.run.call_args
    assert kwargs["port"] == 9123


def test_main_logs_deployment_profile_and_startup_warnings(monkeypatch, capsys, tmp_path):
    """A04: `main()` reports the resolved profile and any startup warnings.

    ``configure_logging`` (called by ``main()`` just before these lines are
    logged) replaces the root logger's handlers with a plain
    ``StreamHandler(sys.stderr)`` — see ``test_logging_config.py`` — which
    also discards pytest's own caplog handler. So, like
    ``test_configure_logging_json_emits_ndjson``, this reads the JSON lines
    actually written to stderr instead of ``caplog.records``.
    """
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "http://localhost:8080")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "enforce")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_ENABLED", "false")
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS", "local-dev-token")

    fake_mcp = MagicMock()

    def _fake_build_server(*, settings):
        return (fake_mcp, None, None, None, None, None, None)

    async def _fake_bootstrap_users_store(*args, **kwargs):
        return None

    monkeypatch.setattr(server, "build_server", _fake_build_server)
    monkeypatch.setattr(server, "bootstrap_users_store", _fake_bootstrap_users_store)
    monkeypatch.setattr(server, "install_policy_reload_signal", lambda *a, **k: None)
    server._startup_failure_holder["error"] = None
    server._deferred_bootstrap_holder["factory"] = None

    server.main()

    stderr_lines = capsys.readouterr().err.strip().splitlines()
    messages = [json.loads(line)["msg"] for line in stderr_lines if line]
    assert any("deployment profile: local" in message for message in messages)
    assert any("KEYSTONE_MCP_DEV_TOKENS is set" in message for message in messages)
