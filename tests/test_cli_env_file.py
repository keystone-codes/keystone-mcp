"""keystone-mcp CLI: .env is loaded before Settings is built, for every subcommand."""

from __future__ import annotations

from keystone_mcp import cli
from keystone_mcp.config import Settings


def _write_env(tmp_path, *lines: str) -> None:
    (tmp_path / ".env").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _live_file_argv(tmp_path) -> list[str]:
    """A cheap, always-valid subcommand invocation (empty live-name file)."""
    live_file = tmp_path / "live.txt"
    live_file.write_text("", encoding="utf-8")
    return ["catalog", "export", "--live-file", str(live_file)]


def test_cli_loads_env_file_before_settings(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KEYSTONE_MCP_ENV_FILE", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_LOG_LEVEL", raising=False)
    _write_env(tmp_path, "KEYSTONE_MCP_LOG_LEVEL=DEBUG")

    seen_settings: list[Settings] = []

    def _fake_configure_logging(settings: Settings) -> None:
        seen_settings.append(settings)

    monkeypatch.setattr(cli, "configure_logging", _fake_configure_logging)

    exit_code = cli.main(_live_file_argv(tmp_path))

    assert exit_code == 0
    assert len(seen_settings) == 1
    assert seen_settings[0].log_level == "DEBUG"


def test_cli_respects_disabled_env_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_ENV_FILE", "")
    monkeypatch.delenv("KEYSTONE_MCP_LOG_LEVEL", raising=False)
    _write_env(tmp_path, "KEYSTONE_MCP_LOG_LEVEL=DEBUG")

    seen_settings: list[Settings] = []

    def _fake_configure_logging(settings: Settings) -> None:
        seen_settings.append(settings)

    monkeypatch.setattr(cli, "configure_logging", _fake_configure_logging)

    exit_code = cli.main(_live_file_argv(tmp_path))

    assert exit_code == 0
    assert len(seen_settings) == 1
    assert seen_settings[0].log_level == "INFO"
