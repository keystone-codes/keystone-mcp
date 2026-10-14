"""Tests for keystone_mcp.env_file.load_env_file.

Every test runs inside ``tmp_path`` (via ``monkeypatch.chdir``) and passes its
own ``environ`` dict instead of touching ``os.environ``, so the suite never
depends on — or pollutes — the real process environment or a developer's own
``.env`` in the repository root.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from keystone_mcp.config import ConfigError
from keystone_mcp.env_file import load_env_file
from keystone_mcp.identity_assertion import normalize_pem_env_value


def test_default_reads_dotenv_in_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("KEYSTONE_MCP_PORT=9123\n", encoding="utf-8")

    environ: dict[str, str] = {}
    result = load_env_file(environ)

    assert result.path is not None and result.path.resolve() == tmp_path / ".env"
    assert result.loaded == ("KEYSTONE_MCP_PORT",)
    assert result.skipped == ()
    assert environ["KEYSTONE_MCP_PORT"] == "9123"


def test_missing_default_file_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    environ: dict[str, str] = {}
    result = load_env_file(environ)

    assert result.path is None
    assert result.loaded == ()
    assert result.skipped == ()
    assert environ == {}


def test_explicit_path_is_used(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    custom = tmp_path / "custom.env"
    custom.write_text("KEYSTONE_MCP_PORT=7000\n", encoding="utf-8")
    # A real .env in cwd must be ignored once KEYSTONE_MCP_ENV_FILE is set.
    (tmp_path / ".env").write_text("KEYSTONE_MCP_PORT=1\n", encoding="utf-8")

    environ = {"KEYSTONE_MCP_ENV_FILE": str(custom)}
    result = load_env_file(environ)

    assert result.path == custom
    assert environ["KEYSTONE_MCP_PORT"] == "7000"


def test_explicit_relative_path_is_resolved_from_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sub = tmp_path / "config"
    sub.mkdir()
    (sub / "service.env").write_text("KEYSTONE_MCP_PORT=7001\n", encoding="utf-8")

    environ = {"KEYSTONE_MCP_ENV_FILE": "config/service.env"}
    result = load_env_file(environ)

    assert result.path is not None and result.path.resolve() == sub / "service.env"
    assert environ["KEYSTONE_MCP_PORT"] == "7001"


def test_explicit_missing_file_is_refused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    environ = {"KEYSTONE_MCP_ENV_FILE": "does-not-exist.env"}
    with pytest.raises(ConfigError, match="does-not-exist.env"):
        load_env_file(environ)


def test_empty_env_file_variable_disables_loading(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("KEYSTONE_MCP_PORT=9123\n", encoding="utf-8")

    environ = {"KEYSTONE_MCP_ENV_FILE": ""}
    result = load_env_file(environ)

    assert result.path is None
    assert result.loaded == ()
    assert result.skipped == ()
    assert environ == {"KEYSTONE_MCP_ENV_FILE": ""}


def test_process_environment_wins(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "KEYSTONE_MCP_PORT=9123\nKEYSTONE_MCP_LOG_LEVEL=DEBUG\n",
        encoding="utf-8",
    )

    environ = {"KEYSTONE_MCP_PORT": "1234", "KEYSTONE_MCP_LOG_LEVEL": ""}
    result = load_env_file(environ)

    assert set(result.skipped) == {"KEYSTONE_MCP_PORT", "KEYSTONE_MCP_LOG_LEVEL"}
    assert result.loaded == ()
    # Unchanged, including the empty value already present.
    assert environ["KEYSTONE_MCP_PORT"] == "1234"
    assert environ["KEYSTONE_MCP_LOG_LEVEL"] == ""


def test_only_keystone_variables_are_loaded(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "COMPOSE_PROJECT_NAME=keystone\nKEYSTONE_MCP_PORT=9123\n",
        encoding="utf-8",
    )

    environ: dict[str, str] = {}
    result = load_env_file(environ)

    assert result.loaded == ("KEYSTONE_MCP_PORT",)
    assert result.skipped == ()
    assert "COMPOSE_PROJECT_NAME" not in environ


@pytest.mark.parametrize(
    ("line", "key", "expected"),
    [
        ('KEYSTONE_MCP_X="a b"', "KEYSTONE_MCP_X", "a b"),
        ("KEYSTONE_MCP_X='x#y'", "KEYSTONE_MCP_X", "x#y"),
        ("export KEYSTONE_MCP_PORT=9000", "KEYSTONE_MCP_PORT", "9000"),
        ("KEYSTONE_MCP_X=val # note", "KEYSTONE_MCP_X", "val"),
        ("KEYSTONE_MCP_X=pa#ss", "KEYSTONE_MCP_X", "pa#ss"),
    ],
)
def test_quotes_export_and_comments(tmp_path, monkeypatch, line, key, expected):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(f"# a comment\n\n{line}\n", encoding="utf-8")

    environ: dict[str, str] = {}
    load_env_file(environ)

    assert environ[key] == expected


def test_line_without_equals_is_refused_with_line_number(tmp_path, monkeypatch):
    # Only a line that looks like ours (starts with KEYSTONE_MCP_) is refused;
    # see test_foreign_line_without_equals_is_skipped_with_warning below for an
    # unrecognised line, which is skipped instead.
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "KEYSTONE_MCP_PORT=9123\nKEYSTONE_MCP_BROKEN_LINE\n",
        encoding="utf-8",
    )

    environ: dict[str, str] = {}
    with pytest.raises(ConfigError, match=r"\.env:2") as exc_info:
        load_env_file(environ)
    # The error names the location only, never the line's own text.
    assert "KEYSTONE_MCP_BROKEN_LINE" not in str(exc_info.value)


def test_foreign_line_without_equals_is_skipped_with_warning(tmp_path, monkeypatch, caplog):
    # A shared .env may carry lines that are not ours at all — for example a
    # continuation line of a multi-line PEM block pasted in by another tool.
    # Those must not blow up loading, and their content must never surface.
    foreign_block = (
        Path(__file__).parent / "data" / "test-keys" / "env-file-foreign-block.txt"
    ).read_text(encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "KEYSTONE_MCP_PORT=9123\n" + foreign_block,
        encoding="utf-8",
    )

    environ: dict[str, str] = {}
    with caplog.at_level("WARNING"):
        result = load_env_file(environ)

    assert result.loaded == ("KEYSTONE_MCP_PORT",)
    assert environ["KEYSTONE_MCP_PORT"] == "9123"
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert "super-secret-key-material-ABCDEF" not in log_text
    assert "PRIVATE KEY" not in log_text
    assert ".env:2" in log_text
    assert ".env:3" in log_text


def test_secret_in_own_broken_line_never_appears_in_exception(tmp_path, monkeypatch):
    # A malformed line that *does* start with KEYSTONE_MCP_ is refused (it is
    # clearly meant for us), but its text — which may itself carry a secret
    # the author meant to assign — must still never reach the exception.
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "KEYSTONE_MCP_SOME_TOKEN top-secret-token-XYZ\n",
        encoding="utf-8",
    )

    environ: dict[str, str] = {}
    with pytest.raises(ConfigError) as exc_info:
        load_env_file(environ)
    assert "top-secret-token-XYZ" not in str(exc_info.value)


def test_quoted_value_with_trailing_comment(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "KEYSTONE_MCP_X=\"value\" # comment\nKEYSTONE_MCP_Y='single' # note\n",
        encoding="utf-8",
    )
    environ: dict[str, str] = {}
    load_env_file(environ)
    assert environ["KEYSTONE_MCP_X"] == "value"
    assert environ["KEYSTONE_MCP_Y"] == "single"


def test_hash_inside_quotes_is_kept(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text('KEYSTONE_MCP_X="pa # ss"\n', encoding="utf-8")
    environ: dict[str, str] = {}
    load_env_file(environ)
    assert environ["KEYSTONE_MCP_X"] == "pa # ss"


def test_unterminated_quote_is_refused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text('KEYSTONE_MCP_X="value\n', encoding="utf-8")
    environ: dict[str, str] = {}
    with pytest.raises(ConfigError, match=r"\.env:1") as exc_info:
        load_env_file(environ)
    assert "KEYSTONE_MCP_X" not in str(exc_info.value)


def test_text_after_closing_quote_is_refused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text('KEYSTONE_MCP_X="a"b\n', encoding="utf-8")
    environ: dict[str, str] = {}
    with pytest.raises(ConfigError, match=r"\.env:1"):
        load_env_file(environ)


def test_pem_with_escaped_newlines_round_trips(tmp_path, monkeypatch):
    import subprocess

    monkeypatch.chdir(tmp_path)
    proc = subprocess.run(
        [
            "openssl",
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
        ],
        capture_output=True,
        check=True,
    )
    pem = proc.stdout.decode("utf-8")
    one_line = pem.replace("\n", "\\n")
    (tmp_path / ".env").write_text(
        f"KEYSTONE_MCP_IDENTITY_SIGNING_KEY={one_line}\n",
        encoding="utf-8",
    )
    environ: dict[str, str] = {}
    load_env_file(environ)
    normalized = normalize_pem_env_value(environ["KEYSTONE_MCP_IDENTITY_SIGNING_KEY"])
    load_pem_private_key(normalized.encode("utf-8"), password=None)


def test_forwarded_allow_ips_in_file_is_flagged(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "KEYSTONE_MCP_PORT=9123\nFORWARDED_ALLOW_IPS=127.0.0.1\n",
        encoding="utf-8",
    )
    environ: dict[str, str] = {}
    result = load_env_file(environ)
    assert result.ignored_forwarded_allow_ips is True
    assert "FORWARDED_ALLOW_IPS" not in environ


def test_forwarded_allow_ips_in_environment_is_not_flagged(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("FORWARDED_ALLOW_IPS=127.0.0.1\n", encoding="utf-8")
    environ = {"FORWARDED_ALLOW_IPS": "10.0.0.1"}
    result = load_env_file(environ)
    assert result.ignored_forwarded_allow_ips is False
