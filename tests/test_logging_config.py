"""Tests for configure_logging."""

from __future__ import annotations

import io
import json
import logging
import re
from dataclasses import replace
from pathlib import Path

import pytest

from keystone_mcp.config import ConfigError, Settings, _parse_log_format, _parse_log_level
from keystone_mcp.observability.logging import configure_logging, reapply_logger_levels
from keystone_mcp.observability.logging.formatters import JsonFormatter, SecretRedactingFilter

REPO_ROOT = Path(__file__).resolve().parents[1]
OBSERVABILITY_LOGGING_DOC = REPO_ROOT / "docs" / "observability-logging.md"


def test_parse_log_level_rejects_garbage() -> None:
    with pytest.raises(ConfigError):
        _parse_log_level("verbose")


def test_parse_log_format_rejects_unknown() -> None:
    with pytest.raises(ConfigError):
        _parse_log_format("yaml")


def test_configure_logging_json_emits_ndjson() -> None:
    settings = replace(Settings(), log_format="json", log_level="INFO", log_redact=True)
    configure_logging(settings)
    buffer = io.StringIO()
    root = logging.getLogger()
    assert root.handlers
    root.handlers[0].stream = buffer

    logging.getLogger("test.logging").info("hello world")
    payload = json.loads(buffer.getvalue().strip())
    assert payload["msg"] == "hello world"
    assert payload["stream"] == "app"
    assert payload["level"] == "INFO"


def test_configure_logging_caps_noisy_loggers_at_info() -> None:
    settings = replace(Settings(), log_level="INFO")
    configure_logging(settings)
    assert logging.getLogger("httpx").level == logging.WARNING
    # fastmcp 4 / mcp SDK 2's own HTTP stack logs under httpx2/httpcore2 (X02).
    assert logging.getLogger("httpx2").level == logging.WARNING
    assert logging.getLogger("httpcore2").level == logging.WARNING


def test_json_formatter_includes_stream_extra() -> None:
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="rbac audit {}",
        args=(),
        exc_info=None,
    )
    record.stream = "audit"
    line = JsonFormatter().format(record)
    payload = json.loads(line)
    assert payload["stream"] == "audit"


def test_fastmcp_logger_propagates_to_root() -> None:
    settings = replace(Settings(), log_format="json", log_level="INFO")
    configure_logging(settings)
    fastmcp_log = logging.getLogger("fastmcp")
    assert not fastmcp_log.handlers
    assert fastmcp_log.propagate is True


def test_uvicorn_loggers_have_no_own_handlers() -> None:
    settings = replace(Settings(), log_format="json", log_level="INFO")
    configure_logging(settings)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        log = logging.getLogger(name)
        assert not log.handlers
        assert log.propagate is True


def test_reapply_logger_levels_after_uvicorn_config() -> None:
    import logging.config

    import uvicorn

    settings = replace(Settings(), log_format="json", log_level="INFO")
    configure_logging(settings)
    root_handler_before = logging.getLogger().handlers[0]

    logging.config.dictConfig(uvicorn.config.LOGGING_CONFIG)
    assert logging.getLogger("uvicorn").handlers

    reapply_logger_levels(settings)
    assert not logging.getLogger("uvicorn").handlers
    assert logging.getLogger("uvicorn").propagate is True
    assert logging.getLogger().handlers[0] is root_handler_before


def test_json_lines_are_compact() -> None:
    record = logging.LogRecord(
        name="keystone_mcp.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="GET /",
        args=(),
        exc_info=None,
    )
    record.stream = "access"
    line = JsonFormatter().format(record)
    assert '"stream":"access"' in line
    assert '"stream": "access"' not in line


def test_documented_grep_finds_access_lines() -> None:
    record = logging.LogRecord(
        name="keystone_mcp.access",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="GET /",
        args=(),
        exc_info=None,
    )
    record.stream = "access"
    line = JsonFormatter().format(record)
    doc = OBSERVABILITY_LOGGING_DOC.read_text(encoding="utf-8")
    match = re.search(r"grep \'([^\']+)\'", doc)
    assert match is not None, "grep pattern not found in observability-logging.md"
    assert re.search(match.group(1), line)


def test_secret_redacting_filter_masks_bearer() -> None:
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="token Bearer abc.def.ghi",
        args=(),
        exc_info=None,
    )
    SecretRedactingFilter().filter(record)
    assert "abc.def" not in record.msg
