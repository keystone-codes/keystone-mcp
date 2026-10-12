"""Tests for configure_logging."""

from __future__ import annotations

import io
import json
import logging
from dataclasses import replace

import pytest

from keystone_mcp.config import ConfigError, Settings, _parse_log_format, _parse_log_level
from keystone_mcp.observability.logging import configure_logging
from keystone_mcp.observability.logging.formatters import JsonFormatter, SecretRedactingFilter


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
