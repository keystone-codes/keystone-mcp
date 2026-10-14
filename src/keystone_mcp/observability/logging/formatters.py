"""Structured log formatters and redacting filter."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from keystone_mcp.observability.logging.context import get_request_id
from keystone_mcp.observability.logging.redact import redact_dict, redact_string, redact_value

_STRUCTURED_EXTRA_KEYS = frozenset(
    {
        "stream",
        "method",
        "path",
        "status",
        "duration_ms",
        "client_ip",
        "request_id",
    }
)


class SecretRedactingFilter(logging.Filter):
    """Redact secrets from log record message and arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_string(record.msg)
        if record.args:
            record.args = tuple(redact_value(arg) for arg in record.args)
        if record.exc_info and record.exc_text:
            record.exc_text = redact_string(record.exc_text)
        return True


def _record_request_id(record: logging.LogRecord) -> str | None:
    explicit = getattr(record, "request_id", None)
    if explicit:
        return str(explicit)
    return get_request_id()


def _structured_fields(record: logging.LogRecord) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key in _STRUCTURED_EXTRA_KEYS:
        if key == "request_id":
            continue
        if hasattr(record, key):
            value = getattr(record, key)
            if value is not None:
                fields[key] = value
    rid = _record_request_id(record)
    if rid:
        fields["request_id"] = rid
    return fields


class JsonFormatter(logging.Formatter):
    """One JSON object per line (NDJSON)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "stream": getattr(record, "stream", "app"),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        payload.update(_structured_fields(record))
        if record.exc_info and not record.exc_text:
            payload["exc_info"] = redact_string(self.formatException(record.exc_info))
        elif record.exc_text:
            payload["exc_info"] = redact_string(record.exc_text)
        payload["msg"] = redact_string(str(payload["msg"]))
        payload = redact_dict(payload)
        return json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":"))


class TextFormatter(logging.Formatter):
    """Human-readable single-line format with optional structured suffix."""

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        extra = _structured_fields(record)
        stream = getattr(record, "stream", None)
        if stream and stream != "app":
            extra.setdefault("stream", stream)
        if not extra:
            return base
        suffix = " ".join(f"{key}={value}" for key, value in sorted(extra.items()))
        return f"{base} ({suffix})"
