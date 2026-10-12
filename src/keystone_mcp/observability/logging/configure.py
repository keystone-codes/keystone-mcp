"""Central logging setup for server and CLI entrypoints."""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING

from keystone_mcp.observability.logging.formatters import (
    JsonFormatter,
    SecretRedactingFilter,
    TextFormatter,
)

if TYPE_CHECKING:
    from keystone_mcp.config import Settings

# fastmcp 4 / mcp SDK 2 moved their own HTTP stack to httpx2/httpcore2 (X02);
# our own HTTP code still logs under "httpx"/"httpcore", so both pairs are
# quieted here.
_NOISY_LOGGERS = (
    "httpx",
    "httpcore",
    "httpx2",
    "httpcore2",
    "uvicorn",
    "uvicorn.error",
    "uvicorn.access",
)


def configure_logging(settings: Settings) -> None:
    """Replace basicConfig with structured, redacted platform logging."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    if settings.log_format == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(TextFormatter())

    redact_filter: SecretRedactingFilter | None = None
    if settings.log_redact:
        redact_filter = SecretRedactingFilter()
        handler.addFilter(redact_filter)

    root.addHandler(handler)

    if settings.log_redact and redact_filter is not None:
        for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
            log = logging.getLogger(name)
            log.addFilter(redact_filter)

    if settings.log_level.upper() != "DEBUG":
        for name in _NOISY_LOGGERS:
            logging.getLogger(name).setLevel(logging.WARNING)

    logging.getLogger("keystone_mcp.access").setLevel(level)
    logging.getLogger("keystone_mcp.observability.audit").setLevel(level)
