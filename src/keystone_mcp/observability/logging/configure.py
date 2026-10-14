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

_last_configured_settings: Settings | None = None

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

_FASTMCP_LOGGER = "fastmcp"
_UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")


def reapply_logger_levels(settings: Settings | None = None) -> None:
    """Reattach FastMCP/uvicorn loggers to the root handler after they reconfigure."""
    global _last_configured_settings
    if settings is None:
        settings = _last_configured_settings
    if settings is None:
        return
    try:
        import fastmcp

        fastmcp.settings.log_enabled = False
    except (AttributeError, ImportError):
        pass

    noisy_level = logging.DEBUG if settings.log_level.upper() == "DEBUG" else logging.WARNING

    fastmcp_log = logging.getLogger(_FASTMCP_LOGGER)
    fastmcp_log.handlers.clear()
    fastmcp_log.propagate = True
    fastmcp_log.setLevel(noisy_level)

    for name in _UVICORN_LOGGERS:
        log = logging.getLogger(name)
        log.handlers.clear()
        log.propagate = True

    if settings.log_level.upper() != "DEBUG":
        for name in _NOISY_LOGGERS:
            logging.getLogger(name).setLevel(logging.WARNING)


def configure_logging(settings: Settings) -> None:
    """Replace basicConfig with structured, redacted platform logging."""
    global _last_configured_settings
    _last_configured_settings = settings
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

    reapply_logger_levels(settings)
