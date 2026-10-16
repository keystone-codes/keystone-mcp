"""Neutral client-visible messages for upstream transport and protocol failures."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import httpx2
from fastmcp.exceptions import PromptError, ResourceError, ToolError
from mcp.shared.exceptions import MCPError
from mcp_types.jsonrpc import REQUEST_TIMEOUT

from keystone_mcp.observability.logging.context import get_request_id

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

_INIT_SESSION_FAILURE = "Failed to initialize server session"


def _is_timeout(exc: BaseException) -> bool:
    if isinstance(exc, TimeoutError):
        return True
    if isinstance(exc, httpx2.TimeoutException):
        return True
    if isinstance(exc, MCPError) and exc.code == REQUEST_TIMEOUT:
        return True
    return False


def _is_unavailable(exc: BaseException) -> bool:
    if isinstance(exc, httpx2.TransportError):
        return True
    if isinstance(exc, RuntimeError):
        text = str(exc).lower()
        if _INIT_SESSION_FAILURE.lower() in text or "failed to connect" in text:
            return True
    return False


def neutral_upstream_message(
    namespace: str,
    exc: BaseException,
    *,
    timeout: float,
) -> str | None:
    """Return a client-safe message, or ``None`` if *exc* should propagate unchanged."""
    if isinstance(exc, (ToolError, PromptError, ResourceError)):
        return None
    try:
        import anyio

        cancelled = anyio.get_cancelled_exc_class()
    except anyio.NoEventLoopError:
        cancelled = None
    if isinstance(exc, asyncio.CancelledError):
        return None
    if cancelled is not None and isinstance(exc, cancelled):
        return None
    if _is_timeout(exc):
        return f"upstream {namespace} did not answer within {timeout:g}s"
    if _is_unavailable(exc):
        return f"upstream {namespace} is unavailable"
    if isinstance(exc, MCPError):
        return f"upstream {namespace} returned an error (code {exc.code})"
    return f"upstream {namespace} failed to answer"


def log_upstream_failure(
    namespace: str,
    exc: BaseException,
    *,
    upstream_tool: str | None = None,
) -> None:
    request_id = get_request_id()
    logger.warning(
        "upstream call failed namespace=%s tool=%s request_id=%s exc=%s: %s",
        namespace,
        upstream_tool or "",
        request_id or "",
        type(exc).__name__,
        exc,
        exc_info=False,
    )


def rethrow_upstream_error(
    namespace: str,
    exc: BaseException,
    *,
    timeout: float,
    error_type: Callable[[str], BaseException] = ToolError,
) -> None:
    message = neutral_upstream_message(namespace, exc, timeout=timeout)
    if message is None:
        raise exc
    raise error_type(message) from exc
