"""Innermost middleware: latency and outcome metrics for executed tool calls."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware, MiddlewareContext

if TYPE_CHECKING:
    from mcp.types import CallToolRequestParams

    from keystone_mcp.observability.service import RbacObservability


class ToolCallObservabilityMiddleware(Middleware):
    """Record invocation metrics only when the call reaches the handler."""

    def __init__(self, *, observability: RbacObservability | None = None) -> None:
        self._observability = observability

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next,
    ):
        tool_name = context.message.name
        started = time.perf_counter()
        outcome = "success"
        try:
            result = await call_next(context)
            if getattr(result, "is_error", False):
                outcome = "tool_error"
            return result
        except ToolError:
            outcome = "tool_error"
            raise
        except Exception:
            outcome = "error"
            raise
        finally:
            if self._observability is not None:
                elapsed = time.perf_counter() - started
                self._observability.record_tool_invocation(
                    tool_name=tool_name,
                    outcome=outcome,
                    duration_seconds=elapsed,
                )
