"""The one place Keystone calls a tool on an upstream MCP server.

Every call Keystone makes to an upstream — proxying a tool, forwarding its
progress, its cancellation, or (later) an elicitation round-trip — goes
through :func:`call_upstream_tool`. Centralizing it here keeps fastmcp/mcp
private APIs (``Client._parse_call_tool_result`` today; ``Client.
_session_kwargs`` and ``Client._await_with_session_monitoring`` once
elicitation lands) confined to one module instead of scattered across the
proxy adapter, so an SDK upgrade only has one place to re-check.

:class:`DownstreamCall` captures the client request this upstream call is
answering, once, at the top of the request: the client's ``ServerSession``
(SDK 2 creates a fresh one per request -- see its class docstring), the
request id, and the ``progressToken`` the client asked for (if any). Passing
it down explicitly, rather than reading the active request context again
later, is what lets a long-lived stdio session (Y09) forward progress for a
call it did not itself receive the request on: the session object is bound to
*that* request's response stream no matter which task ends up awaiting it.

Deliberately not used here: ``fastmcp.server.providers.proxy.ProxyClient``.
It forwards sampling, roots, and — critically — ``forward_incoming_headers``,
which would leak the client's own ``Authorization`` header (the Keystone
OAuth token) straight to the upstream.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import anyio
from fastmcp.server.dependencies import get_context
from mcp.shared.exceptions import MCPError
from mcp_types.jsonrpc import REQUEST_TIMEOUT

if TYPE_CHECKING:
    import mcp.types
    from fastmcp import Client
    from fastmcp.client.client import CallToolResult as ParsedCallToolResult
    from mcp.server.session import ServerSession
    from mcp.types import ProgressToken

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DownstreamCall:
    """The client request that is waiting for this upstream call."""

    session: "ServerSession"
    request_id: str | None
    progress_token: "ProgressToken | None"

    @classmethod
    def current(cls) -> "DownstreamCall | None":
        """Capture from the active FastMCP request; ``None`` outside one.

        "Outside one" covers a unit test that calls an adapter directly, and
        any future caller that runs off the request task (there is none yet).
        Values are captured once here rather than re-read later, which is
        what makes the forwarding work the same way whether the upstream call
        happens inline in the request task or from a separate one (Y09's
        stdio read loop, shared across many client requests).
        """
        try:
            ctx = get_context()
        except RuntimeError:
            return None
        rc = ctx.request_context
        if rc is None:
            return None
        meta = rc.meta or {}
        return cls(
            session=rc.session,
            request_id=rc.request_id,
            progress_token=meta.get("progressToken"),
        )


async def call_upstream_tool(
    client: "Client",
    name: str,
    arguments: dict[str, Any],
    *,
    timeout: float,
    meta: dict[str, Any] | None = None,
    downstream: DownstreamCall | None = None,
    log_namespace: str | None = None,
) -> "mcp.types.CallToolResult":
    """Call *name* on the upstream *client* is connected to.

    When *downstream* carries a ``progressToken`` (the client asked for
    progress on the call this upstream call is answering), a handler is
    registered that relays every ``notifications/progress`` the upstream
    sends back to that same client request, via its own ``ServerSession.
    report_progress`` -- which stamps the *client's* token, not the upstream's,
    and is a no-op if the client never asked.

    No handler of *ours* is registered otherwise (``progress_handler=None``
    is passed to ``call_tool_mcp``) -- but this does not mean the upstream
    never sees a ``progressToken`` at all: fastmcp's own ``Client`` always
    substitutes a default, log-only progress handler when none is given
    (``Client.__init__``), so it still asks the upstream for progress, same
    as it would on any other call. That default handler never reaches past
    this process, so nothing is forwarded on to the real client either way;
    see ``tests/test_proxy_progress.py::
    test_no_progress_token_means_no_forwarding`` for exactly what this
    function does and does not control.

    The client's own token (if Keystone itself was called with one, e.g. by
    another MCP server proxying through it) is never forwarded upstream:
    *this* call gets its own, fresh request to the upstream, with the
    upstream's own request id as the implicit token the SDK assigns when a
    ``progress_handler`` is passed.

    A client that went away mid-call (dropped connection, request cancelled)
    must not fail the upstream call over a progress notification it can no
    longer deliver -- the upstream's own answer is still worth returning.
    """
    forward = None
    if downstream is not None and downstream.progress_token is not None:

        async def forward(progress: float, total: float | None, message: str | None) -> None:
            try:
                await downstream.session.report_progress(progress, total, message)
            except Exception as exc:  # noqa: BLE001 - the client going away must not fail the call
                logger.debug("progress forward dropped: %s", type(exc).__name__)

    try:
        return await client.call_tool_mcp(
            name, arguments, progress_handler=forward, timeout=timeout, meta=meta
        )
    except anyio.get_cancelled_exc_class():
        # MCP SDK 2 sends notifications/cancelled (legacy handshake) or aborts the
        # request POST (2026-07-28) when this task is cancelled; we only log.
        logger.info(
            "upstream call cancelled namespace=%s tool=%s reason=%s",
            log_namespace,
            name,
            "cancelled by the client",
        )
        raise
    except MCPError as exc:
        if exc.code == REQUEST_TIMEOUT:
            logger.info(
                "upstream call cancelled namespace=%s tool=%s reason=%s",
                log_namespace,
                name,
                "timed out in keystone-mcp",
            )
        raise


async def parse_for_status_envelope(
    client: "Client",
    name: str,
    result: "mcp.types.CallToolResult",
) -> "ParsedCallToolResult":
    """Parse a raw upstream result into fastmcp's ``CallToolResult`` (with ``.data``).

    ``status_envelope`` mode (P03) needs the upstream's answer decoded against
    its own output schema (``result.data``), which the public ``ToolResult.
    from_mcp_result`` does not do. ``Client._parse_call_tool_result`` is
    private fastmcp API -- re-check this on every fastmcp upgrade; it is
    guarded by ``tests/test_proxy_progress.py::
    test_status_envelope_mode_still_parses_data``. Call it only from here,
    and only while *client*'s session is still open: the schema it decodes
    against comes from the session's cached tool list.
    """
    return await client._parse_call_tool_result(name, result, raise_on_error=False)
