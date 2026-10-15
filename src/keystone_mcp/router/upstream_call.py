"""The one place Keystone calls a tool on an upstream MCP server.

Every call Keystone makes to an upstream — proxying a tool, forwarding its
progress, its cancellation, or (later) an elicitation round-trip — goes
through :func:`call_upstream_tool`. Most private fastmcp/mcp symbols live
here (``Client._session_kwargs``, ``Client._await_with_session_monitoring``,
``Client._parse_call_tool_result``); others are in ``server.py``
(``FastMCP._mcp_server``), ``router/upstream_content.py`` (``Namespace._transform_uri``),
``router/proxy_components.py`` (``forward_uri``, ``ProxyResource._cached_content``),
and ``surface/client_sessions.py``
(``ServerSession._connection``). The full list and signatures are in
``tests/test_private_api_sentinels.py``.

:class:`DownstreamCall` captures the client request this upstream call is
answering, once, at the top of the request: the client's ``ServerSession``
(SDK 2 creates a fresh one per request -- see its class docstring), the
request id, and the ``progressToken`` the client asked for (if any). Passing
it down explicitly, rather than reading the active request context again
later, is what lets a long-lived stdio session forward progress for a
call it did not itself receive the request on: the session object is bound to
*that* request's response stream no matter which task ends up awaiting it.

Deliberately not used here: ``fastmcp.server.providers.proxy.ProxyClient``.
It forwards sampling, roots, and — critically — ``forward_incoming_headers``,
which would leak the client's own ``Authorization`` header (the Keystone
OAuth token) straight to the upstream.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import anyio
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_context
from fastmcp.tools.base import InputRequiredToolResult
from mcp import types
from mcp.client.session import ClientRequestContext, ElicitationFnT
from mcp.server.connection import MODERN_PROTOCOL_VERSIONS
from mcp.shared.exceptions import MCPError
from mcp_types.jsonrpc import REQUEST_TIMEOUT

if TYPE_CHECKING:
    import mcp.types
    from fastmcp import Client
    from fastmcp.client.client import CallToolResult as ParsedCallToolResult
    from mcp.server.session import ServerSession
    from mcp.types import ProgressToken

logger = logging.getLogger(__name__)

_KEYSTONE_REQUEST_STATE_VERSION = 1
# Same default as mcp.client._input_required.DEFAULT_INPUT_REQUIRED_MAX_ROUNDS (10).
_MAX_INPUT_ROUNDS = 10


async def _accept_upstream_tool_result(_name: str, _result: Any) -> None:
    return None


def skip_upstream_output_validation(client: "Client") -> None:
    """Disable the MCP client's synchronous outputSchema validation for this session.

    Keystone forwards upstream answers transparently; validating on Keystone's
    event loop against a hostile upstream ``pattern`` can stall the process.
    """
    session = getattr(client, "session", None)
    if session is not None:
        session.validate_tool_result = _accept_upstream_tool_result


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
        happens inline in the request task or from a separate one (stdio upstream wiring
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


def downstream_supports_form_elicitation(session: "ServerSession") -> bool:
    """True when the Keystone client declared form-mode elicitation."""
    return session.check_client_capability(
        types.ClientCapabilities(
            elicitation=types.ElicitationCapability(
                form=types.FormElicitationCapability(),
            )
        )
    )


def attach_upstream_elicitation_callback(
    client: "Client",
    callback: ElicitationFnT,
) -> None:
    """Install the raw SDK elicitation callback before the client connects."""
    client._session_kwargs["elicitation_callback"] = callback


async def call_upstream_resource_read(
    client: "Client",
    uri: str,
    *,
    meta: dict[str, Any] | None = None,
    input_responses: types.InputResponses | None = None,
    request_state: str | None = None,
) -> types.ReadResourceResult | types.InputRequiredResult:
    """``resources/read`` on an upstream without forwarding client ``_meta``."""
    if client.protocol_version not in MODERN_PROTOCOL_VERSIONS:
        return await client.read_resource_mcp(uri, meta=meta)
    return await client._await_with_session_monitoring(
        client.session.read_resource(
            uri,
            meta=meta,
            input_responses=input_responses,
            request_state=request_state,
            allow_input_required=True,
        )
    )


async def call_upstream_prompt_modern(
    client: "Client",
    name: str,
    arguments: dict[str, Any],
    *,
    meta: dict[str, Any] | None = None,
    input_responses: types.InputResponses | None = None,
    request_state: str | None = None,
) -> types.GetPromptResult | types.InputRequiredResult:
    """``prompts/get`` on a modern upstream without forwarding client ``_meta``.

    ``meta=None`` keeps the Keystone client's request metadata off the upstream
    call unless Keystone supplies identity metadata itself; ``allow_input_required=True``
    lets guard-round answers flow from the downstream client on MCP 2026-07-28.
    """
    return await client._await_with_session_monitoring(
        client.session.get_prompt(
            name,
            arguments,
            meta=meta,
            input_responses=input_responses,
            request_state=request_state,
            allow_input_required=True,
        )
    )


def make_elicitation_callback(
    downstream: DownstreamCall,
    *,
    namespace: str,
    tool_name: str,
) -> ElicitationFnT:
    """Raw MCP SDK elicitation callback for an upstream client session."""
    rounds = 0

    async def _callback(
        _context: ClientRequestContext,
        params: types.ElicitRequestParams,
    ) -> types.ElicitResult | types.ErrorData:
        from keystone_mcp.observability.metrics import (
            record_upstream_elicitation,
            record_upstream_input_rounds_exceeded,
        )

        nonlocal rounds
        rounds += 1
        if rounds > _MAX_INPUT_ROUNDS:
            logger.warning(
                "upstream elicitation round cap reached namespace=%s tool=%s after %d rounds",
                namespace,
                tool_name,
                _MAX_INPUT_ROUNDS,
            )
            record_upstream_input_rounds_exceeded(namespace=namespace)
            return types.ElicitResult(action="cancel")

        if isinstance(params, types.ElicitRequestURLParams):
            logger.info(
                "upstream elicitation declined namespace=%s: url mode is not forwarded",
                namespace,
            )
            record_upstream_elicitation(namespace=namespace, action="decline")
            return types.ElicitResult(action="decline")

        if getattr(downstream.session, "protocol_version", None) in MODERN_PROTOCOL_VERSIONS:
            logger.info(
                "upstream elicitation declined namespace=%s: a 2026-07-28 client "
                "cannot be asked mid-call",
                namespace,
            )
            record_upstream_elicitation(namespace=namespace, action="decline")
            return types.ElicitResult(action="decline")

        if not isinstance(params, types.ElicitRequestFormParams):
            logger.info(
                "upstream elicitation declined namespace=%s: unsupported elicitation mode",
                namespace,
            )
            record_upstream_elicitation(namespace=namespace, action="decline")
            return types.ElicitResult(action="decline")

        try:
            result = await downstream.session.elicit_form(
                f"[{namespace}] {params.message}",
                params.requested_schema,
                related_request_id=downstream.request_id,
            )
        except Exception:  # noqa: BLE001 — client gone or back-channel closed
            logger.info(
                "upstream elicitation forwarded namespace=%s tool=%s action=%s",
                namespace,
                tool_name,
                "cancel",
            )
            record_upstream_elicitation(namespace=namespace, action="cancel")
            return types.ElicitResult(action="cancel")

        action = result.action
        logger.info(
            "upstream elicitation forwarded namespace=%s tool=%s action=%s",
            namespace,
            tool_name,
            action,
        )
        record_upstream_elicitation(namespace=namespace, action=action)
        return result

    return _callback


def _encode_keystone_request_state(
    upstream_state: str | None,
    declined_keys: list[str],
    rounds: int = 0,
) -> str:
    payload: dict[str, Any] = {
        "v": _KEYSTONE_REQUEST_STATE_VERSION,
        "u": upstream_state,
        "d": declined_keys,
    }
    if rounds:
        payload["n"] = rounds
    return json.dumps(payload, separators=(",", ":"))


def _decode_keystone_request_state(
    request_state: str | None,
) -> tuple[str | None, list[str], int]:
    if not request_state:
        return None, [], 0
    try:
        parsed = json.loads(request_state)
    except json.JSONDecodeError:
        return request_state, [], 0
    if not isinstance(parsed, dict):
        return request_state, [], 0
    upstream = parsed.get("u")
    declined = parsed.get("d")
    if not isinstance(declined, list):
        declined = []
    rounds_raw = parsed.get("n", 0)
    rounds = rounds_raw if isinstance(rounds_raw, int) and rounds_raw >= 0 else 0
    upstream_out = upstream if isinstance(upstream, str) or upstream is None else request_state
    return upstream_out, declined, rounds


def _merge_upstream_input_responses(
    client_responses: types.InputResponses | None,
    declined_keys: list[str],
) -> types.InputResponses:
    merged: types.InputResponses = dict(client_responses or {})
    for key in declined_keys:
        merged[key] = types.ElicitResult(action="decline")
    return merged


def _record_client_elicitation_actions(
    *,
    namespace: str,
    tool_name: str,
    responses: types.InputResponses | None,
) -> None:
    from keystone_mcp.observability.metrics import record_upstream_elicitation

    if not responses:
        return
    for response in responses.values():
        if isinstance(response, types.ElicitResult):
            action = response.action
            logger.info(
                "upstream elicitation forwarded namespace=%s tool=%s action=%s",
                namespace,
                tool_name,
                action,
            )
            record_upstream_elicitation(namespace=namespace, action=action)


def _wrap_upstream_input_required(
    result: types.InputRequiredResult,
    *,
    namespace: str,
    rounds: int,
) -> tuple[InputRequiredToolResult | None, types.InputResponses | None, str | None]:
    """Split an upstream ask into client-visible form asks vs auto-declines.

    Returns ``(tool_result, upstream_responses, upstream_state)`` when every
    request was auto-declined and the upstream must be called again immediately.
    Otherwise returns ``(InputRequiredToolResult, None, None)``.
    """
    client_requests: dict[str, types.ElicitRequest] = {}
    declined_keys: list[str] = []

    for key, request in result.input_requests.items():
        if not isinstance(request, types.ElicitRequest):
            method = getattr(request, "method", type(request).__name__)
            logger.info(
                "upstream input request not forwarded namespace=%s method=%s",
                namespace,
                method,
            )
            raise ToolError(
                f"upstream {namespace} asked for {method}, which keystone-mcp does not forward"
            )
        params = request.params
        if isinstance(params, types.ElicitRequestURLParams):
            declined_keys.append(key)
            continue
        if isinstance(params, types.ElicitRequestFormParams):
            prefixed = params.model_copy(
                update={"message": f"[{namespace}] {params.message}"},
            )
            client_requests[key] = request.model_copy(update={"params": prefixed})
            continue
        declined_keys.append(key)

    if not client_requests:
        responses = _merge_upstream_input_responses(None, declined_keys)
        return None, responses, result.request_state

    wrapped = types.InputRequiredResult(
        input_requests=client_requests,
        request_state=_encode_keystone_request_state(
            result.request_state,
            declined_keys,
            rounds,
        ),
    )
    return InputRequiredToolResult(wrapped), None, None


async def call_upstream_tool(
    client: "Client",
    name: str,
    arguments: dict[str, Any],
    *,
    timeout: float,
    meta: dict[str, Any] | None = None,
    downstream: DownstreamCall | None = None,
    log_namespace: str | None = None,
    input_responses: types.InputResponses | None = None,
    request_state: str | None = None,
    proxy_elicitation: bool = True,
) -> "mcp.types.CallToolResult | InputRequiredToolResult":
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

    downstream_version = (
        getattr(downstream.session, "protocol_version", None) if downstream is not None else None
    )
    modern_downstream = downstream is not None and downstream_version in MODERN_PROTOCOL_VERSIONS
    upstream_version = getattr(client, "protocol_version", None)
    modern_upstream = (
        upstream_version in MODERN_PROTOCOL_VERSIONS if upstream_version is not None else False
    )

    skip_upstream_output_validation(client)

    try:
        if proxy_elicitation and modern_downstream and modern_upstream:
            if input_responses is not None:
                _record_client_elicitation_actions(
                    namespace=log_namespace or "",
                    tool_name=name,
                    responses=input_responses,
                )
            upstream_state, declined_keys, rounds = _decode_keystone_request_state(request_state)
            upstream_input_responses = _merge_upstream_input_responses(
                input_responses,
                declined_keys,
            )
            namespace = log_namespace or ""
            try:
                with anyio.fail_after(timeout):
                    while True:
                        result = await client._await_with_session_monitoring(
                            client.session.call_tool(
                                name,
                                arguments,
                                read_timeout_seconds=timeout,
                                progress_callback=forward,
                                meta=meta,
                                input_responses=upstream_input_responses or None,
                                request_state=upstream_state,
                                allow_input_required=True,
                            )
                        )
                        if isinstance(result, types.InputRequiredResult):
                            rounds += 1
                            if rounds >= _MAX_INPUT_ROUNDS:
                                from keystone_mcp.observability.metrics import (
                                    record_upstream_input_rounds_exceeded,
                                )

                                logger.warning(
                                    "upstream input round cap reached namespace=%s tool=%s "
                                    "after %d rounds",
                                    namespace,
                                    name,
                                    rounds,
                                )
                                record_upstream_input_rounds_exceeded(namespace=namespace)
                                raise ToolError(
                                    f"upstream {namespace} kept requesting input; "
                                    f"stopped after {rounds} rounds"
                                )
                            wrapped, auto_responses, auto_state = _wrap_upstream_input_required(
                                result,
                                namespace=namespace,
                                rounds=rounds,
                            )
                            if wrapped is not None:
                                return wrapped
                            upstream_input_responses = auto_responses
                            upstream_state = auto_state
                            continue
                        return result
            except TimeoutError as exc:
                raise ToolError(f"upstream {namespace} did not answer within {timeout:g}s") from exc

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
