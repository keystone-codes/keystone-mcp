"""Track open client connections so a surface change can reach them.

MCP has two protocol eras that need different delivery for
``notifications/tools/list_changed`` (and, once prompt/resource notifications publish them,
prompts/resources):

- **Handshake era** (``initialize``, pre-``2026-07-28``): the connection has a
  standing back-channel (the standalone SSE stream a client opens with
  ``GET``), and the server pushes the notification onto it directly.
- **``2026-07-28`` era**: there is no connection between requests. Change
  notifications are delivered only on a ``subscriptions/listen`` stream the
  client opens itself; the SDK's :class:`mcp.server.subscriptions.ListenHandler`
  serves that stream and :class:`mcp.server.subscriptions.SubscriptionBus` is
  the fan-out seam that feeds it.

This module owns both delivery paths: :class:`ClientSessionRegistry` keeps a
``WeakSet`` of handshake-era connections (via the mcp SDK's private
``ServerSession._connection`` -- see :func:`ClientSessionRegistry.add`) and a
:class:`KeystoneSubscriptionBus` that counts its own open listen streams
(the SDK's own ``InMemorySubscriptionBus`` does not expose that count, which
the list_changed metric needs). It does not import anything from
``keystone_mcp.router`` or ``keystone_mcp.rbac``: it only knows about
connections and streams, not about tools, routes or policy.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Collection
from typing import TYPE_CHECKING, Literal
from weakref import WeakSet

import anyio
import anyio.lowlevel
from fastmcp.server.middleware import Middleware, MiddlewareContext
from mcp.server.subscriptions import ListenHandler
from mcp.shared.subscriptions import (
    PromptsListChanged,
    ResourcesListChanged,
    ServerEvent,
    ToolsListChanged,
)
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

if TYPE_CHECKING:
    from fastmcp.server.middleware import CallNext
    from mcp.server.connection import Connection
    from mcp.server.session import ServerSession

logger = logging.getLogger(__name__)

ListKind = Literal["tools", "prompts", "resources"]

#: How long a single handshake-era connection may take to accept one
#: notification before it is treated as unresponsive and dropped. A slow or
#: wedged connection must not hold up the rest of the broadcast.
_NOTIFY_TIMEOUT_SECONDS = 1.0

_EVENT_FOR_KIND: dict[ListKind, ServerEvent] = {
    "tools": ToolsListChanged(),
    "prompts": PromptsListChanged(),
    "resources": ResourcesListChanged(),
}


async def _send_tools(connection: Connection) -> None:
    await connection.send_tool_list_changed()


async def _send_prompts(connection: Connection) -> None:
    await connection.send_prompt_list_changed()


async def _send_resources(connection: Connection) -> None:
    await connection.send_resource_list_changed()


_SEND_FOR_KIND: dict[ListKind, Callable[[Connection], Awaitable[None]]] = {
    "tools": _send_tools,
    "prompts": _send_prompts,
    "resources": _send_resources,
}


class KeystoneSubscriptionBus:
    """In-process ``SubscriptionBus`` (mirrors the SDK's own) that can count its listeners.

    Structurally satisfies ``mcp.server.subscriptions.SubscriptionBus``; a
    dedicated class rather than the SDK's ``InMemorySubscriptionBus`` only so
    :meth:`ClientSessionRegistry.broadcast_list_changed` can report how many
    ``subscriptions/listen`` streams are open (``len(bus)``) for the
    ``keystone_mcp_list_changed_sessions_total`` metric -- ``ListenHandler``
    keeps its own stream set private.
    """

    def __init__(self) -> None:
        self._listeners: dict[object, Callable[[ServerEvent], None]] = {}

    async def publish(self, event: ServerEvent) -> None:
        """Deliver ``event`` to every subscribed listener.

        A raising listener is logged and skipped, same as the SDK's own bus:
        one bad listener must not starve the others. Ends with a checkpoint
        so a burst of publishes lets listen streams drain between events.
        """
        for listener in list(self._listeners.values()):
            try:
                listener(event)
            except Exception:
                logger.exception("subscription listener raised; continuing")
        await anyio.lowlevel.checkpoint()

    def subscribe(self, listener: Callable[[ServerEvent], None]) -> Callable[[], None]:
        token = object()
        self._listeners[token] = listener

        def unsubscribe() -> None:
            self._listeners.pop(token, None)

        return unsubscribe

    def __len__(self) -> int:
        """Open ``subscriptions/listen`` streams (one listener per stream)."""
        return len(self._listeners)


class ClientSessionRegistry:
    """Open connections and listen streams this Keystone-MCP instance can notify.

       One instance per server (``build_server``); each replica's registry only
       knows about its own connections and streams -- no cross-replica fan-out
    (see the list_changed developer notes: a Redis-backed bus is not needed because each
       instance's reconciler only ever notifies its own clients).
    """

    def __init__(self) -> None:
        self._bus = KeystoneSubscriptionBus()
        self._listen_handler = ListenHandler(self._bus)
        self._connections: WeakSet[Connection] = WeakSet()

    @property
    def listen_handler(self) -> ListenHandler:
        return self._listen_handler

    def add(self, session: ServerSession) -> None:
        """Remember ``session``'s connection, if it is a notifiable handshake-era one.

        ``session._connection`` is a private mcp API: the same access pattern
        fastmcp's own ping middleware and state-prefix lookup use to reach the
        stable per-connection object behind SDK 2's per-request
        ``ServerSession`` (see ``fastmcp/server/middleware/ping.py`` and
        ``fastmcp/server/context.py``). ``test_registry_reaches_connection_via_private_field``
        guards this field against disappearing on a future mcp upgrade.

        A ``2026-07-28``-era connection or one with no standalone channel is
        not remembered: the former is notified only through
        ``subscriptions/listen`` (see :meth:`broadcast_list_changed`), and the
        latter has no channel to push a notification onto at all.
        """
        connection = getattr(session, "_connection", None)
        if connection is None:
            return
        if connection.protocol_version in MODERN_PROTOCOL_VERSIONS:
            return
        if not connection.has_standalone_channel:
            return
        if connection in self._connections:
            return
        self._connections.add(connection)
        connection.exit_stack.callback(self._connections.discard, connection)

    def __len__(self) -> int:
        """Tracked handshake-era connections (not ``subscriptions/listen`` streams)."""
        return len(self._connections)

    async def broadcast_list_changed(self, kinds: Collection[ListKind]) -> int:
        """Notify every handshake-era connection and every listen stream.

        Returns how many were reached: a handshake-era connection counts once
        it received every requested kind without raising or timing out
        (``_NOTIFY_TIMEOUT_SECONDS`` each); a connection that fails or stalls
        is dropped from the registry instead. Connections are notified one at
        a time (there are few per instance), so one wedged connection delays
        -- but, thanks to the per-call timeout, does not block -- the rest.
        Every open ``subscriptions/listen`` stream is counted regardless of
        which kinds it actually asked for: ``ListenHandler`` itself filters
        delivery to what each stream honored.
        """
        reached = 0
        for connection in list(self._connections):
            delivered = True
            for kind in kinds:
                send = _SEND_FOR_KIND[kind]
                try:
                    with anyio.move_on_after(_NOTIFY_TIMEOUT_SECONDS) as scope:
                        await send(connection)
                    if scope.cancelled_caught:
                        logger.debug(
                            "list_changed notify timed out on a handshake-era "
                            "connection; dropping it"
                        )
                        delivered = False
                        break
                except Exception:
                    # Connection.notify is documented as never raising, but
                    # this is the defensive boundary anyway -- a raising
                    # stand-in connection (tests) or a future mcp change must
                    # not break the rest of the broadcast.
                    logger.debug(
                        "list_changed notify failed on a handshake-era connection; dropping it",
                        exc_info=True,
                    )
                    delivered = False
                    break
            if delivered:
                reached += 1
            else:
                self._connections.discard(connection)

        streams = len(self._bus)
        for kind in kinds:
            await self._bus.publish(_EVENT_FOR_KIND[kind])

        return reached + streams

    def close(self) -> None:
        """End every open ``subscriptions/listen`` stream gracefully."""
        self._listen_handler.close()


class SessionTrackingMiddleware(Middleware):
    """Remembers every handshake-era connection a request arrives on.

    Added to the server first -- before ``ThrottleMiddleware`` and
    ``RbacMiddleware`` -- so a connection is remembered even when the request
    riding it is later throttled or denied by RBAC
    (``test_session_is_tracked_even_when_rbac_denies``): list_changed delivery
    must not depend on what the *first* request on a connection was allowed
    to do.
    """

    def __init__(self, registry: ClientSessionRegistry) -> None:
        self._registry = registry

    async def on_request(self, context: MiddlewareContext, call_next: CallNext) -> object:
        ctx = context.fastmcp_context
        # ``fastmcp_context`` (and its ``request_context``) can be ``None``
        # for messages observed before a session is fully bound (see
        # ``MiddlewareContext.fastmcp_context``'s docstring); there is no
        # session to remember in that case.
        if ctx is not None and ctx.request_context is not None:
            self._registry.add(ctx.request_context.session)
        return await call_next(context)
