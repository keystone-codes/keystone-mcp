"""The RBAC decision for the tool call currently in flight.

:class:`~keystone_mcp.router.rbac_middleware.RbacMiddleware` is the only
writer: it sets this for the duration of ``call_next`` in ``on_call_tool`` so
that code further down the same call — in particular
:class:`keystone_mcp.identity_assertion.IdentityAssertionSigner`, which has no
other way to learn which roles RBAC actually used — can read the roles behind
this call without threading them through every layer in between.

This works because FastMCP runs middleware, the mounted sub-server, the tool,
the engine and the adapter in one ``asyncio`` task (plain nested ``await``,
no new task is spawned), so a :class:`contextvars.ContextVar` set here is
still visible there. If a future change makes an upstream call happen in a new
task, this stops working silently (the signer would just see ``None`` and
assert ``roles: []``) — see ``tests/test_proxy_foreign_upstream.py::
test_identity_assertion_roles_match_rbac_decision``.

``RbacDecision`` is imported only under ``TYPE_CHECKING``: this module must
not import :mod:`keystone_mcp.router.rbac_middleware` at runtime, since that
module (via the router package) does not import ``rbac`` — importing it here
for real would create an import cycle.
"""

from __future__ import annotations

from contextvars import ContextVar
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from keystone_mcp.router.rbac_middleware import RbacDecision

#: The :class:`RbacDecision` for the tool call currently executing in this
#: task, or ``None`` outside of one (including when RBAC is off, or for the
#: upstream discovery/list-tools path, which never sets this).
current_call_decision: "ContextVar[RbacDecision | None]" = ContextVar(
    "keystone_call_decision", default=None
)
