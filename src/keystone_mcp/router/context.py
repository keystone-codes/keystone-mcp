"""Transport-level context passed to a route's transform and adapter.

Everything here is transport-level (no business validation): the verified
identity, the deterministic task_id, the canonical args, and endpoint config.
The "inner logic" of a route (e.g. building a webhook payload or mapping args to
an external request) lives in the transform and reads from this context.
"""

from __future__ import annotations

from dataclasses import dataclass

from keystone_mcp.adapters.base import Pattern
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity


@dataclass(frozen=True)
class RouteContext:
    verified_identity: VerifiedIdentity
    task_id: str
    canonical_args: str
    tool_name: str
    pattern: Pattern
    settings: Settings
