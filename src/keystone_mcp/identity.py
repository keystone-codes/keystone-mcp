"""Verified identity and the deterministic task_id derived from it.

The hosted MCP derives a deterministic ``task_id`` from the verified identity,
the tool name and a canonical serialization of the arguments. Determinism is
what lets a repeated call hit a previously published result (idempotency / peek
short-circuit). The verified email is propagated downstream as the
``X-Author-Email`` header.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

# Header carrying the verified user identity to every downstream target.
AUTHOR_EMAIL_HEADER = "X-Author-Email"


@dataclass(frozen=True)
class VerifiedIdentity:
    """Identity extracted from a validated OAuth access token.

    ``email`` is the verified OAuth claim, never a client-asserted header. A
    single service token may back many users; the identity still comes from the
    per-user OAuth connection.
    """

    email: str
    claims: dict[str, Any] | None = None


def resolve_verified_identity() -> VerifiedIdentity | None:
    """Extract verified identity from the FastMCP OAuth access token."""
    try:
        from fastmcp.server.dependencies import get_access_token
    except Exception:
        return None
    token = get_access_token()
    if token is None:
        return None
    claims = token.claims or {}
    email = claims.get("email") or token.subject
    if not email:
        return None
    return VerifiedIdentity(email=email, claims=claims)


def _canonicalize(value: Any) -> Any:
    """Recursively normalize a value into a canonical, order-stable form."""
    if isinstance(value, dict):
        return {k: _canonicalize(value[k]) for k in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_canonicalize(v) for v in value]
    return value


def canonical(args: dict[str, Any] | None) -> str:
    """Return a deterministic canonical JSON string for *args*.

    Keys are sorted at every level and separators are fixed so that the same
    logical arguments always serialize identically regardless of input order.
    """
    normalized = _canonicalize(args or {})
    return json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def make_task_id(
    identity: VerifiedIdentity,
    tool_name: str,
    args: dict[str, Any] | None,
    *,
    namespace: str | None = None,
    idempotency_token: str | None = None,
) -> str:
    """Deterministic ``task_id = hash(verified_identity + tool + canonical(args))``.

    When *namespace* is set (upstream proxy routes), it is included so identical
    tool names from different upstream APIs do not collide.

    An optional ``idempotency_token`` lets a caller intentionally fork a new task
    for otherwise-identical arguments.
    """
    parts = [identity.email]
    if namespace:
        parts.append(namespace)
    parts.extend([tool_name, canonical(args)])
    if idempotency_token:
        parts.append(idempotency_token)
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return f"t_{digest[:32]}"
