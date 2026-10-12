"""Verified identity and the deterministic task_id derived from it.

The hosted MCP derives a deterministic ``task_id`` from the verified identity,
the tool name and a canonical serialization of the arguments. Determinism is
what lets a repeated call hit a previously published result (idempotency / peek
short-circuit). The verified subject is propagated downstream as
``X-Keystone-Subject`` and ``X-Keystone-Subject-Type``; for people,
``X-Author-Email`` is also sent (deprecated since 0.5.0, removed in 2.0).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from keystone_mcp.user_directory.types import (
    parse_service_subject,
    service_subject,
    subject_type_of,
)
from keystone_mcp.user_directory.util import normalize_email

# Header carrying the verified user identity to every downstream target.
AUTHOR_EMAIL_HEADER = "X-Author-Email"
SUBJECT_HEADER = "X-Keystone-Subject"
SUBJECT_TYPE_HEADER = "X-Keystone-Subject-Type"


@dataclass(frozen=True, init=False)
class VerifiedIdentity:
    """Identity extracted from a validated OAuth access token.

    ``subject`` is the verified OAuth claim: an email for people, ``svc:<name>``
    for service accounts. A single service token may back many users; the
    identity still comes from the per-user OAuth connection.
    """

    subject: str
    subject_type: Literal["human", "service"]
    claims: dict[str, Any] | None
    client_id: str | None

    def __init__(
        self,
        subject: str | None = None,
        claims: dict[str, Any] | None = None,
        *,
        subject_type: Literal["human", "service"] | None = None,
        email: str | None = None,
        client_id: str | None = None,
    ) -> None:
        if subject is not None and email is not None:
            raise TypeError("pass either subject= or email=, not both")
        resolved_subject = subject if subject is not None else email
        if not resolved_subject:
            raise TypeError("subject or email is required")
        resolved_type = subject_type or subject_type_of(resolved_subject)
        if resolved_type == "human":
            resolved_subject = normalize_email(resolved_subject)
        else:
            svc_name = parse_service_subject(resolved_subject)
            if svc_name is not None:
                resolved_subject = service_subject(svc_name)
        object.__setattr__(self, "subject", resolved_subject)
        object.__setattr__(self, "subject_type", resolved_type)
        object.__setattr__(self, "claims", claims)
        object.__setattr__(self, "client_id", client_id)

    @property
    def email(self) -> str | None:
        """The person's e-mail; ``None`` for a service account."""
        if self.subject_type == "human":
            return self.subject
        return None


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
    subject = claims.get("subject") or claims.get("email") or token.subject
    if not subject:
        return None
    subject_type = claims.get("subject_type") or subject_type_of(str(subject))
    if subject_type not in ("human", "service"):
        subject_type = subject_type_of(str(subject))
    return VerifiedIdentity(
        subject=str(subject),
        claims=claims,
        subject_type=subject_type,
        client_id=getattr(token, "client_id", None),
    )


def upstream_identity_headers(identity: VerifiedIdentity) -> dict[str, str]:
    """Headers Keystone attaches when calling an upstream MCP server."""
    headers = {
        SUBJECT_HEADER: identity.subject,
        SUBJECT_TYPE_HEADER: identity.subject_type,
    }
    if identity.email is not None:
        headers[AUTHOR_EMAIL_HEADER] = identity.email
    return headers


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
    parts = [identity.subject]
    if namespace:
        parts.append(namespace)
    parts.extend([tool_name, canonical(args)])
    if idempotency_token:
        parts.append(idempotency_token)
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return f"t_{digest[:32]}"
