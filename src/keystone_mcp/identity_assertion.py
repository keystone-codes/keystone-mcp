"""Signed identity assertion forwarded to upstream MCP services.

Every proxied tool call carries a short-lived JWT, ``X-Keystone-Identity``,
telling the upstream who is calling: the verified subject, the roles RBAC used
to allow this call, the auth method, the OAuth client, the task id, and which
tool was invoked. It is signed HS256 with a secret unique to the upstream
(``auth.identity_secret_env`` in the registry entry), so compromising one
upstream's secret never lets it forge an assertion for another.

``X-Author-Email`` (``keystone_mcp.identity.AUTHOR_EMAIL_HEADER``) is still
sent alongside it, unsigned, deprecated since 0.5.0 (kept until 2.0).
"""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from math import ceil
from typing import TYPE_CHECKING, Any

import jwt

from keystone_mcp.user_directory.util import normalize_email

if TYPE_CHECKING:
    from keystone_mcp.identity import VerifiedIdentity

#: Header carrying the signed identity assertion to the upstream.
IDENTITY_HEADER = "X-Keystone-Identity"

#: JWT header ``typ`` value — distinguishes this assertion from any other JWT
#: an upstream might otherwise accept on the same header.
IDENTITY_TYP = "keystone-identity+jwt"

#: Key under a stdio ``tools/call`` request's ``params._meta`` the assertion
#: is carried in instead of an HTTP header (Y09). Defined here, used there.
IDENTITY_META_KEY = "keystone-mcp/identity"

#: Minimum length, in UTF-8 bytes, of an ``auth.identity_secret_env`` value.
MIN_SECRET_BYTES = 32

#: Extra seconds of validity past the call's own timeout, so the assertion
#: never expires before the call it authenticates can finish.
ASSERTION_SKEW_SECONDS = 60

#: ``sub_type`` values accepted on a :class:`~keystone_mcp.identity.
#: VerifiedIdentity`; anything else (including absent, pre-X07) defaults to
#: ``"human"``.
_KNOWN_SUBJECT_TYPES = frozenset({"human", "service"})


def resolve_identity_secret(name: str, var: str) -> bytes:
    """Read and validate one upstream's identity-assertion secret.

    Shared by the registry loader (``upstream_registry/load.py``, which only
    validates — the secret itself is read again here) and
    :meth:`~keystone_mcp.router.upstream.UpstreamRegistry.add_upstream`,
    which builds the actual :class:`IdentityAssertionSigner` from it. *name*
    is the upstream registry entry's ``name`` (for the error message), *var*
    is the environment variable named by ``auth.identity_secret_env``.

    Raises ``ValueError`` naming the registry entry and the variable — never
    its value — when the variable is unset, empty, or shorter than
    :data:`MIN_SECRET_BYTES` bytes (UTF-8).
    """
    value = os.environ.get(var, "")
    if not value.strip():
        raise ValueError(
            f"upstream {name!r}: auth.identity_secret_env names {var}, which is not set or empty"
        )
    secret = value.encode("utf-8")
    if len(secret) < MIN_SECRET_BYTES:
        raise ValueError(f"upstream {name!r}: {var} must be at least {MIN_SECRET_BYTES} bytes")
    return secret


def build_identity_claims(
    *,
    issuer: str,
    audience: str,
    identity: "VerifiedIdentity",
    roles: list[str],
    rbac_mode: str,
    task_id: str,
    mcp_method: str,
    mcp_target: str,
    timeout_seconds: float,
    now: float | None = None,
) -> dict[str, Any]:
    """Build the claim set for ``X-Keystone-Identity``, per the 0.5.0 contract.

    Pure function (no signing, no I/O) so the claim shape can be tested
    without a secret. Only the fields in the 0.5.0 contract are ever present:
    ``email`` is included only for a human subject, ``client_id`` only when
    the identity carries one.
    """
    # Local import: keystone_mcp.rbac re-exports keystone_mcp.rbac.loader,
    # which imports keystone_mcp.router.registry -- and this module is
    # imported from keystone_mcp.adapters.mcp_proxy, which router.registry's
    # own import chain (router -> router.upstream -> adapters -> mcp_proxy)
    # reaches before adapters/__init__ finishes. A module-level import here
    # would reenter this same (still-initializing) module and fail.
    from keystone_mcp.rbac.human_identity import has_interactive_human_identity

    subject = getattr(identity, "subject", None)
    sub_type = getattr(identity, "subject_type", None)
    if sub_type not in _KNOWN_SUBJECT_TYPES:
        sub_type = "human"
    sub = subject or getattr(identity, "subject", None)
    if not sub:
        email = getattr(identity, "email", None)
        sub = normalize_email(email) if email else ""
    elif getattr(identity, "email", None) is not None and sub == getattr(identity, "email", None):
        sub = normalize_email(sub)

    issued_at = int(now if now is not None else time.time())
    expires_at = issued_at + ceil(timeout_seconds) + ASSERTION_SKEW_SECONDS

    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "sub_type": sub_type,
        "roles": sorted(roles),
        "rbac": rbac_mode,
        "auth_method": (identity.claims or {}).get("auth_method") or "unknown",
        "interactive": has_interactive_human_identity(identity),
        "task_id": task_id,
        "mcp_method": mcp_method,
        "mcp_target": mcp_target,
        "iat": issued_at,
        "exp": expires_at,
        "jti": secrets.token_urlsafe(16),
    }

    if sub_type == "human" and identity.email:
        claims["email"] = normalize_email(identity.email)

    client_id = getattr(identity, "client_id", None)
    if client_id:
        claims["client_id"] = client_id

    return claims


@dataclass(frozen=True, slots=True)
class IdentityAssertionSigner:
    """Signs ``X-Keystone-Identity`` assertions for one upstream registry entry."""

    audience: str
    # Never included in repr() — the registry (and anything that logs it)
    # must stay safe to print as a whole.
    secret: bytes = field(repr=False)
    issuer: str

    def sign(
        self,
        *,
        identity: "VerifiedIdentity",
        task_id: str,
        mcp_method: str,
        mcp_target: str,
        timeout_seconds: float,
        rbac_mode: str,
        now: float | None = None,
    ) -> str:
        """Build and sign one assertion for a single upstream call.

        Roles come from the RBAC decision recorded for this call (``[]`` if
        none was recorded, e.g. RBAC off) via
        :data:`keystone_mcp.rbac.call_decision.current_call_decision` — never
        from the caller, so an adapter cannot assert roles RBAC did not
        actually use to allow the call.
        """
        # Local import: see the matching note in build_identity_claims.
        from keystone_mcp.rbac.call_decision import current_call_decision

        decision = current_call_decision.get()
        roles = sorted(decision.roles) if decision is not None else []
        claims = build_identity_claims(
            issuer=self.issuer,
            audience=self.audience,
            identity=identity,
            roles=roles,
            rbac_mode=rbac_mode,
            task_id=task_id,
            mcp_method=mcp_method,
            mcp_target=mcp_target,
            timeout_seconds=timeout_seconds,
            now=now,
        )
        return jwt.encode(claims, self.secret, algorithm="HS256", headers={"typ": IDENTITY_TYP})
