"""Signed identity assertion forwarded to upstream MCP services.

Every proxied tool call carries a short-lived JWT, ``X-Keystone-Identity``,
telling the upstream who is calling: the verified subject, the roles RBAC used
to allow this call, the auth method, the OAuth client, the task id, and which
tool was invoked. It is signed HS256 with a secret unique to the upstream
(``auth.identity_secret_env`` in the registry entry), or ES256 with a single
deployment-wide EC P-256 key (``KEYSTONE_MCP_IDENTITY_SIGNING_KEY`` and
``auth.identity_alg: ES256``), so compromising one upstream's secret never lets
it forge an assertion for another.

``X-Author-Email`` (``keystone_mcp.identity.AUTHOR_EMAIL_HEADER``) is still
sent alongside it, unsigned, deprecated since 0.5.0 (kept until 2.0).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from math import ceil
from typing import TYPE_CHECKING, Any, Literal

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key

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

#: Published JWKS document for ES256 identity assertions (Y11).
IDENTITY_JWKS_PATH = "/.well-known/keystone-identity-jwks.json"

#: Minimum length, in UTF-8 bytes, of an ``auth.identity_secret_env`` value.
MIN_SECRET_BYTES = 32

#: Extra seconds of validity past the call's own timeout, so the assertion
#: never expires before the call it authenticates can finish.
ASSERTION_SKEW_SECONDS = 60

#: ``sub_type`` values accepted on a :class:`~keystone_mcp.identity.
#: VerifiedIdentity`; anything else (including absent, pre-X07) defaults to
#: ``"human"``.
_KNOWN_SUBJECT_TYPES = frozenset({"human", "service"})


def normalize_pem_env_value(raw: str) -> str:
    """Expand a one-line PEM env value (``\\n`` escapes) to a multi-line PEM."""
    stripped = raw.strip()
    if "\\n" in stripped and "\n" not in stripped:
        return stripped.replace("\\n", "\n")
    return stripped


def load_ec_p256_private_key(pem: str) -> EllipticCurvePrivateKey:
    """Parse a PEM EC P-256 private key; raise ``ValueError`` on failure."""
    normalized = normalize_pem_env_value(pem)
    if not normalized:
        raise ValueError("empty PEM")
    try:
        key = load_pem_private_key(normalized.encode("utf-8"), password=None)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid PEM") from exc
    if not isinstance(key, EllipticCurvePrivateKey):
        raise ValueError("not an EC private key")
    if key.curve.name != "secp256r1":
        raise ValueError("curve is not P-256")
    return key


def ec_public_key_jwk_thumbprint(public_key: EllipticCurvePublicKey) -> str:
    """RFC 7638 thumbprint for an EC public key (``kid`` for ES256 assertions)."""
    jwk_dict = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(public_key))
    canonical = json.dumps(
        {"crv": jwk_dict["crv"], "kty": jwk_dict["kty"], "x": jwk_dict["x"], "y": jwk_dict["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def identity_signing_key_from_env() -> EllipticCurvePrivateKey | None:
    """Return the deployment ES256 signing key, or ``None`` when unset."""
    raw = os.environ.get("KEYSTONE_MCP_IDENTITY_SIGNING_KEY", "")
    if not raw.strip():
        return None
    return load_ec_p256_private_key(raw)


def _ec_private_key_to_jwk(private_key: EllipticCurvePrivateKey) -> dict[str, Any]:
    public_key = private_key.public_key()
    jwk_dict = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(public_key))
    kid = ec_public_key_jwk_thumbprint(public_key)
    jwk_dict.update({"kid": kid, "alg": "ES256", "use": "sig"})
    return jwk_dict


def build_identity_jwks(
    private_key: EllipticCurvePrivateKey,
    *,
    previous_key: EllipticCurvePrivateKey | None = None,
) -> dict[str, Any]:
    """Build the JWKS payload served at :data:`IDENTITY_JWKS_PATH`."""
    keys = [_ec_private_key_to_jwk(private_key)]
    if previous_key is not None:
        previous_jwk = _ec_private_key_to_jwk(previous_key)
        if previous_jwk["kid"] != keys[0]["kid"]:
            keys.append(previous_jwk)
    return {"keys": keys}


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
    rbac_decision: str | None = None,
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

    if rbac_decision is not None:
        claims["rbac_decision"] = rbac_decision

    return claims


@dataclass(frozen=True, slots=True)
class IdentityAssertionSigner:
    """Signs ``X-Keystone-Identity`` assertions for one upstream registry entry."""

    audience: str
    issuer: str
    # HS256: ``secret`` is set. ES256: ``private_key`` and ``kid`` are set.
    # Never included in repr() — the registry (and anything that logs it)
    # must stay safe to print as a whole.
    secret: bytes | None = field(default=None, repr=False)
    private_key: EllipticCurvePrivateKey | None = field(default=None, repr=False)
    kid: str | None = None

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
        rbac_decision = None
        if decision is not None:
            rbac_decision = "allow" if decision.allowed else "deny"
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
            rbac_decision=rbac_decision,
        )
        headers: dict[str, str] = {"typ": IDENTITY_TYP}
        if self.private_key is not None:
            assert self.kid is not None
            headers["kid"] = self.kid
            return jwt.encode(claims, self.private_key, algorithm="ES256", headers=headers)
        assert self.secret is not None
        return jwt.encode(claims, self.secret, algorithm="HS256", headers=headers)

    @property
    def algorithm(self) -> Literal["HS256", "ES256"]:
        return "ES256" if self.private_key is not None else "HS256"
