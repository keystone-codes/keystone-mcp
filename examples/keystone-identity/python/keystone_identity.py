"""Reference verifier for Keystone-MCP's signed identity assertion.

Standalone, no dependency on ``keystone_mcp`` itself -- only ``PyJWT>=2.8``.
Copy this file (or vendor its logic) into your own upstream service; it is
not published as a package. See ``../../../docs/connecting-services.md``
(section "Who is calling: X-Keystone-Identity") for the full contract.

Usage::

    from keystone_identity import IdentityError, verify_keystone_identity

    try:
        identity = verify_keystone_identity(
            request.headers.get("x-keystone-identity"),
            secrets=[os.environ["MYSVC_IDENTITY_SECRET"]],
            audience="mysvc-mcp",  # this upstream's own registry entry name
        )
    except IdentityError as exc:
        raise ValueError(f"identity rejected: {exc}") from exc
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import jwt

#: JWT header ``typ`` Keystone-MCP stamps on every assertion -- distinguishes
#: it from any other JWT an upstream might otherwise accept on this header.
IDENTITY_TYP = "keystone-identity+jwt"

#: The only algorithm ever accepted. Never read the algorithm from the token
#: itself (the classic "alg: none" / algorithm-confusion attack) -- PyJWT's
#: ``algorithms=`` parameter already enforces this, but it is spelled out
#: here because it is the one rule that must never be relaxed.
_ALGORITHMS = ["HS256"]


class IdentityError(Exception):
    """The assertion is missing, malformed, or fails verification.

    The message never includes the raw token -- only PyJWT's own short
    description of what failed.
    """


@dataclass(frozen=True)
class KeystoneIdentity:
    """The verified claims of one ``X-Keystone-Identity`` assertion."""

    sub: str
    sub_type: str
    email: str | None
    roles: tuple[str, ...]
    rbac: str
    auth_method: str
    interactive: bool
    client_id: str | None
    task_id: str
    mcp_method: str
    mcp_target: str
    jti: str


def verify_keystone_identity(
    token: str | None,
    *,
    secrets: Sequence[str],
    audience: str,
    issuer: str | None = None,
    leeway: int = 30,
) -> KeystoneIdentity:
    """Verify one ``X-Keystone-Identity`` header; raise :class:`IdentityError` otherwise.

    *secrets* is tried in order, so a secret can be rotated by configuring
    the new and old value together for one deployment, then dropping the old
    one once Keystone-MCP has restarted with the new secret.

    *audience* is required: it must be this upstream's own registry entry
    ``name`` (not its ``namespace``) -- the whole point of ``aud`` is that an
    assertion signed for a different upstream, even with the same secret by
    mistake, is rejected here. *issuer* is checked only when given.
    """
    if not token:
        raise IdentityError("missing X-Keystone-Identity")
    if not audience:
        raise IdentityError("audience is required")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise IdentityError(f"malformed X-Keystone-Identity: {exc}") from exc
    if header.get("typ") != IDENTITY_TYP:
        raise IdentityError(f"unexpected typ: {header.get('typ')!r}")

    last_error: jwt.PyJWTError | None = None
    for secret in secrets:
        try:
            claims = jwt.decode(
                token,
                secret,
                algorithms=_ALGORITHMS,
                audience=audience,
                issuer=issuer,
                leeway=leeway,
                options={"require": ["exp", "iat", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            last_error = exc
            continue
        return _identity_from_claims(claims)

    raise IdentityError(f"signature or claims rejected: {last_error}") from last_error


def _identity_from_claims(claims: dict) -> KeystoneIdentity:
    return KeystoneIdentity(
        sub=claims["sub"],
        sub_type=claims.get("sub_type", "human"),
        email=claims.get("email"),
        roles=tuple(claims.get("roles") or ()),
        rbac=claims.get("rbac", "off"),
        auth_method=claims.get("auth_method", "unknown"),
        interactive=bool(claims.get("interactive", False)),
        client_id=claims.get("client_id"),
        task_id=claims.get("task_id", ""),
        mcp_method=claims.get("mcp_method", ""),
        mcp_target=claims.get("mcp_target", ""),
        jti=claims.get("jti", ""),
    )
