"""Reference verifier for Keystone-MCP's signed identity assertion.

Standalone, no dependency on ``keystone_mcp`` itself -- only ``PyJWT>=2.8``.
Copy this file (or vendor its logic) into your own upstream service; it is
not published as a package. See ``../../../docs/connecting-services.md``
(section "Who is calling: X-Keystone-Identity") for the full contract.

Usage (HS256, per-upstream secret)::

    from keystone_identity import IdentityError, verify_keystone_identity

    try:
        identity = verify_keystone_identity(
            request.headers.get("x-keystone-identity"),
            secrets=[os.environ["MYSVC_IDENTITY_SECRET"]],
            audience="mysvc-mcp",  # this upstream's own registry entry name
            issuer=os.environ["KEYSTONE_MCP_BASE_URL"].rstrip("/"),
        )
    except IdentityError as exc:
        raise ValueError(f"identity rejected: {exc}") from exc

Usage (ES256, Keystone JWKS)::

    identity = verify_keystone_identity(
        request.headers.get("x-keystone-identity"),
        jwks_url="https://keystone.example/.well-known/keystone-identity-jwks.json",
        audience="mysvc-mcp",
        issuer="https://keystone.example",
        algorithms=["ES256"],
    )

Keystone's issuer is ``KEYSTONE_MCP_BASE_URL`` without a trailing slash.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import dataclass

import jwt

#: JWT header ``typ`` Keystone-MCP stamps on every assertion -- distinguishes
#: it from any other JWT an upstream might otherwise accept on this header.
IDENTITY_TYP = "keystone-identity+jwt"

#: Default algorithms for each verification mode.
_HS256_ALGORITHMS = ["HS256"]
_ES256_ALGORITHMS = ["ES256"]

_JWK_CLIENTS: dict[str, jwt.PyJWKClient] = {}
_JWK_CLIENTS_LOCK = threading.Lock()


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
    rbac_decision: str | None
    auth_method: str
    interactive: bool
    client_id: str | None
    task_id: str
    mcp_method: str
    mcp_target: str
    jti: str


def _jwks_client(jwks_url: str) -> jwt.PyJWKClient:
    with _JWK_CLIENTS_LOCK:
        client = _JWK_CLIENTS.get(jwks_url)
        if client is None:
            client = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300)
            _JWK_CLIENTS[jwks_url] = client
        return client


def verify_keystone_identity(
    token: str | None,
    *,
    secrets: Sequence[str] | None = None,
    jwks_url: str | None = None,
    audience: str,
    issuer: str,
    leeway: int = 30,
    algorithms: Sequence[str] | None = None,
    accept_observe_denials: bool = False,
) -> KeystoneIdentity:
    """Verify one ``X-Keystone-Identity`` header; raise :class:`IdentityError` otherwise.

    For HS256, pass *secrets* (tried in order so a secret can be rotated without
    downtime). For ES256, pass *jwks_url* pointing at Keystone's
    ``/.well-known/keystone-identity-jwks.json`` and set *algorithms* to
    ``["ES256"]`` (or rely on the default ES256 list when *jwks_url* is set).

    Never read the algorithm from the token itself (the classic "alg: none" /
    algorithm-confusion attack) -- the caller pins *algorithms* on the verify
    call.

    *audience* is required: it must be this upstream's own registry entry
    ``name`` (not its ``namespace``). *issuer* must be Keystone's
    ``KEYSTONE_MCP_BASE_URL`` without a trailing slash.
    """
    if not token:
        raise IdentityError("missing X-Keystone-Identity")
    if not audience:
        raise IdentityError("audience is required")
    if not issuer or not issuer.strip():
        raise IdentityError("issuer is required")
    if secrets and jwks_url:
        raise IdentityError("pass either secrets (HS256) or jwks_url (ES256), not both")
    if not secrets and not jwks_url:
        raise IdentityError("secrets or jwks_url is required")

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise IdentityError(f"malformed X-Keystone-Identity: {exc}") from exc
    if header.get("typ") != IDENTITY_TYP:
        raise IdentityError(f"unexpected typ: {header.get('typ')!r}")

    if jwks_url:
        allowed = list(algorithms) if algorithms is not None else _ES256_ALGORITHMS
        client = _jwks_client(jwks_url)
        try:
            signing_key = client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=allowed,
                audience=audience,
                issuer=issuer,
                leeway=leeway,
                options={"require": ["exp", "iat", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise IdentityError(f"signature or claims rejected: {exc}") from exc
        return _identity_from_claims(claims, accept_observe_denials=accept_observe_denials)

    allowed = list(algorithms) if algorithms is not None else _HS256_ALGORITHMS
    last_error: jwt.PyJWTError | None = None
    assert secrets is not None
    for secret in secrets:
        try:
            claims = jwt.decode(
                token,
                secret,
                algorithms=allowed,
                audience=audience,
                issuer=issuer,
                leeway=leeway,
                options={"require": ["exp", "iat", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            last_error = exc
            continue
        return _identity_from_claims(claims, accept_observe_denials=accept_observe_denials)

    raise IdentityError(f"signature or claims rejected: {last_error}") from last_error


def _identity_from_claims(
    claims: dict,
    *,
    accept_observe_denials: bool,
) -> KeystoneIdentity:
    rbac_decision = claims.get("rbac_decision")
    if rbac_decision == "deny" and not accept_observe_denials:
        raise IdentityError("Keystone RBAC would deny this call")
    return KeystoneIdentity(
        sub=claims["sub"],
        sub_type=claims.get("sub_type", "human"),
        email=claims.get("email"),
        roles=tuple(claims.get("roles") or ()),
        rbac=claims.get("rbac", "off"),
        rbac_decision=rbac_decision,
        auth_method=claims.get("auth_method", "unknown"),
        interactive=bool(claims.get("interactive", False)),
        client_id=claims.get("client_id"),
        task_id=claims.get("task_id", ""),
        mcp_method=claims.get("mcp_method", ""),
        mcp_target=claims.get("mcp_target", ""),
        jti=claims.get("jti", ""),
    )
