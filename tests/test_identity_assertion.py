"""Signed identity assertion (X-Keystone-Identity): claim shape and signing."""

from __future__ import annotations

from dataclasses import dataclass

import jwt
import pytest

from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.identity_assertion import (
    IDENTITY_TYP,
    IdentityAssertionSigner,
    build_identity_claims,
)
from keystone_mcp.rbac.call_decision import current_call_decision
from keystone_mcp.router.rbac_middleware import RbacDecision

ISSUER = "https://keystone.example"
AUDIENCE = "docs-mcp"
SECRET = b"s" * 32

HUMAN = VerifiedIdentity(email="ann@example.com", claims={"auth_method": "google"})

_EXPECTED_REQUIRED_FIELDS = {
    "iss",
    "aud",
    "sub",
    "sub_type",
    "roles",
    "rbac",
    "auth_method",
    "interactive",
    "task_id",
    "mcp_method",
    "mcp_target",
    "iat",
    "exp",
    "jti",
}


@dataclass
class _FutureIdentity:
    """Stands in for a post-X07 VerifiedIdentity (subject, subject_type, client_id)."""

    email: str
    claims: dict | None = None
    subject: str | None = None
    subject_type: str | None = None
    client_id: str | None = None


def _claims(**overrides):
    base = dict(
        issuer=ISSUER,
        audience=AUDIENCE,
        identity=HUMAN,
        roles=[],
        rbac_mode="enforce",
        task_id="t_test",
        mcp_method="tools/call",
        mcp_target="whoami",
        timeout_seconds=180,
    )
    base.update(overrides)
    return build_identity_claims(**base)


def test_claims_have_exact_field_set():
    human_claims = _claims(identity=HUMAN, roles=["member"])
    assert set(human_claims) == _EXPECTED_REQUIRED_FIELDS | {"email"}
    assert human_claims["email"] == "ann@example.com"

    full = _FutureIdentity(
        email="svc-owner@example.com",
        claims={"auth_method": "api_key"},
        subject="svc:ci",
        subject_type="service",
        client_id="client-123",
    )
    service_claims = _claims(identity=full, roles=[])
    # A service subject never carries email, even if the identity object has
    # one; client_id is included whenever present.
    assert set(service_claims) == _EXPECTED_REQUIRED_FIELDS | {"client_id"}
    assert service_claims["client_id"] == "client-123"
    assert service_claims["sub"] == "svc:ci"
    assert service_claims["sub_type"] == "service"

    minimal = _FutureIdentity(
        email="svc-owner@example.com", subject="svc:ci", subject_type="service"
    )
    minimal_claims = _claims(identity=minimal)
    assert set(minimal_claims) == _EXPECTED_REQUIRED_FIELDS


def test_signature_verifies_with_secret_and_audience():
    signer = IdentityAssertionSigner(audience=AUDIENCE, secret=SECRET, issuer=ISSUER)
    token = signer.sign(
        identity=HUMAN,
        task_id="t_1",
        mcp_method="tools/call",
        mcp_target="whoami",
        timeout_seconds=180,
        rbac_mode="enforce",
    )

    header = jwt.get_unverified_header(token)
    assert header["typ"] == IDENTITY_TYP
    assert header["alg"] == "HS256"

    decoded = jwt.decode(token, SECRET, algorithms=["HS256"], audience=AUDIENCE, issuer=ISSUER)
    assert decoded["aud"] == AUDIENCE
    assert decoded["iss"] == ISSUER
    assert decoded["sub"] == "ann@example.com"
    assert decoded["mcp_target"] == "whoami"


def test_wrong_secret_or_audience_is_rejected():
    signer = IdentityAssertionSigner(audience=AUDIENCE, secret=SECRET, issuer=ISSUER)
    token = signer.sign(
        identity=HUMAN,
        task_id="t_1",
        mcp_method="tools/call",
        mcp_target="whoami",
        timeout_seconds=30,
        rbac_mode="off",
    )

    with pytest.raises(jwt.InvalidSignatureError):
        jwt.decode(token, b"w" * 32, algorithms=["HS256"], audience=AUDIENCE, issuer=ISSUER)

    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(token, SECRET, algorithms=["HS256"], audience="someone-else", issuer=ISSUER)


def test_expiry_covers_tool_timeout():
    claims = _claims(timeout_seconds=180)
    assert claims["exp"] - claims["iat"] >= 180

    overridden = _claims(timeout_seconds=600)
    assert overridden["exp"] - overridden["iat"] >= 600


def test_roles_come_from_rbac_decision():
    signer = IdentityAssertionSigner(audience=AUDIENCE, secret=SECRET, issuer=ISSUER)
    decision = RbacDecision(
        tool_name="hello_whoami",
        email="ann@example.com",
        allowed=True,
        roles=frozenset({"member", "analyst"}),
    )

    token_handle = current_call_decision.set(decision)
    try:
        token = signer.sign(
            identity=HUMAN,
            task_id="t_1",
            mcp_method="tools/call",
            mcp_target="whoami",
            timeout_seconds=30,
            rbac_mode="enforce",
        )
    finally:
        current_call_decision.reset(token_handle)
    decoded = jwt.decode(token, SECRET, algorithms=["HS256"], audience=AUDIENCE, issuer=ISSUER)
    assert decoded["roles"] == ["analyst", "member"]
    assert decoded["rbac"] == "enforce"

    # No decision in context (e.g. RBAC off: RbacMiddleware is never mounted).
    no_decision_token = signer.sign(
        identity=HUMAN,
        task_id="t_2",
        mcp_method="tools/call",
        mcp_target="whoami",
        timeout_seconds=30,
        rbac_mode="off",
    )
    decoded_off = jwt.decode(
        no_decision_token, SECRET, algorithms=["HS256"], audience=AUDIENCE, issuer=ISSUER
    )
    assert decoded_off["roles"] == []
    assert decoded_off["rbac"] == "off"


def test_sub_type_defaults_to_human_and_reads_identity():
    plain = VerifiedIdentity(email="Ann@Example.com")
    claims = _claims(identity=plain)
    assert claims["sub_type"] == "human"
    assert claims["sub"] == "ann@example.com"
    # email is normalized the same way as sub (same identity, same case).
    assert claims["email"] == "ann@example.com"

    service = _FutureIdentity(email="", claims=None, subject="svc:ci", subject_type="service")
    service_claims = _claims(identity=service)
    assert service_claims["sub"] == "svc:ci"
    assert service_claims["sub_type"] == "service"
    assert "email" not in service_claims

    garbage_type = _FutureIdentity(
        email="x@example.com", claims=None, subject=None, subject_type="robot"
    )
    garbage_claims = _claims(identity=garbage_type)
    assert garbage_claims["sub_type"] == "human"
    assert garbage_claims["sub"] == "x@example.com"


def test_signer_repr_hides_secret():
    secret = b"q" * 40
    signer = IdentityAssertionSigner(audience=AUDIENCE, secret=secret, issuer=ISSUER)
    assert secret.decode() not in repr(signer)
    assert "secret" not in repr(signer)
