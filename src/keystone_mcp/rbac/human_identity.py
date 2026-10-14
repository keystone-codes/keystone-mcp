"""Human-identity gate: tools that require an interactive human login.

Which tools are gated is policy data (``requires_human_identity`` in the policy
file), not code. This module only knows what an interactive identity *is*.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from keystone_mcp.identity import VerifiedIdentity

if TYPE_CHECKING:
    from keystone_mcp.rbac.policy import RbacPolicy


def requires_human_identity(tool_name: str, policy: RbacPolicy | None) -> bool:
    """Whether the active policy gates this tool behind an interactive login."""
    if policy is None:
        return False
    return policy.requires_human_identity(tool_name)


def has_interactive_human_identity(identity: VerifiedIdentity | None) -> bool:
    """True when an interactive human login is bound to the token.

    Reads the ``interactive`` claim the issuing ``LoginProvider`` reported
    (``LoginProvider.interactive``, carried onto the token by
    ``KeystoneOAuthProvider``) -- never the sign-in method's *name*: an OIDC
    provider configured under any name (Okta, Entra, ...) opens these tools
    exactly like Google does, and a provider that happens to be named
    "google" without being interactive does not.
    """
    if identity is None:
        return False
    if identity.subject_type == "service":
        return False
    claims = identity.claims or {}
    if "interactive" in claims:
        return claims["interactive"] is True
    # Kept until 2.0: sessions upgraded from 0.4.x still carry refresh markers
    # without ``interactive``, and they must survive an upgrade.
    return claims.get("auth_method") == "google"
