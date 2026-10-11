"""Human-identity gate: tools that require an interactive human login.

Which tools are gated is policy data (``requires_human_identity`` in the policy
file), not code. This module only knows what an interactive identity *is*.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from keystone_mcp.identity import VerifiedIdentity

if TYPE_CHECKING:
    from keystone_mcp.rbac.policy import RbacPolicy

#: ``auth_method`` claim value the platform sets for an interactive OIDC login.
INTERACTIVE_AUTH_METHOD = "google"


def requires_human_identity(tool_name: str, policy: RbacPolicy | None) -> bool:
    """Whether the active policy gates this tool behind an interactive login."""
    if policy is None:
        return False
    return policy.requires_human_identity(tool_name)


def has_interactive_human_identity(identity: VerifiedIdentity | None) -> bool:
    """True when an interactive human login is bound to the token."""
    if identity is None:
        return False
    claims = identity.claims or {}
    return claims.get("auth_method") == INTERACTIVE_AUTH_METHOD
