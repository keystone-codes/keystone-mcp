"""The ``LoginProvider`` protocol: Keystone's pluggable sign-in contract.

Re-exports only the names defined in :mod:`keystone_mcp.login.protocol`. The
built-in implementations (:mod:`keystone_mcp.login.google`,
:mod:`keystone_mcp.login.api_key`) and the factory
(:mod:`keystone_mcp.login.factory`) are imported from their own modules, not
from here, so importing this package alone never pulls in fastmcp, mcp,
starlette, httpx, or any other framework dependency.
"""

from __future__ import annotations

from keystone_mcp.login.protocol import (
    FormField,
    FormLoginProvider,
    LoginIdentity,
    LoginKind,
    LoginProvider,
    LoginRedirect,
    LoginRejected,
    LoginRejectReason,
    RedirectLoginProvider,
)

__all__ = [
    "FormField",
    "FormLoginProvider",
    "LoginIdentity",
    "LoginKind",
    "LoginProvider",
    "LoginRedirect",
    "LoginRejectReason",
    "LoginRejected",
    "RedirectLoginProvider",
]
