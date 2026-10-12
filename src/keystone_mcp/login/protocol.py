"""The ``LoginProvider`` contract: how a sign-in method plugs into Keystone.

This module is the frozen public surface a login provider is written
against (``tests/test_login_protocol.py::test_protocol_module_is_framework_free``
enforces that it stays free of any framework import). It defines two provider
shapes — ``redirect`` (an external identity provider the browser visits, e.g.
an OIDC login) and ``form`` (credentials collected directly on Keystone's own
login page) — and the small set of types a provider exchanges with Keystone.

Rules every implementation must follow:

- A provider never learns about the OAuth transaction it is embedded in, the
  users directory, cookies, or the login page's HTML. Keystone mints and
  stores the ``state``/``txn``, keeps the per-attempt data a redirect
  provider hands back in ``begin()``, checks the users directory, and issues
  the authorization code. A provider only proves *who* signed in.
- Any refusal a provider wants Keystone to show the user as a sign-in error
  is raised as :class:`LoginRejected` with a :data:`LoginRejectReason`. Any
  other exception a provider raises is treated by Keystone as
  ``"provider_unavailable"`` and logged with a full traceback — a provider
  should not need to catch its own bugs to produce a clean error page.
- :attr:`LoginIdentity.email` is always lower-case with no leading or
  trailing whitespace: the value Keystone looks up in the users directory
  and binds to the issued token.
- A provider must never log a secret, an authorization code, or a token —
  its own or Keystone's.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal, Protocol, runtime_checkable

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

LoginKind = Literal["redirect", "form"]

LoginRejectReason = Literal[
    "invalid_credentials",  # form: wrong key or e-mail
    "identity_invalid",  # redirect: token exchange failed, bad signature, issuer, audience, nonce
    "email_unverified",  # the provider did not confirm the e-mail
    "domain_not_allowed",  # e-mail or hosted domain outside the configured allow-list
    "provider_unavailable",  # the provider could not be reached
    "request_invalid",  # malformed callback (missing code/state, error=... from provider)
]


class LoginRejected(Exception):
    """Raised by a provider to refuse a sign-in attempt with a known reason.

    Any other exception a provider raises is treated by Keystone as
    ``"provider_unavailable"`` and logged with a traceback.
    """

    def __init__(self, reason: LoginRejectReason, message: str = "") -> None:
        super().__init__(message or reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class LoginIdentity:
    """The outcome of a successful sign-in, handed back to Keystone."""

    email: str  # lower-case; the key looked up in the users directory
    provider: str  # provider instance name; becomes the token's auth_method
    interactive: bool  # a person completed an interactive sign-in
    groups: tuple[str, ...] = field(default_factory=tuple)  # informational; RBAC ignores it in 0.5


@dataclass(frozen=True, slots=True)
class LoginRedirect:
    """Where to send the browser, and what to remember about this attempt."""

    url: str  # where to send the browser
    attempt: Mapping[str, str]  # private per-attempt data (nonce, PKCE verifier);
    # Keystone keeps it server-side and hands it back to complete()


@dataclass(frozen=True, slots=True)
class FormField:
    """One input on Keystone's own login form, for a ``form``-kind provider."""

    name: str  # form field name, [a-z_]+
    input_type: Literal["email", "password", "text"]
    label_key: str  # translation key on the login page


@runtime_checkable
class LoginProvider(Protocol):
    """Common shape every sign-in method implements, whatever its kind."""

    @property
    def name(self) -> str: ...  # [a-z][a-z0-9_-]{0,31}; unique per deployment

    @property
    def kind(self) -> LoginKind: ...

    @property
    def title(self) -> str: ...  # plain text shown on the button or form heading

    @property
    def interactive(self) -> bool: ...

    async def warm_up(self) -> None: ...  # once at startup; must not raise on network errors

    async def aclose(self) -> None: ...


@runtime_checkable
class RedirectLoginProvider(LoginProvider, Protocol):
    """A provider the browser is sent away to (e.g. an OIDC authorization endpoint)."""

    async def begin(self, *, state: str, callback_url: str) -> LoginRedirect: ...

    async def complete(
        self, *, params: Mapping[str, str], callback_url: str, attempt: Mapping[str, str]
    ) -> LoginIdentity: ...


@runtime_checkable
class FormLoginProvider(LoginProvider, Protocol):
    """A provider whose credentials are collected on Keystone's own login page."""

    def form_fields(self) -> Sequence[FormField]: ...

    async def verify(self, form: Mapping[str, str]) -> LoginIdentity: ...
