"""``ApiKeyLoginProvider`` — the email + api_token form as a ``LoginProvider``.

Wraps an :class:`~keystone_mcp.auth.identity_provider.IdentityProvider`
(dev-token set or auth-service introspection) behind the ``FormLoginProvider``
shape: Keystone renders the two fields on its own login page and posts them
straight back to this provider for verification.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from keystone_mcp.auth.identity_provider import IdentityProvider
from keystone_mcp.login.protocol import FormField, LoginIdentity, LoginKind, LoginRejected
from keystone_mcp.user_directory.util import normalize_email


class ApiKeyLoginProvider:
    """The api_token + email form as a ``form``-kind ``LoginProvider``."""

    def __init__(self, identity: IdentityProvider) -> None:
        self._identity = identity

    @property
    def name(self) -> str:
        return "api_key"

    @property
    def kind(self) -> LoginKind:
        return "form"

    @property
    def title(self) -> str:
        return "API key"

    @property
    def interactive(self) -> bool:
        return False

    async def warm_up(self) -> None:
        return None

    async def aclose(self) -> None:
        return None

    def form_fields(self) -> Sequence[FormField]:
        return (
            FormField("email", "email", "email_label"),
            FormField("api_token", "password", "token_label"),
        )

    async def verify(self, form: Mapping[str, str]) -> LoginIdentity:
        email = normalize_email(str(form.get("email", "")))
        api_token = str(form.get("api_token", ""))
        if not await self._identity.verify(api_token, email):
            raise LoginRejected("invalid_credentials")
        return LoginIdentity(email=email, provider="api_key", interactive=False)
