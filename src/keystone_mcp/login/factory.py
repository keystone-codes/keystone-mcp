"""Build and validate the configured list of ``LoginProvider`` instances.

Entry-point based discovery of third-party providers arrives with X09; for
now this only assembles the two built-in providers Keystone has always
shipped (Google, API key) from ``Settings``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from keystone_mcp.auth.google_oidc import GoogleOidcClient
from keystone_mcp.auth.identity_provider import IdentityProvider
from keystone_mcp.config import Settings
from keystone_mcp.login.api_key import ApiKeyLoginProvider
from keystone_mcp.login.google import GoogleLoginProvider
from keystone_mcp.login.protocol import FormLoginProvider, LoginProvider, RedirectLoginProvider

_PROVIDER_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


def build_login_providers(
    settings: Settings,
    *,
    identity_provider: IdentityProvider,
    google_oidc_client: GoogleOidcClient | None = None,
) -> list[LoginProvider]:
    """Assemble the providers for the login page, in display order.

    Order matches the blocks the login page has always shown: Google first
    (when enabled), then the api_token + email form (when enabled).
    """
    providers: list[LoginProvider] = []
    if settings.google_login_enabled:
        client = google_oidc_client or GoogleOidcClient(
            settings.google_client_id,
            settings.google_client_secret,
            settings.google_redirect_uri,
        )
        providers.append(GoogleLoginProvider(client, allowed_domain=settings.google_allowed_domain))
    if settings.api_key_login_enabled:
        providers.append(ApiKeyLoginProvider(identity_provider))
    return providers


def validate_login_providers(providers: Sequence[LoginProvider]) -> None:
    """Check the configured provider set for the invariants Keystone relies on.

    - Names are unique and match ``^[a-z][a-z0-9_-]{0,31}$`` (safe to use
      verbatim in a route path).
    - At most one provider declares ``kind == "form"``: the login page has a
      single credential form, posted to ``/login``.
    - Every provider actually implements the protocol its own ``kind``
      promises.

    Raises ``ValueError`` naming the offending provider on any violation.
    """
    seen: set[str] = set()
    form_count = 0
    for provider in providers:
        name = provider.name
        if not _PROVIDER_NAME_RE.match(name):
            raise ValueError(f"login provider name is not valid: {name!r}")
        if name in seen:
            raise ValueError(f"duplicate login provider name: {name!r}")
        seen.add(name)

        if provider.kind == "redirect":
            if not isinstance(provider, RedirectLoginProvider):
                raise ValueError(
                    f"login provider {name!r} declares kind='redirect' but does not "
                    "implement RedirectLoginProvider (begin/complete)"
                )
        elif provider.kind == "form":
            if not isinstance(provider, FormLoginProvider):
                raise ValueError(
                    f"login provider {name!r} declares kind='form' but does not "
                    "implement FormLoginProvider (form_fields/verify)"
                )
            form_count += 1
        else:
            raise ValueError(f"login provider {name!r} has an unknown kind: {provider.kind!r}")

    if form_count > 1:
        raise ValueError("at most one form-kind login provider is allowed")
