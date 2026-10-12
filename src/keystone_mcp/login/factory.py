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

# Provider names a deployment may never configure for a custom implementation.
#
# - "redirect-not-allowed" is the fixed route authorize() sends a refused
#   redirect_uri to (server.py registers GET /login/redirect-not-allowed
#   unconditionally); a provider claiming that name would collide with it.
# - "google" is reserved for the built-in GoogleLoginProvider itself: nothing
#   else may claim it, since RBAC's interactive-human check
#   (rbac/human_identity.py) and _complete_login's provider-name check both
#   trust the *route* a sign-in came back on, and a custom provider named
#   "google" would ride on that trust.
_RESERVED_PROVIDER_NAMES = frozenset({"redirect-not-allowed"})

_FORM_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
_VALID_FORM_FIELD_INPUT_TYPES = frozenset({"email", "password", "text"})


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

    - Names are unique, match ``^[a-z][a-z0-9_-]{0,31}$`` in full (safe to use
      verbatim in a route path -- ``fullmatch``, not ``match``: a name ending
      in e.g. ``"\\n"`` must not slip through just because ``$`` also matches
      right before a trailing newline), and are not one of the names Keystone
      itself reserves (see ``_RESERVED_PROVIDER_NAMES``, and "google" for
      anything other than the built-in Google provider).
    - At most one provider declares ``kind == "form"``: the login page has a
      single credential form, posted to ``/login``.
    - Every provider actually implements the protocol its own ``kind``
      promises.
    - A ``form``-kind provider's fields have a safe ``name``
      (``^[A-Za-z0-9_]+$``, verbatim in the rendered ``<input name=...>``) and
      a recognised ``input_type``.

    Raises ``ValueError`` naming the offending provider on any violation.
    """
    seen: set[str] = set()
    form_count = 0
    for provider in providers:
        name = provider.name
        if not _PROVIDER_NAME_RE.fullmatch(name):
            raise ValueError(f"login provider name is not valid: {name!r}")
        if name in _RESERVED_PROVIDER_NAMES:
            raise ValueError(f"login provider name {name!r} is reserved by Keystone")
        if name == "google" and not isinstance(provider, GoogleLoginProvider):
            raise ValueError(
                "login provider name 'google' is reserved for the built-in Google provider"
            )
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
            for field in provider.form_fields():
                if not _FORM_FIELD_NAME_RE.fullmatch(field.name):
                    raise ValueError(
                        f"login provider {name!r} has a form field with an unsafe "
                        f"name: {field.name!r}"
                    )
                if field.input_type not in _VALID_FORM_FIELD_INPUT_TYPES:
                    raise ValueError(
                        f"login provider {name!r} has a form field {field.name!r} with "
                        f"an unrecognised input_type: {field.input_type!r}"
                    )
        else:
            raise ValueError(f"login provider {name!r} has an unknown kind: {provider.kind!r}")

    if form_count > 1:
        raise ValueError("at most one form-kind login provider is allowed")
