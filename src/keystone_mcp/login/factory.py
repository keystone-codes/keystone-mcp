"""Build and validate the configured list of ``LoginProvider`` instances.

Entry-point based discovery of third-party providers arrives with X09; for
now this assembles built-in providers from ``Settings`` or a providers file.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Sequence

import httpx

from keystone_mcp.auth.identity_provider import IdentityProvider
from keystone_mcp.config import Settings
from keystone_mcp.login.api_key import ApiKeyLoginProvider
from keystone_mcp.login.config import LoginProviderEntry, load_login_providers_file
from keystone_mcp.login.oidc import (
    OidcLoginProvider,
    OidcProviderConfig,
    google_provider_config,
    is_builtin_google_provider,
)
from keystone_mcp.login.protocol import FormLoginProvider, LoginProvider, RedirectLoginProvider

_PROVIDER_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")

# Provider names a deployment may never configure for a custom implementation.
#
# - "redirect-not-allowed" is the fixed route authorize() sends a refused
#   redirect_uri to (server.py registers GET /login/redirect-not-allowed
#   unconditionally); a provider claiming that name would collide with it.
# - "google" is reserved for the built-in Google OIDC preset: nothing else may
#   claim it, since RBAC's interactive-human check and _complete_login's
#   provider-name check both trust the *route* a sign-in came back on.
_RESERVED_PROVIDER_NAMES = frozenset({"redirect-not-allowed"})

_FORM_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
_VALID_FORM_FIELD_INPUT_TYPES = frozenset({"email", "password", "text"})


def _entry_to_oidc_config(entry: LoginProviderEntry) -> OidcProviderConfig:
    if entry.type == "google":
        return google_provider_config(
            client_id=entry.client_id,
            client_secret=entry.client_secret,
            allowed_domain=entry.allowed_domain,
            name=entry.name,
            title=entry.title,
        )
    return OidcProviderConfig(
        name=entry.name,
        title=entry.title,
        issuer=entry.issuer,
        client_id=entry.client_id,
        client_secret=entry.client_secret,
        scopes=entry.scopes,
        allowed_domains=entry.allowed_domains,
        hosted_domain=entry.hosted_domain,
        email_claim=entry.email_claim,
        require_email_verified=entry.require_email_verified,
        groups_claim=entry.groups_claim,
        extra_authorize_params=entry.extra_authorize_params or {},
        additional_issuers=entry.additional_issuers,
        token_auth_method=entry.token_auth_method,
    )


def _build_from_file(
    settings: Settings,
    *,
    identity_provider: IdentityProvider,
    http_client_factory: Callable[[], httpx.AsyncClient] | None,
) -> list[LoginProvider]:
    entries = load_login_providers_file(
        settings.login_providers_path,
        deployment_profile=settings.deployment_profile,
        environ=os.environ,
    )
    providers: list[LoginProvider] = []
    for entry in entries:
        if entry.type == "api_key":
            providers.append(ApiKeyLoginProvider(identity_provider))
        else:
            config = _entry_to_oidc_config(entry)
            providers.append(OidcLoginProvider(config, http_client_factory=http_client_factory))
    return providers


def _legacy_google_enabled(settings: Settings) -> bool:
    return settings.google_login_enabled


def build_login_providers(
    settings: Settings,
    *,
    identity_provider: IdentityProvider,
    http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
) -> list[LoginProvider]:
    """Assemble the providers for the login page, in display order."""
    path = settings.login_providers_path.strip()
    if path:
        return _build_from_file(
            settings,
            identity_provider=identity_provider,
            http_client_factory=http_client_factory,
        )

    providers: list[LoginProvider] = []
    if _legacy_google_enabled(settings):
        config = google_provider_config(
            client_id=settings.google_client_id,
            client_secret=settings.google_client_secret,
            allowed_domain=settings.google_allowed_domain,
        )
        providers.append(OidcLoginProvider(config, http_client_factory=http_client_factory))
    if settings.api_key_login_enabled:
        providers.append(ApiKeyLoginProvider(identity_provider))
    return providers


def file_has_interactive_providers(settings: Settings) -> bool:
    """True when the providers file lists oidc or google sign-in."""
    path = settings.login_providers_path.strip()
    if not path:
        return False
    entries = load_login_providers_file(
        path,
        deployment_profile=settings.deployment_profile,
        environ=os.environ,
    )
    return any(entry.type in ("oidc", "google") for entry in entries)


def validate_login_providers(providers: Sequence[LoginProvider]) -> None:
    """Check the configured provider set for the invariants Keystone relies on."""
    seen: set[str] = set()
    form_count = 0
    for provider in providers:
        name = provider.name
        if not _PROVIDER_NAME_RE.fullmatch(name):
            raise ValueError(f"login provider name is not valid: {name!r}")
        if name in _RESERVED_PROVIDER_NAMES:
            raise ValueError(f"login provider name {name!r} is reserved by Keystone")
        if name == "google" and not is_builtin_google_provider(provider):
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
