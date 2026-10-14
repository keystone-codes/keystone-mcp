"""Build and validate the configured list of ``LoginProvider`` instances."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Sequence

import httpx

from keystone_mcp.config import ConfigError, Settings
from keystone_mcp.login.api_key import ApiKeyLoginProvider
from keystone_mcp.login.config import load_login_providers_file
from keystone_mcp.login.oidc import OidcLoginProvider, is_builtin_google_provider
from keystone_mcp.login.protocol import FormLoginProvider, LoginProvider, RedirectLoginProvider
from keystone_mcp.plugins import (
    LOGIN_PROVIDERS_GROUP,
    LoginProviderConfig,
    LoginProviderFactory,
    build_plugin_context,
    discover,
    entry_point_label,
    load_factory,
)
from keystone_mcp.user_directory.protocol import UserDirectoryResolver

logger = logging.getLogger(__name__)

_PROVIDER_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_RESERVED_PROVIDER_NAMES = frozenset({"redirect-not-allowed"})
_FORM_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
_VALID_FORM_FIELD_INPUT_TYPES = frozenset({"email", "password", "text"})


def _invoke_login_factory(
    factory: LoginProviderFactory,
    config: LoginProviderConfig,
    context,
) -> LoginProvider:
    try:
        return factory(config, context)
    except ValueError as exc:
        raise ConfigError(f"login provider {config.name!r}: {exc}") from exc


def _build_one(
    config: LoginProviderConfig,
    *,
    settings: Settings,
    resolver: UserDirectoryResolver | None,
    http_client_factory: Callable[[], httpx.AsyncClient] | None,
) -> LoginProvider:
    factory_obj = load_factory(LOGIN_PROVIDERS_GROUP, config.type)
    if not callable(factory_obj):
        raise ConfigError(
            f"{LOGIN_PROVIDERS_GROUP} '{config.type}' did not resolve to a callable factory"
        )
    context = build_plugin_context(settings, user_resolver=resolver)
    provider = _invoke_login_factory(factory_obj, config, context)
    if isinstance(provider, OidcLoginProvider) and http_client_factory is not None:
        provider = OidcLoginProvider(
            provider.config,
            http_client_factory=http_client_factory,
        )
    ep = discover(LOGIN_PROVIDERS_GROUP)[config.type]
    dist, version, _target = entry_point_label(ep)
    if provider.kind == "redirect":
        logger.info(
            "login provider %s: type %s from %s %s, callback %s/login/%s/callback",
            config.name,
            config.type,
            dist,
            version,
            settings.base_url.rstrip("/"),
            provider.name,
        )
    return provider


def _build_from_file(
    settings: Settings,
    *,
    resolver: UserDirectoryResolver | None,
    http_client_factory: Callable[[], httpx.AsyncClient] | None,
) -> list[LoginProvider]:
    entries = load_login_providers_file(
        settings.login_providers_path,
        deployment_profile=settings.deployment_profile,
    )
    return [
        _build_one(
            entry,
            settings=settings,
            resolver=resolver,
            http_client_factory=http_client_factory,
        )
        for entry in entries
    ]


def _legacy_google_enabled(settings: Settings) -> bool:
    return settings.google_login_enabled


def build_login_providers(
    settings: Settings,
    *,
    resolver: UserDirectoryResolver | None = None,
    http_client_factory: Callable[[], httpx.AsyncClient] | None = None,
) -> list[LoginProvider]:
    """Assemble the providers for the login page, in display order."""
    path = settings.login_providers_path.strip()
    if path:
        return _build_from_file(
            settings,
            resolver=resolver,
            http_client_factory=http_client_factory,
        )

    providers: list[LoginProvider] = []
    if _legacy_google_enabled(settings):
        config = LoginProviderConfig(
            name="google",
            type="google",
            title="Google",
            options={
                "client_id": settings.google_client_id,
                "client_secret_env": "KEYSTONE_MCP_GOOGLE_CLIENT_SECRET",
            },
        )
        providers.append(
            _build_one(
                config,
                settings=settings,
                resolver=resolver,
                http_client_factory=http_client_factory,
            )
        )
    if settings.api_key_login_enabled:
        config = LoginProviderConfig(
            name="api_key",
            type="api_key",
            title="API key",
            options={},
        )
        providers.append(
            _build_one(
                config,
                settings=settings,
                resolver=resolver,
                http_client_factory=http_client_factory,
            )
        )
    return providers


def login_providers_want_directory_resolver(providers: Sequence[LoginProvider]) -> bool:
    for provider in providers:
        if provider.name == "api_key" and isinstance(provider, ApiKeyLoginProvider):
            if provider.wants_directory_resolver:
                return True
    return False


def file_has_interactive_providers(settings: Settings) -> bool:
    """True when the providers file lists oidc or google sign-in."""
    path = settings.login_providers_path.strip()
    if not path:
        return False
    entries = load_login_providers_file(
        path,
        deployment_profile=settings.deployment_profile,
    )
    return any(entry.type in ("oidc", "google") for entry in entries)


def file_has_api_key_provider(settings: Settings) -> bool:
    """True when the providers file lists api_key sign-in."""
    path = settings.login_providers_path.strip()
    if not path:
        return False
    entries = load_login_providers_file(
        path,
        deployment_profile=settings.deployment_profile,
    )
    return any(entry.type == "api_key" for entry in entries)


def api_key_login_configured(settings: Settings) -> bool:
    """Whether api_key sign-in is configured (providers file or legacy env)."""
    if settings.login_providers_path.strip():
        return file_has_api_key_provider(settings)
    return settings.api_key_login_enabled


def check_login_providers_for_profile(
    settings: Settings, providers: Sequence[LoginProvider]
) -> None:
    """Refuse api_key next to an interactive provider in production."""
    if settings.deployment_profile != "production":
        return
    has_api_key = any(p.name == "api_key" for p in providers)
    has_interactive = any(getattr(p, "interactive", False) for p in providers)
    if has_api_key and has_interactive:
        raise ConfigError(
            "api_key sign-in for people is not available in the production profile "
            "when an interactive provider is configured; people sign in through the "
            "provider, machines use Bearer keys"
        )


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
