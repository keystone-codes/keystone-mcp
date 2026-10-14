"""Parse OIDC/Google provider options from a login providers file entry."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any, Literal
from urllib.parse import urlparse

from keystone_mcp.config import ConfigError, DeploymentProfile
from keystone_mcp.login.oidc import OidcProviderConfig, google_provider_config

_SECRET_ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


def _require_str(options: Mapping[str, Any], key: str, *, provider_name: str) -> str:
    value = options.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{provider_name}: {key} must be a non-empty string")
    return value.strip()


def _loopback_http_issuer_allowed(issuer: str) -> bool:
    parsed = urlparse(issuer)
    if parsed.scheme != "http":
        return False
    host = (parsed.hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


def parse_google_options(
    options: Mapping[str, Any],
    *,
    name: str,
    title: str,
    secret: Callable[[str], str],
) -> OidcProviderConfig:
    client_id = _require_str(options, "client_id", provider_name=name)
    secret_env = _require_str(options, "client_secret_env", provider_name=name)
    if not _SECRET_ENV_RE.fullmatch(secret_env):
        raise ValueError(f"{name}: client_secret_env must match ^[A-Z_][A-Z0-9_]*$")
    client_secret = secret(secret_env)
    allowed_domain = ""
    if "allowed_domain" in options:
        val = options["allowed_domain"]
        if not isinstance(val, str):
            raise ValueError(f"{name}: allowed_domain must be a string")
        allowed_domain = val.strip().lower().lstrip("@")
    return google_provider_config(
        client_id=client_id,
        client_secret=client_secret,
        allowed_domain=allowed_domain,
        name=name,
        title=title,
    )


def parse_oidc_options(
    options: Mapping[str, Any],
    *,
    name: str,
    title: str,
    deployment_profile: DeploymentProfile,
    secret: Callable[[str], str],
) -> OidcProviderConfig:
    client_id = _require_str(options, "client_id", provider_name=name)
    secret_env = _require_str(options, "client_secret_env", provider_name=name)
    if not _SECRET_ENV_RE.fullmatch(secret_env):
        raise ValueError(f"{name}: client_secret_env must match ^[A-Z_][A-Z0-9_]*$")
    client_secret = secret(secret_env)
    issuer = _require_str(options, "issuer", provider_name=name)
    parsed = urlparse(issuer)
    if parsed.scheme == "https":
        pass
    elif _loopback_http_issuer_allowed(issuer):
        if deployment_profile != "local":
            raise ConfigError(
                f"{name}: http:// loopback issuers are allowed only when "
                "KEYSTONE_MCP_DEPLOYMENT_PROFILE=local"
            )
    else:
        raise ValueError(
            f"{name}: issuer must be https:// (or http:// on loopback in local profile)"
        )

    allowed_domains: tuple[str, ...] = ()
    if "allowed_domains" in options:
        raw_domains = options["allowed_domains"]
        if not isinstance(raw_domains, list) or not raw_domains:
            raise ValueError(f"{name}: allowed_domains must be a non-empty list")
        domains: list[str] = []
        for i, item in enumerate(raw_domains):
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"{name}: allowed_domains[{i}] must be a non-empty string")
            domains.append(item.strip().lower().lstrip("@"))
        allowed_domains = tuple(domains)

    scopes: tuple[str, ...] = ("openid", "email")
    if "scopes" in options:
        raw_scopes = options["scopes"]
        if not isinstance(raw_scopes, list) or not raw_scopes:
            raise ValueError(f"{name}: scopes must be a non-empty list")
        scopes = tuple(str(s).strip() for s in raw_scopes if str(s).strip())

    hosted_domain: str | None = None
    if "hosted_domain" in options:
        hd = options["hosted_domain"]
        if not isinstance(hd, str) or not hd.strip():
            raise ValueError(f"{name}: hosted_domain must be a non-empty string")
        hosted_domain = hd.strip().lower().lstrip("@")

    email_claim = "email"
    if "email_claim" in options:
        email_claim = _require_str(options, "email_claim", provider_name=name)

    email_verified_claim_explicit = "email_verified_claim" in options
    email_verified_claim = "email_verified"
    if email_verified_claim_explicit:
        email_verified_claim = _require_str(options, "email_verified_claim", provider_name=name)

    require_email_verified = True
    if "require_email_verified" in options:
        val = options["require_email_verified"]
        if not isinstance(val, bool):
            raise ValueError(f"{name}: require_email_verified must be a boolean")
        require_email_verified = val

    if email_claim != "email" and require_email_verified and not email_verified_claim_explicit:
        raise ConfigError(
            f"{name}: email_claim is {email_claim!r} but require_email_verified checks "
            "'email_verified', which providers set for the 'email' claim only. Set "
            f"email_verified_claim to the claim that confirms {email_claim!r}, or set "
            "require_email_verified: false together with allowed_domains or hosted_domain."
        )

    if not require_email_verified and not allowed_domains and hosted_domain is None:
        raise ConfigError(
            f"{name}: require_email_verified is false but neither allowed_domains "
            "nor hosted_domain is set; the provider would accept any email signed "
            "by the IdP. Set allowed_domains or hosted_domain, or keep "
            "require_email_verified true."
        )

    groups_claim: str | None = None
    if "groups_claim" in options:
        groups_claim = _require_str(options, "groups_claim", provider_name=name)

    extra_authorize_params: dict[str, str] | None = None
    if "extra_authorize_params" in options:
        raw_extra = options["extra_authorize_params"]
        if not isinstance(raw_extra, dict):
            raise ValueError(f"{name}: extra_authorize_params must be a mapping")
        extra_authorize_params = {str(k): str(v) for k, v in raw_extra.items()}

    additional_issuers: tuple[str, ...] = ()
    if "additional_issuers" in options:
        raw_issuers = options["additional_issuers"]
        if not isinstance(raw_issuers, list):
            raise ValueError(f"{name}: additional_issuers must be a list")
        additional_issuers = tuple(str(i).strip() for i in raw_issuers if str(i).strip())

    token_auth_method: Literal["client_secret_basic", "client_secret_post"] | None = None
    if "token_auth_method" in options:
        tam = _require_str(options, "token_auth_method", provider_name=name)
        if tam not in ("client_secret_basic", "client_secret_post"):
            raise ValueError(
                f"{name}: token_auth_method must be client_secret_basic or client_secret_post"
            )
        token_auth_method = tam  # type: ignore[assignment]

    return OidcProviderConfig(
        name=name,
        title=title,
        client_id=client_id,
        client_secret=client_secret,
        issuer=issuer,
        allowed_domains=allowed_domains,
        scopes=scopes,
        hosted_domain=hosted_domain,
        email_claim=email_claim,
        email_verified_claim=email_verified_claim,
        require_email_verified=require_email_verified,
        groups_claim=groups_claim,
        extra_authorize_params=extra_authorize_params or {},
        additional_issuers=additional_issuers,
        token_auth_method=token_auth_method,
    )
