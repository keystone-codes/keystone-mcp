"""Load sign-in providers from a YAML configuration file."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml

from keystone_mcp.config import ConfigError, DeploymentProfile

_PROVIDER_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_SECRET_ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
_FORBIDDEN_SECRET_KEYS = frozenset({"client_secret", "secret", "password"})
_VALID_PROVIDER_TYPES = frozenset({"oidc", "google", "api_key"})

_TOP_LEVEL_KEYS = frozenset({"version", "providers"})
_OIDC_KEYS = frozenset(
    {
        "name",
        "type",
        "title",
        "issuer",
        "client_id",
        "client_secret_env",
        "allowed_domains",
        "scopes",
        "hosted_domain",
        "email_claim",
        "require_email_verified",
        "groups_claim",
        "extra_authorize_params",
        "additional_issuers",
        "token_auth_method",
    }
)
_GOOGLE_KEYS = frozenset(
    {"name", "type", "title", "client_id", "client_secret_env", "allowed_domain"}
)
_API_KEY_KEYS = frozenset({"name", "type", "title"})


@dataclass(frozen=True, slots=True)
class LoginProviderEntry:
    name: str
    type: Literal["oidc", "google", "api_key"]
    title: str
    client_id: str = ""
    client_secret: str = ""
    issuer: str = ""
    allowed_domains: tuple[str, ...] = ()
    allowed_domain: str = ""
    scopes: tuple[str, ...] = ("openid", "email")
    hosted_domain: str | None = None
    email_claim: str = "email"
    require_email_verified: bool = True
    groups_claim: str | None = None
    extra_authorize_params: Mapping[str, str] | None = None
    additional_issuers: tuple[str, ...] = ()
    token_auth_method: Literal["client_secret_basic", "client_secret_post"] | None = None


def _prefix(path: str) -> str:
    return f"KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: {path}"


def _check_unknown_keys(
    data: Mapping[str, Any],
    allowed: frozenset[str],
    *,
    path: str,
) -> None:
    for key in data:
        if key not in allowed:
            if key in _FORBIDDEN_SECRET_KEYS:
                raise ConfigError(
                    f"{_prefix(path)}: secrets must not be stored in the file; "
                    "use client_secret_env with the name of an environment variable"
                )
            raise ConfigError(f"{_prefix(path)}: unknown key {key!r}")


def _require_str(data: Mapping[str, Any], key: str, *, path: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{_prefix(path)}.{key}: must be a non-empty string")
    return value.strip()


def _loopback_http_issuer_allowed(issuer: str) -> bool:
    parsed = urlparse(issuer)
    if parsed.scheme != "http":
        return False
    host = (parsed.hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


def _parse_provider(
    raw: Any,
    index: int,
    *,
    deployment_profile: DeploymentProfile,
    environ: Mapping[str, str],
) -> LoginProviderEntry:
    path = f"providers[{index}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{_prefix(path)}: must be a mapping")

    provider_type_raw = raw.get("type")
    if not isinstance(provider_type_raw, str):
        raise ConfigError(f"{_prefix(path)}.type: must be a string")
    provider_type = provider_type_raw.strip().lower()
    if provider_type not in _VALID_PROVIDER_TYPES:
        raise ConfigError(
            f"{_prefix(path)}.type: must be one of {sorted(_VALID_PROVIDER_TYPES)}; "
            f"got {provider_type_raw!r}"
        )

    if provider_type == "oidc":
        _check_unknown_keys(raw, _OIDC_KEYS, path=path)
    elif provider_type == "google":
        _check_unknown_keys(raw, _GOOGLE_KEYS, path=path)
    else:
        _check_unknown_keys(raw, _API_KEY_KEYS, path=path)

    name = _require_str(raw, "name", path=path)
    if not _PROVIDER_NAME_RE.fullmatch(name):
        raise ConfigError(f"{_prefix(path)}.name: invalid provider name {name!r}")

    title_raw = raw.get("title")
    if title_raw is None:
        title = name[:1].upper() + name[1:]
    else:
        title = _require_str(raw, "title", path=path)

    if provider_type == "api_key":
        return LoginProviderEntry(name=name, type="api_key", title=title)

    client_id = _require_str(raw, "client_id", path=path)
    secret_env = _require_str(raw, "client_secret_env", path=path)
    if not _SECRET_ENV_RE.fullmatch(secret_env):
        raise ConfigError(f"{_prefix(path)}.client_secret_env: must match ^[A-Z_][A-Z0-9_]*$")
    secret_value = environ.get(secret_env, "").strip()
    if not secret_value:
        raise ConfigError(
            f"{_prefix(path)}.client_secret_env: environment variable "
            f"{secret_env!r} is missing or empty"
        )

    if provider_type == "google":
        allowed_domain = ""
        if "allowed_domain" in raw:
            val = raw["allowed_domain"]
            if not isinstance(val, str):
                raise ConfigError(f"{_prefix(path)}.allowed_domain: must be a string")
            allowed_domain = val.strip().lower().lstrip("@")
        return LoginProviderEntry(
            name=name,
            type="google",
            title=title,
            client_id=client_id,
            client_secret=secret_value,
            allowed_domain=allowed_domain,
        )

    issuer = _require_str(raw, "issuer", path=path)
    parsed = urlparse(issuer)
    if parsed.scheme == "https":
        pass
    elif _loopback_http_issuer_allowed(issuer):
        if deployment_profile != "local":
            raise ConfigError(
                f"{_prefix(path)}.issuer: http:// loopback issuers are allowed only "
                "when KEYSTONE_MCP_DEPLOYMENT_PROFILE=local"
            )
    else:
        raise ConfigError(
            f"{_prefix(path)}.issuer: must be https:// (or http:// on loopback in local profile)"
        )

    allowed_domains: tuple[str, ...] = ()
    if "allowed_domains" in raw:
        raw_domains = raw["allowed_domains"]
        if not isinstance(raw_domains, list) or not raw_domains:
            raise ConfigError(f"{_prefix(path)}.allowed_domains: must be a non-empty list")
        domains: list[str] = []
        for i, item in enumerate(raw_domains):
            if not isinstance(item, str) or not item.strip():
                raise ConfigError(
                    f"{_prefix(path)}.allowed_domains[{i}]: must be a non-empty string"
                )
            domains.append(item.strip().lower().lstrip("@"))
        allowed_domains = tuple(domains)

    scopes: tuple[str, ...] = ("openid", "email")
    if "scopes" in raw:
        raw_scopes = raw["scopes"]
        if not isinstance(raw_scopes, list) or not raw_scopes:
            raise ConfigError(f"{_prefix(path)}.scopes: must be a non-empty list")
        scopes = tuple(str(s).strip() for s in raw_scopes if str(s).strip())

    hosted_domain: str | None = None
    if "hosted_domain" in raw:
        hd = raw["hosted_domain"]
        if not isinstance(hd, str) or not hd.strip():
            raise ConfigError(f"{_prefix(path)}.hosted_domain: must be a non-empty string")
        hosted_domain = hd.strip().lower().lstrip("@")

    email_claim = "email"
    if "email_claim" in raw:
        email_claim = _require_str(raw, "email_claim", path=path)

    require_email_verified = True
    if "require_email_verified" in raw:
        val = raw["require_email_verified"]
        if not isinstance(val, bool):
            raise ConfigError(f"{_prefix(path)}.require_email_verified: must be a boolean")
        require_email_verified = val

    groups_claim: str | None = None
    if "groups_claim" in raw:
        groups_claim = _require_str(raw, "groups_claim", path=path)

    extra_authorize_params: dict[str, str] | None = None
    if "extra_authorize_params" in raw:
        raw_extra = raw["extra_authorize_params"]
        if not isinstance(raw_extra, dict):
            raise ConfigError(f"{_prefix(path)}.extra_authorize_params: must be a mapping")
        extra_authorize_params = {str(k): str(v) for k, v in raw_extra.items()}

    additional_issuers: tuple[str, ...] = ()
    if "additional_issuers" in raw:
        raw_issuers = raw["additional_issuers"]
        if not isinstance(raw_issuers, list):
            raise ConfigError(f"{_prefix(path)}.additional_issuers: must be a list")
        additional_issuers = tuple(str(i).strip() for i in raw_issuers if str(i).strip())

    token_auth_method: Literal["client_secret_basic", "client_secret_post"] | None = None
    if "token_auth_method" in raw:
        tam = _require_str(raw, "token_auth_method", path=path)
        if tam not in ("client_secret_basic", "client_secret_post"):
            raise ConfigError(
                f"{_prefix(path)}.token_auth_method: must be client_secret_basic or "
                "client_secret_post"
            )
        token_auth_method = tam  # type: ignore[assignment]

    return LoginProviderEntry(
        name=name,
        type="oidc",
        title=title,
        client_id=client_id,
        client_secret=secret_value,
        issuer=issuer,
        allowed_domains=allowed_domains,
        scopes=scopes,
        hosted_domain=hosted_domain,
        email_claim=email_claim,
        require_email_verified=require_email_verified,
        groups_claim=groups_claim,
        extra_authorize_params=extra_authorize_params,
        additional_issuers=additional_issuers,
        token_auth_method=token_auth_method,
    )


def load_login_providers_file(
    path: str,
    *,
    deployment_profile: DeploymentProfile,
    environ: Mapping[str, str] | None = None,
) -> list[LoginProviderEntry]:
    """Parse and validate a login providers YAML file (no network I/O)."""
    env = os.environ if environ is None else environ
    file_path = Path(path.strip())
    if not file_path.is_file():
        raise ConfigError(f"KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: file not found: {path}")

    try:
        raw_text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: cannot read file: {path}") from exc

    try:
        document = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: invalid YAML: {exc}") from exc

    if not isinstance(document, dict):
        raise ConfigError("KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: root must be a mapping")

    _check_unknown_keys(document, _TOP_LEVEL_KEYS, path="root")

    version = document.get("version")
    if version != 1:
        raise ConfigError(f"KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: version must be 1; got {version!r}")

    providers_raw = document.get("providers")
    if not isinstance(providers_raw, list) or not providers_raw:
        raise ConfigError("KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: providers must be a non-empty list")

    entries = [
        _parse_provider(item, index, deployment_profile=deployment_profile, environ=env)
        for index, item in enumerate(providers_raw)
    ]

    seen: set[str] = set()
    api_key_count = 0
    for entry in entries:
        if entry.name in seen:
            raise ConfigError(
                f"KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: duplicate provider name {entry.name!r}"
            )
        seen.add(entry.name)
        if entry.type == "api_key":
            api_key_count += 1
    if api_key_count > 1:
        raise ConfigError("KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: at most one api_key provider")

    return entries
