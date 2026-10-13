"""Load sign-in providers from a YAML configuration file."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from keystone_mcp.config import ConfigError, DeploymentProfile
from keystone_mcp.plugins import LoginProviderConfig

_PROVIDER_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_FORBIDDEN_SECRET_KEYS = frozenset({"client_secret", "secret", "password"})
_TOP_LEVEL_KEYS = frozenset({"version", "providers"})
_ENTRY_KEYS = frozenset({"name", "type", "title"})


def _prefix(path: str) -> str:
    return f"KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: {path}"


def _check_forbidden_secrets(data: Mapping[str, Any], *, path: str) -> None:
    for key, value in data.items():
        if key in _FORBIDDEN_SECRET_KEYS:
            raise ConfigError(
                f"{_prefix(path)}: secrets must not be stored in the file; "
                "use client_secret_env with the name of an environment variable"
            )
        if isinstance(value, dict):
            _check_forbidden_secrets(value, path=f"{path}.{key}")


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


def _entry_options(raw: Mapping[str, Any]) -> dict[str, Any]:
    options: dict[str, Any] = {}
    for key, value in raw.items():
        if key in _ENTRY_KEYS:
            continue
        options[key] = value
    return options


def _parse_provider(
    raw: Any,
    index: int,
) -> LoginProviderConfig:
    path = f"providers[{index}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{_prefix(path)}: must be a mapping")

    _check_forbidden_secrets(raw, path=path)

    provider_type = _require_str(raw, "type", path=path).lower()
    name = _require_str(raw, "name", path=path)
    if not _PROVIDER_NAME_RE.fullmatch(name):
        raise ConfigError(f"{_prefix(path)}.name: invalid provider name {name!r}")

    title_raw = raw.get("title")
    if title_raw is None:
        title: str | None = name[:1].upper() + name[1:]
    else:
        title = _require_str(raw, "title", path=path)

    return LoginProviderConfig(
        name=name,
        type=provider_type,
        title=title,
        options=_entry_options(raw),
    )


def load_login_providers_file(
    path: str,
    *,
    deployment_profile: DeploymentProfile,
    environ: Mapping[str, str] | None = None,
) -> list[LoginProviderConfig]:
    """Parse and validate a login providers YAML file (no network I/O)."""
    _ = deployment_profile  # reserved for callers; OIDC rules run at factory time
    _ = os.environ if environ is None else environ
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
        msg = "KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: invalid YAML"
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            msg = f"{msg} at line {mark.line + 1}"
        raise ConfigError(msg) from None

    if not isinstance(document, dict):
        raise ConfigError("KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: root must be a mapping")

    _check_unknown_keys(document, _TOP_LEVEL_KEYS, path="root")

    version = document.get("version")
    if version != 1:
        raise ConfigError(f"KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: version must be 1; got {version!r}")

    providers_raw = document.get("providers")
    if not isinstance(providers_raw, list) or not providers_raw:
        raise ConfigError("KEYSTONE_MCP_LOGIN_PROVIDERS_PATH: providers must be a non-empty list")

    entries = [_parse_provider(item, index) for index, item in enumerate(providers_raw)]

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
