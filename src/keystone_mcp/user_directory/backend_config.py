"""Load optional YAML options for a users-directory plugin."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from keystone_mcp.config import ConfigError

_FORBIDDEN_SUBSTRINGS = (
    "secret",
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "credential",
)


def _is_forbidden_key(key: str) -> bool:
    lowered = key.lower()
    if lowered.endswith("_env"):
        return False
    return any(part in lowered for part in _FORBIDDEN_SUBSTRINGS)


def _check_forbidden(value: Any, *, path: str) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            key_str = str(key)
            if _is_forbidden_key(key_str):
                raise ConfigError(
                    f"{path}: secrets must not be stored in the file; use "
                    f"{key_str}_env and read it with context.secret()"
                )
            _check_forbidden(nested, path=f"{path}.{key_str}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _check_forbidden(item, path=f"{path}[{index}]")


def load_users_backend_config(path: str) -> dict[str, Any]:
    """Parse ``KEYSTONE_MCP_USERS_BACKEND_CONFIG`` as a YAML mapping."""
    file_path = Path(path.strip())
    if not file_path.is_file():
        raise ConfigError(f"KEYSTONE_MCP_USERS_BACKEND_CONFIG: file not found: {path}")
    try:
        raw_text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"KEYSTONE_MCP_USERS_BACKEND_CONFIG: cannot read file: {path}") from exc
    try:
        document = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        msg = "KEYSTONE_MCP_USERS_BACKEND_CONFIG: invalid YAML"
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            msg = f"{msg} at line {mark.line + 1}"
        raise ConfigError(msg) from None
    if not isinstance(document, dict):
        raise ConfigError("KEYSTONE_MCP_USERS_BACKEND_CONFIG: root must be a mapping")
    _check_forbidden(document, path="KEYSTONE_MCP_USERS_BACKEND_CONFIG")
    return document
