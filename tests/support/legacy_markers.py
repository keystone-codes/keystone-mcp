"""Verbatim parsers from Keystone MCP v0.5.0 — do not edit."""

from __future__ import annotations

import json

from mcp.server.auth.provider import AuthorizationCode
from pydantic import ValidationError


def legacy_read_refresh_meta(raw: str | None) -> tuple[str, str | None, bool]:
    if raw is None:
        return "api_key", None, False
    try:
        data = json.loads(raw)
    except ValueError:
        data = None
    if isinstance(data, dict):
        auth_method = data.get("auth_method")
        if not isinstance(auth_method, str) or not auth_method:
            return "api_key", None, False
        resource = data.get("resource")
        if resource is not None and not isinstance(resource, str):
            resource = None
        if "interactive" in data:
            interactive = data["interactive"] is True
        else:
            interactive = auth_method == "google"
        return auth_method, resource, interactive
    auth_method = raw.strip()
    if not auth_method:
        return "api_key", None, False
    return auth_method, None, auth_method == "google"


def legacy_parse_auth_code_envelope(raw: str) -> tuple[AuthorizationCode, str, bool] | None:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict) and "code" in payload:
        try:
            code = AuthorizationCode.model_validate(payload["code"])
        except ValidationError:
            return None
        auth_method = str(payload.get("auth_method", "api_key")).strip() or "api_key"
        if "interactive" in payload:
            interactive = payload["interactive"] is True
        else:
            interactive = auth_method == "google"
        return code, auth_method, interactive
    try:
        return AuthorizationCode.model_validate_json(raw), "api_key", False
    except ValidationError:
        return None
