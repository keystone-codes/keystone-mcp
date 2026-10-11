"""Redact secrets and PII from log payloads."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+\b", re.IGNORECASE)
_TOKEN_KV_RE = re.compile(
    r"(?i)(token|secret|password|api[_-]?key|authorization)\s*[:=]\s*['\"]?"
    r"([^'\"\s,}]+)['\"]?"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_REDIS_URL_RE = re.compile(r"\bredis(?:s)?://[^\s]+", re.IGNORECASE)
_REDACTED = "***REDACTED***"


def redact_string(value: str) -> str:
    if not value:
        return value
    out = _BEARER_RE.sub("Bearer ***REDACTED***", value)
    out = _REDIS_URL_RE.sub(_redact_redis_url, out)
    out = _EMAIL_RE.sub("***@***", out)
    out = _TOKEN_KV_RE.sub(lambda m: f"{m.group(1)}={_REDACTED}", out)
    return out


def _redact_redis_url(match: re.Match[str]) -> str:
    return redact_url_credentials(match.group(0))


def redact_url_credentials(url: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return _REDACTED
    if not parsed.scheme:
        return redact_string(url)
    username = parsed.username
    password = parsed.password
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    userinfo = ""
    if username or password:
        userinfo = "***:***@"
    netloc = f"{userinfo}{host}{port}"
    query = _redact_query(parsed.query)
    fragment = _REDACTED if parsed.fragment else ""
    if not username and not password and query == parsed.query and not parsed.fragment:
        return url
    return urlunparse(
        (
            parsed.scheme,
            netloc,
            parsed.path,
            parsed.params,
            query,
            fragment,
        )
    )


def _redact_query(query: str) -> str:
    if not query:
        return query
    sensitive_names = frozenset(
        {"password", "token", "secret", "code", "state", "api_key", "client_secret"}
    )
    pairs = parse_qsl(query, keep_blank_values=True)
    redacted: list[tuple[str, str]] = []
    for key, value in pairs:
        key_lower = key.lower()
        if key_lower in sensitive_names or "token" in key_lower or "secret" in key_lower:
            redacted.append((key, _REDACTED))
        else:
            redacted.append((key, redact_string(value)))
    return urlencode(redacted)


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_string(value)
    if isinstance(value, dict):
        return redact_dict(value)
    if isinstance(value, (list, tuple)):
        return type(value)(redact_value(item) for item in value)
    return value


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    sensitive_keys = frozenset(
        {
            "authorization",
            "cookie",
            "set-cookie",
            "password",
            "secret",
            "token",
            "api_key",
            "api-key",
            "client_secret",
            "access_token",
            "refresh_token",
            "private_key",
            "credential",
            "api_token",
        }
    )
    out: dict[str, Any] = {}
    for key, value in data.items():
        key_lower = str(key).lower()
        if key_lower in sensitive_keys:
            out[key] = _REDACTED
        else:
            out[key] = redact_value(value)
    return out
