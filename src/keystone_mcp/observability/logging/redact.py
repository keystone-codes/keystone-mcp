"""Redact secrets and PII from log payloads."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

_API_KEY_RE = re.compile(r"\bksk_[0-9a-f]{12}_[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")
_KEYSTONE_TOKEN_RE = re.compile(r"\bkm_(?:at|rt)_[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])")


def _mask_api_key(match: re.Match[str]) -> str:
    value = match.group(0)
    key_id = value[4:16]
    return f"ksk_{key_id}_***"


def _mask_keystone_token(match: re.Match[str]) -> str:
    value = match.group(0)
    if value.startswith("km_at_"):
        return "km_at_***"
    return "km_rt_***"


_BEARER_RE = re.compile(
    r"\bBearer\s+(?!ksk_[0-9a-f]{12}_)[A-Za-z0-9._~+/=-]+(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)
#: A bare compact JWT (e.g. the X-Keystone-Identity assertion) — three
#: base64url segments, the header segment always starting with ``eyJ`` (the
#: base64 encoding of ``{"``). Catches a token logged outside a "Bearer "
#: prefix or a token=value pair, e.g. a raw header dump.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_TOKEN_KV_RE = re.compile(
    r"(?i)(token|secret|password|api[_-]?key|authorization)\s*[:=]\s*['\"]?"
    r"([^'\"\s,}]+)['\"]?"
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_REDIS_URL_RE = re.compile(r"\bredis(?:s)?://[^\s]+", re.IGNORECASE)
#: Bare third-party tokens often printed in diagnostics (GitHub, GitLab, Slack,
#: OpenAI, Anthropic, AWS access key id).
_WELL_KNOWN_TOKEN_RE = re.compile(
    r"\b("
    r"ghp_[A-Za-z0-9_\-]{20,}|"
    r"gho_[A-Za-z0-9_\-]{20,}|"
    r"ghu_[A-Za-z0-9_\-]{20,}|"
    r"ghs_[A-Za-z0-9_\-]{20,}|"
    r"ghr_[A-Za-z0-9_\-]{20,}|"
    r"github_pat_[A-Za-z0-9_\-]{20,}|"
    r"glpat-[A-Za-z0-9_\-]{20,}|"
    r"xox[abprs]-[A-Za-z0-9_\-]{20,}|"
    r"sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}|"
    r"AKIA[0-9A-Z]{16}"
    r")\b"
)
_REDACTED = "***REDACTED***"


def redact_string(value: str) -> str:
    if not value:
        return value
    out = _API_KEY_RE.sub(_mask_api_key, value)
    out = _KEYSTONE_TOKEN_RE.sub(_mask_keystone_token, out)
    out = _BEARER_RE.sub("Bearer ***REDACTED***", out)
    out = _REDIS_URL_RE.sub(_redact_redis_url, out)
    out = _EMAIL_RE.sub("***@***", out)
    out = _TOKEN_KV_RE.sub(lambda m: f"{m.group(1)}={_REDACTED}", out)
    out = _JWT_RE.sub(_REDACTED, out)
    out = _WELL_KNOWN_TOKEN_RE.sub(_REDACTED, out)
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
            # The signed identity assertion header -- a JWT, not a
            # secret by itself, but it carries roles, email and task_id for
            # whoever is named in it and should not sit in plain log storage.
            "x-keystone-identity",
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
