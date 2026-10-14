"""Build a JSON export of everything Keystone holds about one person."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from redis.exceptions import RedisError

from keystone_mcp.adapters.users_delete_support import build_pseudonym
from keystone_mcp.auth.oauth_store import OAuthStore, _subject_key
from keystone_mcp.user_directory.errors import UserNotFoundError
from keystone_mcp.user_directory.protocol import (
    ApiKeyDirectory,
    IdentityBindingDirectory,
    UserDirectory,
)
from keystone_mcp.user_directory.types import ApiKeyRecord, UserRecord, _iso_utc
from keystone_mcp.user_directory.util import normalize_email

if TYPE_CHECKING:
    from keystone_mcp.config import Settings

_EXPORT_FORMAT = "keystone-person-export/1"

_NOT_HELD_STATIC: tuple[str, ...] = (
    "upstream services keep their own data",
    "process logs contain no e-mail addresses",
    "database backups are the operator's",
)

_NOT_HELD_NO_API_KEYS = "the users directory does not report API keys"
_NOT_HELD_NO_IDENTITY_BINDING = "the users directory does not report identity binding"


def _export_record(record: UserRecord) -> dict[str, Any]:
    return {
        "full_name": record.full_name,
        "is_blocked": record.is_blocked,
        "note": record.note,
        "created_by": record.created_by,
        "created_at": _iso_utc(record.created_at),
        "updated_at": _iso_utc(record.updated_at),
        "roles": list(record.roles),
    }


def _export_api_key(key: ApiKeyRecord) -> dict[str, Any]:
    return {
        "key_id": key.key_id,
        "label": key.label,
        "created_at": _iso_utc(key.created_at),
        "expires_at": _iso_utc(key.expires_at) if key.expires_at is not None else None,
        "revoked_at": _iso_utc(key.revoked_at) if key.revoked_at is not None else None,
        "revoked_by": key.revoked_by,
    }


async def _find_user_record(directory: UserDirectory, email: str) -> UserRecord:
    normalized = normalize_email(email)
    resolved = await directory.resolve_user(normalized)
    if not resolved.exists:
        raise UserNotFoundError(normalized)
    rows = await directory.list_users(is_blocked=None, email_contains=normalized)
    for row in rows:
        if row.email == normalized:
            return row
    raise UserNotFoundError(normalized)


async def _count_open_sessions(oauth_store: OAuthStore | None, email: str) -> dict[str, Any]:
    if oauth_store is None:
        return {"open": None, "reason": "token store unavailable"}
    normalized = normalize_email(email)
    try:
        _access, refresh = await oauth_store.subject_tokens(normalized)
        # Subject index holds both access and refresh members; count refresh
        # tokens only — one refresh token represents one browser session.
        return {"open": len(refresh)}
    except (RedisError, OSError, AttributeError, TypeError):
        return {"open": None, "reason": "token store unavailable"}
    try:
        redis = getattr(oauth_store, "redis", None) or getattr(oauth_store, "_redis", None)
        prefix = getattr(oauth_store, "_prefix", "km:oauth:")
        if redis is not None:
            idx_key = f"{prefix}subject:{_subject_key(normalized)}"
            members = await redis.smembers(idx_key)
            if isinstance(members, (set, frozenset)):
                decoded = members
            else:
                decoded = {m.decode("utf-8") if isinstance(m, bytes) else str(m) for m in members}
            open_count = sum(1 for member in decoded if str(member).startswith("rt:"))
            return {"open": open_count}
    except (RedisError, OSError, AttributeError, TypeError):
        pass
    return {"open": None, "reason": "token store unavailable"}


async def _authored_records(directory: UserDirectory, email: str) -> dict[str, int] | None:
    store = getattr(directory, "_store", None)
    if store is None or not hasattr(store, "person_authored_records"):
        return None
    return await store.person_authored_records(email)


async def build_person_export(
    email: str,
    *,
    directory: UserDirectory,
    oauth_store: OAuthStore | None,
    settings: Settings,
) -> dict[str, Any]:
    normalized = normalize_email(email)
    record = await _find_user_record(directory, email)
    not_held = list(_NOT_HELD_STATIC)

    api_keys: list[dict[str, Any]] | None
    if "api_keys" in directory.capabilities and isinstance(directory, ApiKeyDirectory):
        keys = await directory.list_api_keys(subject=normalized, include_revoked=True)
        api_keys = [_export_api_key(key) for key in keys]
    else:
        api_keys = None
        not_held.append(_NOT_HELD_NO_API_KEYS)

    identity_binding: dict[str, Any] | None
    if "identity_binding" in directory.capabilities and isinstance(
        directory, IdentityBindingDirectory
    ):
        binding = await directory.get_identity_binding(normalized)
        if binding is None:
            identity_binding = None
        else:
            identity_binding = {
                "issuer": binding.issuer,
                "subject": binding.subject,
                "bound_at": _iso_utc(binding.bound_at),
            }
    else:
        identity_binding = None
        not_held.append(_NOT_HELD_NO_IDENTITY_BINDING)

    pseudonym = build_pseudonym(normalized, salt=settings.rbac_audit_subject_salt)
    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    return {
        "format": _EXPORT_FORMAT,
        "generated_at": generated_at,
        "email": normalized,
        "directory": {"backend": directory.name, "record": _export_record(record)},
        "identity_binding": identity_binding,
        "api_keys": api_keys,
        "authored_records": await _authored_records(directory, normalized),
        "sessions": await _count_open_sessions(oauth_store, normalized),
        "audit": {
            "pseudonym": pseudonym,
            "note": "audit events reference this person only by this pseudonym",
        },
        "not_held": not_held,
    }


__all__ = ["build_person_export"]
