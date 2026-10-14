"""Confirmation flow and summary helpers for ``users_delete``."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import TYPE_CHECKING, Any

from redis.exceptions import RedisError

from keystone_mcp.adapters.guards import resolve_admin_call
from keystone_mcp.auth.oauth_store import OAuthStore, _subject_key
from keystone_mcp.observability.subject import hash_subject
from keystone_mcp.user_directory.protocol import (
    ApiKeyDirectory,
    UserDirectory,
)
from keystone_mcp.user_directory.util import normalize_email

if TYPE_CHECKING:
    from keystone_mcp.auth.login_pending_store import LoginPendingStore
    from keystone_mcp.rbac.management import ManagementSource
    from keystone_mcp.router.context import RouteContext
    from keystone_mcp.router.route import Route

_CONFIRM_NAMESPACE = "users_delete_confirm"
_CONFIRM_TTL_SECONDS = 300
_INVALID_CONFIRMATION = (
    "confirmation code is invalid or expired; call users_delete without it to get a new one"
)


def _email_digest(email: str) -> str:
    return hashlib.sha256(normalize_email(email).encode("utf-8")).hexdigest()


def _confirmation_key(code: str) -> str:
    return hashlib.sha256(code.strip().encode("utf-8")).hexdigest()


def _issue_confirmation_code() -> str:
    return base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")


async def person_summary(
    directory: UserDirectory,
    oauth_store: OAuthStore | None,
    *,
    email: str,
) -> dict[str, Any]:
    normalized = normalize_email(email)
    resolved = await directory.resolve_user(normalized)
    if not resolved.exists:
        from keystone_mcp.user_directory.errors import UserNotFoundError

        raise UserNotFoundError(normalized)
    roles = list(resolved.roles)
    api_keys_total = 0
    api_keys_active = 0
    if isinstance(directory, ApiKeyDirectory):
        keys = await directory.list_api_keys(subject=normalized, include_revoked=True)
        api_keys_total = len(keys)
        api_keys_active = sum(1 for key in keys if key.revoked_at is None)
    references = 0
    store = getattr(directory, "_store", None)
    if store is not None and hasattr(store, "count_person_references"):
        references = await store.count_person_references(normalized)
    open_sessions: int | None = None
    if oauth_store is not None:
        try:
            access, refresh = await oauth_store.subject_tokens(normalized)
            open_sessions = len(access) + len(refresh)
        except (RedisError, OSError, AttributeError, TypeError):
            try:
                redis = getattr(oauth_store, "redis", None) or getattr(oauth_store, "_redis", None)
                prefix = getattr(oauth_store, "_prefix", "km:oauth:")
                if redis is not None:
                    idx_key = f"{prefix}subject:{_subject_key(normalized)}"
                    open_sessions = int(await redis.scard(idx_key))
            except (RedisError, OSError, AttributeError):
                open_sessions = None
    return {
        "roles": roles,
        "api_keys_active": api_keys_active,
        "api_keys_total": api_keys_total,
        "open_sessions": open_sessions,
        "references": references,
    }


async def check_delete_preconditions(
    route: Route,
    ctx: RouteContext,
    *,
    directory: UserDirectory,
    management_source: ManagementSource | None,
    target_email: str,
) -> tuple[str | None, frozenset[str]]:
    """Return ``(error_code, target_roles)``; code is set when the delete must be refused."""
    actor = normalize_email(ctx.verified_identity.subject)
    target = normalize_email(target_email)
    if actor == target:
        return "self_admin_mutation_forbidden", frozenset()
    admin_call = await resolve_admin_call(
        route,
        ctx,
        directory=directory,
        management_source=management_source,
        target_subject=target,
    )
    if isinstance(admin_call, dict):
        code = str(admin_call.get("code", "service_unavailable"))
        return code, frozenset()
    if management_source is not None and admin_call.view.policies:
        if not admin_call.view.is_full_administrator(admin_call.actor_roles):
            return "forbidden", admin_call.target_roles
        people = await directory.list_users(is_blocked=False)
        if admin_call.view.is_full_administrator(admin_call.target_roles):
            full_count = sum(
                1 for person in people if admin_call.view.is_full_administrator(person.roles)
            )
            if full_count <= 1:
                return "last_administrator", admin_call.target_roles
    elif management_source is not None:
        if not admin_call.view.is_full_administrator(admin_call.actor_roles):
            return "forbidden", admin_call.target_roles
    return None, admin_call.target_roles


async def store_confirmation(
    pending_store: LoginPendingStore,
    *,
    code: str,
    actor_email: str,
    target_email: str,
    mode: str,
) -> None:
    payload = json.dumps(
        {
            "actor": _email_digest(actor_email),
            "email": _email_digest(target_email),
            "mode": mode,
        },
        separators=(",", ":"),
    )
    await pending_store.put(
        _CONFIRM_NAMESPACE,
        _confirmation_key(code),
        payload,
        _CONFIRM_TTL_SECONDS,
    )


async def consume_confirmation(
    pending_store: LoginPendingStore,
    *,
    code: str,
    actor_email: str,
    target_email: str,
    mode: str,
) -> bool:
    raw = await pending_store.consume(_CONFIRM_NAMESPACE, _confirmation_key(code))
    if raw is None:
        return False
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return False
    return (
        data.get("actor") == _email_digest(actor_email)
        and data.get("email") == _email_digest(target_email)
        and data.get("mode") == mode
    )


def directory_supports_delete(directory: UserDirectory) -> bool:
    if "delete" not in directory.capabilities:
        return False
    return callable(getattr(directory, "delete_user", None))


def build_pseudonym(email: str, *, salt: str) -> str:
    pseudonym = hash_subject(email, salt=salt)
    assert pseudonym is not None
    return pseudonym


__all__ = [
    "_CONFIRM_TTL_SECONDS",
    "_INVALID_CONFIRMATION",
    "_issue_confirmation_code",
    "build_pseudonym",
    "check_delete_preconditions",
    "consume_confirmation",
    "directory_supports_delete",
    "person_summary",
    "store_confirmation",
]
