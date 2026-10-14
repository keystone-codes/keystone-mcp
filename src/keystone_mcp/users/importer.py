"""Reads user records from an external users directory, for ``users import``.

The external directory is the legacy HTTP-based service this project used to
run as a separate process (see ``docs/users.md`` after the users CLI landed, and the contract
from the HTTP users API spec: ``GET /v1/users`` with an
``is_blocked`` filter, bearer auth, ``{"users": [...], "total": N}``). This
module only reads from that service; writing the imported records into the
built-in directory is :func:`keystone_mcp.users.service.upsert_imported_user`.
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import urlparse

import httpx

from keystone_mcp.users.emails import normalize_email
from keystone_mcp.users.records import ImportedUser


class ImportSourceError(RuntimeError):
    """The external users directory could not be read, or answered nonsense.

    Never carries the source's response body or the bearer token: both may
    contain secrets, and this message is printed to stderr as-is.
    """


def _parse_datetime(value: object, *, index: int) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ImportSourceError(f"malformed user record at index {index}")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ImportSourceError(f"malformed user record at index {index}") from exc


def _parse_user(raw: object, *, index: int) -> ImportedUser:
    if not isinstance(raw, dict):
        raise ImportSourceError(f"malformed user record at index {index}")

    email = raw.get("email")
    full_name = raw.get("full_name")
    roles = raw.get("roles")
    is_blocked = raw.get("is_blocked")
    note = raw.get("note")
    created_by = raw.get("created_by")

    if (
        not isinstance(email, str)
        or not email.strip()
        or not isinstance(full_name, str)
        or not isinstance(roles, list)
        or not all(isinstance(role, str) for role in roles)
        or not isinstance(is_blocked, bool)
        or (note is not None and not isinstance(note, str))
        or (created_by is not None and not isinstance(created_by, str))
    ):
        raise ImportSourceError(f"malformed user record at index {index}")

    return ImportedUser(
        email=normalize_email(email),
        full_name=full_name,
        roles=tuple(roles),
        is_blocked=is_blocked,
        note=note,
        created_by=created_by,
        created_at=_parse_datetime(raw.get("created_at"), index=index),
        updated_at=_parse_datetime(raw.get("updated_at"), index=index),
    )


def _fetch_page(client: httpx.Client, *, is_blocked: bool) -> list[ImportedUser]:
    try:
        response = client.get("/v1/users", params={"is_blocked": "true" if is_blocked else "false"})
    except httpx.HTTPError as exc:
        raise ImportSourceError(f"source is unreachable: {type(exc).__name__}") from exc

    if not 200 <= response.status_code < 300:
        code: str | None = None
        try:
            body = response.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            raw_code = body.get("code")
            if isinstance(raw_code, str):
                code = raw_code
        suffix = f" ({code})" if code else ""
        raise ImportSourceError(f"source returned HTTP {response.status_code}{suffix}")

    try:
        body = response.json()
    except ValueError as exc:
        raise ImportSourceError("source returned a malformed response body") from exc

    raw_users = body.get("users") if isinstance(body, dict) else None
    if not isinstance(raw_users, list):
        raise ImportSourceError("source response is missing a 'users' list")

    return [_parse_user(raw_user, index=index) for index, raw_user in enumerate(raw_users)]


def fetch_source_users(
    base_url: str,
    token: str,
    *,
    timeout_seconds: float = 10.0,
    transport: httpx.BaseTransport | None = None,
) -> list[ImportedUser]:
    """Read every user from an external users directory.

    Issues two requests — ``is_blocked=false`` then ``is_blocked=true`` — no
    other filters. When the same email appears in both responses (it should
    not, but the source is someone else's code), the later one wins: the
    blocked page is fetched second, so a user who is blocked is reported as
    blocked even if a stale unblocked row also came back.
    """
    scheme = urlparse(base_url.strip()).scheme.lower()
    if scheme not in {"http", "https"}:
        raise ImportSourceError(f"source URL must start with http:// or https://: {base_url!r}")

    users_by_email: dict[str, ImportedUser] = {}
    with httpx.Client(
        base_url=base_url.rstrip("/"),
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout_seconds,
        transport=transport,
        follow_redirects=False,
    ) as client:
        for is_blocked in (False, True):
            for user in _fetch_page(client, is_blocked=is_blocked):
                users_by_email[user.email] = user

    return list(users_by_email.values())
