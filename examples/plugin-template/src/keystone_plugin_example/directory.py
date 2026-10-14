"""Read-only users directory backed by a YAML file."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from keystone_mcp.plugins import PluginContext
from keystone_mcp.user_directory import UserDirectoryBase, normalize_email
from keystone_mcp.user_directory.types import UserRecord, UserResolveResult

_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


class StaticFileUserDirectory(UserDirectoryBase):
    """Read-only directory that loads people from a YAML list."""

    def __init__(self, people: list[dict[str, Any]]) -> None:
        self._users: dict[str, UserRecord] = {}
        for row in people:
            email = normalize_email(str(row["email"]))
            roles = tuple(str(r) for r in row.get("roles") or ())
            self._users[email] = UserRecord(
                email=email,
                full_name=str(row.get("full_name") or email),
                roles=roles,
                is_blocked=bool(row.get("blocked", False)),
                created_at=_EPOCH,
                updated_at=_EPOCH,
                created_by=None,
                note=None,
            )

    @property
    def name(self) -> str:
        return "static-file"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset()

    async def resolve_user(self, subject: str) -> UserResolveResult:
        email = normalize_email(subject)
        record = self._users.get(email)
        if record is None:
            return UserResolveResult(exists=False, roles=(), is_blocked=False)
        return UserResolveResult(
            exists=True,
            roles=record.roles,
            is_blocked=record.is_blocked,
        )

    async def list_users(
        self,
        *,
        is_blocked: bool | None = False,
        role: str | None = None,
        email_contains: str | None = None,
    ) -> list[UserRecord]:
        needle = (email_contains or "").strip().lower()
        role_name = role.strip() if role else None
        records: list[UserRecord] = []
        for record in sorted(self._users.values(), key=lambda item: item.email):
            if is_blocked is not None and record.is_blocked != is_blocked:
                continue
            if role_name is not None and role_name not in record.roles:
                continue
            if needle and needle not in record.email:
                continue
            records.append(record)
        return records

    async def ping(self) -> None:
        return None

    async def aclose(self) -> None:
        return None


def create_directory(context: PluginContext, options: Mapping[str, Any]) -> StaticFileUserDirectory:
    path_raw = options.get("path")
    if not path_raw or not str(path_raw).strip():
        raise ValueError("options.path must point at a YAML file listing people")
    path = Path(str(path_raw))
    if not path.is_file():
        raise ValueError(f"options.path does not exist or is not a file: {path}")
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("people file must contain a YAML list of user objects")
    return StaticFileUserDirectory(payload)
