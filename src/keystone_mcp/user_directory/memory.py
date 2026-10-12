"""In-memory users directory for local development, tests, and plugin examples.

Implements the full read+admin protocol with the same administrator
invariants as the built-in database-backed directory
(:mod:`keystone_mcp.users.service`): the last active administrator cannot be
blocked or demoted, and nobody can mutate their own administrator access.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from keystone_mcp.user_directory.errors import (
    LastAdministratorError,
    SelfAdminMutationError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from keystone_mcp.user_directory.types import (
    MutationResult,
    ServiceAccountMutation,
    ServiceAccountRecord,
    UserRecord,
    UserResolveResult,
    is_valid_service_account_name,
    parse_service_subject,
    service_subject,
)
from keystone_mcp.user_directory.util import normalize_email
from keystone_mcp.users.errors import InvalidRoleError, InvalidUserFieldError
from keystone_mcp.users.roles import ROLE_ADMINISTRATOR, check_role_name

_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass
class _ServiceEntry:
    description: str | None
    roles: tuple[str, ...]
    is_blocked: bool
    created_by: str | None = None
    created_at: datetime = field(default_factory=lambda: _EPOCH)
    updated_at: datetime = field(default_factory=lambda: _EPOCH)


@dataclass
class _Entry:
    full_name: str
    roles: tuple[str, ...]
    is_blocked: bool
    note: str | None = None
    created_by: str | None = None
    created_at: datetime = field(default_factory=lambda: _EPOCH)
    updated_at: datetime = field(default_factory=lambda: _EPOCH)


@dataclass
class InMemoryUserDirectory:
    """Dev/test directory implementing the full ``UserDirectory`` protocol."""

    _users: dict[str, _Entry] = field(default_factory=dict)
    _services: dict[str, _ServiceEntry] = field(default_factory=dict)
    unavailable: bool = False

    @property
    def name(self) -> str:
        return "memory"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"admin", "service_accounts"})

    # ── Test-only seeding helpers (kept from the 0.4.0 backend) ────────────

    def seed(
        self,
        email: str,
        *,
        roles: tuple[str, ...] | list[str] = (),
        is_blocked: bool = False,
    ) -> None:
        normalized = normalize_email(email)
        existing = self._users.get(normalized)
        self._users[normalized] = _Entry(
            full_name=existing.full_name if existing else normalized,
            roles=tuple(roles),
            is_blocked=is_blocked,
            note=existing.note if existing else None,
            created_by=existing.created_by if existing else None,
            created_at=existing.created_at if existing else _EPOCH,
        )

    def block(self, email: str) -> None:
        normalized = normalize_email(email)
        if normalized not in self._users:
            raise KeyError(email)
        self._users[normalized].is_blocked = True

    def set_roles(self, email: str, roles: tuple[str, ...] | list[str]) -> None:
        normalized = normalize_email(email)
        if normalized not in self._users:
            raise KeyError(email)
        self._users[normalized].roles = tuple(roles)

    # ── UserDirectory ────────────────────────────────────────────────────

    async def resolve_user(self, subject: str) -> UserResolveResult:
        if self.unavailable:
            raise OSError("users directory unavailable")
        svc_name = parse_service_subject(subject.strip().lower())
        if svc_name is not None:
            entry = self._services.get(svc_name)
            if entry is None:
                return UserResolveResult(
                    exists=False, roles=(), is_blocked=False, subject_type="service"
                )
            return UserResolveResult(
                exists=True,
                roles=entry.roles,
                is_blocked=entry.is_blocked,
                subject_type="service",
            )
        normalized = normalize_email(subject)
        entry = self._users.get(normalized)
        if entry is None:
            return UserResolveResult(exists=False, roles=(), is_blocked=False)
        return UserResolveResult(exists=True, roles=entry.roles, is_blocked=entry.is_blocked)

    async def list_users(
        self,
        *,
        is_blocked: bool | None = False,
        role: str | None = None,
        email_contains: str | None = None,
    ) -> list[UserRecord]:
        role_name = check_role_name(role) if role else None
        records = []
        for email, entry in sorted(self._users.items()):
            if is_blocked is not None and entry.is_blocked != is_blocked:
                continue
            if role_name is not None and role_name not in entry.roles:
                continue
            if email_contains and normalize_email(email_contains) not in email:
                continue
            records.append(self._record(email, entry))
        return records

    async def ping(self) -> None:
        return None

    async def aclose(self) -> None:
        return None

    # ── UserDirectoryAdmin ───────────────────────────────────────────────

    def _active_administrators(self) -> set[str]:
        return {
            email
            for email, entry in self._users.items()
            if not entry.is_blocked and ROLE_ADMINISTRATOR in entry.roles
        }

    def _record(self, email: str, entry: _Entry) -> UserRecord:
        return UserRecord(
            email=email,
            full_name=entry.full_name,
            roles=tuple(sorted(entry.roles)),
            is_blocked=entry.is_blocked,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            created_by=entry.created_by,
            note=entry.note,
        )

    def _require(self, email: str) -> tuple[str, _Entry]:
        normalized = normalize_email(email)
        entry = self._users.get(normalized)
        if entry is None:
            raise UserNotFoundError(normalized)
        return normalized, entry

    async def create_user(
        self,
        *,
        email: str,
        full_name: str,
        roles: Sequence[str],
        note: str | None,
        actor: str,
    ) -> MutationResult:
        normalized = normalize_email(email)
        if normalized in self._users:
            raise UserAlreadyExistsError(normalized)
        role_list = tuple(dict.fromkeys(check_role_name(role) for role in roles))
        entry = _Entry(
            full_name=full_name,
            roles=role_list,
            is_blocked=False,
            note=note,
            created_by=normalize_email(actor),
        )
        self._users[normalized] = entry
        return MutationResult(user=self._record(normalized, entry), changed=True, created=True)

    async def update_user(
        self,
        *,
        email: str,
        full_name: str | None,
        note: str | None,
        actor: str,  # noqa: ARG002
    ) -> MutationResult:
        normalized, entry = self._require(email)
        changed = False
        if full_name is not None and entry.full_name != full_name:
            entry.full_name = full_name
            changed = True
        if note is not None and entry.note != note:
            entry.note = note
            changed = True
        return MutationResult(user=self._record(normalized, entry), changed=changed)

    async def set_blocked(self, *, email: str, blocked: bool, actor: str) -> MutationResult:
        normalized, entry = self._require(email)
        blocked_before = entry.is_blocked
        if entry.is_blocked == blocked:
            return MutationResult(
                user=self._record(normalized, entry), changed=False, blocked_before=blocked_before
            )
        if blocked and ROLE_ADMINISTRATOR in entry.roles:
            if normalize_email(actor) == normalized:
                raise SelfAdminMutationError("block")
            if self._active_administrators() <= {normalized}:
                raise LastAdministratorError()
        entry.is_blocked = blocked
        return MutationResult(
            user=self._record(normalized, entry), changed=True, blocked_before=blocked_before
        )

    async def replace_roles(
        self, *, email: str, roles: Sequence[str], actor: str
    ) -> MutationResult:
        normalized, entry = self._require(email)
        roles_before = tuple(sorted(entry.roles))
        next_roles = tuple(dict.fromkeys(check_role_name(role) for role in roles))
        if set(roles_before) == set(next_roles):
            return MutationResult(
                user=self._record(normalized, entry), changed=False, roles_before=roles_before
            )
        if ROLE_ADMINISTRATOR in entry.roles and ROLE_ADMINISTRATOR not in next_roles:
            if normalize_email(actor) == normalized:
                raise SelfAdminMutationError("revoke administrator")
            if self._active_administrators() <= {normalized}:
                raise LastAdministratorError()
        entry.roles = next_roles
        return MutationResult(
            user=self._record(normalized, entry), changed=True, roles_before=roles_before
        )

    async def grant_role(self, *, email: str, role: str, actor: str) -> MutationResult:  # noqa: ARG002
        normalized, entry = self._require(email)
        roles_before = tuple(sorted(entry.roles))
        role_name = check_role_name(role)
        if role_name in entry.roles:
            return MutationResult(
                user=self._record(normalized, entry), changed=False, roles_before=roles_before
            )
        entry.roles = (*entry.roles, role_name)
        return MutationResult(
            user=self._record(normalized, entry), changed=True, roles_before=roles_before
        )

    async def revoke_role(self, *, email: str, role: str, actor: str) -> MutationResult:
        normalized, entry = self._require(email)
        roles_before = tuple(sorted(entry.roles))
        role_name = check_role_name(role)
        if role_name not in entry.roles:
            return MutationResult(
                user=self._record(normalized, entry), changed=False, roles_before=roles_before
            )
        if role_name == ROLE_ADMINISTRATOR:
            if normalize_email(actor) == normalized:
                raise SelfAdminMutationError("revoke administrator")
            if self._active_administrators() <= {normalized}:
                raise LastAdministratorError()
        entry.roles = tuple(r for r in entry.roles if r != role_name)
        return MutationResult(
            user=self._record(normalized, entry), changed=True, roles_before=roles_before
        )

    def _service_record(self, name: str, entry: _ServiceEntry) -> ServiceAccountRecord:
        return ServiceAccountRecord(
            name=name,
            subject=service_subject(name),
            description=entry.description,
            roles=tuple(sorted(entry.roles)),
            is_blocked=entry.is_blocked,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            created_by=entry.created_by,
        )

    async def list_service_accounts(
        self,
        *,
        is_blocked: bool | None = False,
    ) -> list[ServiceAccountRecord]:
        records = []
        for name, entry in sorted(self._services.items()):
            if is_blocked is not None and entry.is_blocked != is_blocked:
                continue
            records.append(self._service_record(name, entry))
        return records

    async def create_service_account(
        self,
        *,
        name: str,
        description: str | None,
        roles: Sequence[str],
        actor: str,
    ) -> ServiceAccountMutation:
        if not is_valid_service_account_name(name):
            raise InvalidUserFieldError("name", "must match ^[a-z][a-z0-9-]{1,62}$")
        if name in self._services:
            raise UserAlreadyExistsError(service_subject(name))
        role_list = tuple(dict.fromkeys(check_role_name(role) for role in roles))
        if ROLE_ADMINISTRATOR in role_list:
            raise InvalidRoleError(ROLE_ADMINISTRATOR, reason="reserved")
        entry = _ServiceEntry(
            description=description,
            roles=role_list,
            is_blocked=False,
            created_by=actor,
        )
        self._services[name] = entry
        return ServiceAccountMutation(
            account=self._service_record(name, entry), changed=True, created=True
        )

    async def update_service_account(
        self,
        *,
        name: str,
        description: str | None = None,
        roles: Sequence[str] | None = None,
        is_blocked: bool | None = None,
        actor: str,  # noqa: ARG002
    ) -> ServiceAccountMutation:
        if name not in self._services:
            raise UserNotFoundError(
                service_subject(name),
                message=f"Service account not found: {service_subject(name)}",
            )
        entry = self._services[name]
        roles_before = tuple(sorted(entry.roles))
        blocked_before = entry.is_blocked
        changed = False
        if description is not None and entry.description != description:
            entry.description = description
            changed = True
        if is_blocked is not None and entry.is_blocked != is_blocked:
            entry.is_blocked = is_blocked
            changed = True
        if roles is not None:
            role_list = tuple(dict.fromkeys(check_role_name(role) for role in roles))
            if ROLE_ADMINISTRATOR in role_list:
                raise InvalidRoleError(ROLE_ADMINISTRATOR, reason="reserved")
            if set(roles_before) != set(role_list):
                entry.roles = role_list
                changed = True
        return ServiceAccountMutation(
            account=self._service_record(name, entry),
            changed=changed,
            roles_before=roles_before,
            blocked_before=blocked_before,
        )


#: Old name, kept as an alias without a deprecation warning: this is a test
#: helper, not a published contract (see X06's coordinator decision).
InMemoryUserDirectoryBackend = InMemoryUserDirectory
