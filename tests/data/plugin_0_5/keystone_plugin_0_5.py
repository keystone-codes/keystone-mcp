# Frozen copy of a plugin written against Keystone-MCP 0.5.0. Do not edit: it must keep working until 2.0.
"""Frozen 0.5-style plugin used by Keystone compatibility tests."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from keystone_mcp.login.protocol import (
    FormField,
    LoginIdentity,
    LoginKind,
    LoginRedirect,
    LoginRejected,
)
from keystone_mcp.plugins import LoginProviderConfig, PluginContext
from keystone_mcp.user_directory.errors import (
    LastAdministratorError,
    SelfAdminMutationError,
    UserAlreadyExistsError,
    UserDirectoryUnavailableError,
    UserNotFoundError,
)
from keystone_mcp.user_directory.types import (
    ApiKeyRecord,
    ApiKeyVerification,
    IssuedApiKey,
    MutationResult,
    ServiceAccountMutation,
    ServiceAccountRecord,
    UserRecord,
    UserResolveResult,
    is_valid_service_account_name,
    parse_service_subject,
    service_subject,
)

_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
_ROLE_ADMIN = "administrator"


def _normalize_email(email: str) -> str:
    return email.strip().lower()


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
class _ServiceEntry:
    description: str | None
    roles: tuple[str, ...]
    is_blocked: bool
    created_by: str | None = None
    created_at: datetime = field(default_factory=lambda: _EPOCH)
    updated_at: datetime = field(default_factory=lambda: _EPOCH)


@dataclass
class _ApiKeyEntry:
    key_id: str
    subject: str
    label: str | None
    created_at: datetime
    expires_at: datetime | None
    revoked: bool = False


@dataclass
class Plugin05Directory:
    _users: dict[str, _Entry] = field(default_factory=dict)
    _services: dict[str, _ServiceEntry] = field(default_factory=dict)
    _api_keys: dict[str, _ApiKeyEntry] = field(default_factory=dict)
    _api_secrets: dict[str, str] = field(default_factory=dict)
    unavailable: bool = False

    @property
    def name(self) -> str:
        return "plugin-0-5"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"admin", "service_accounts", "api_keys"})

    async def resolve_user(self, subject: str) -> UserResolveResult:
        if self.unavailable:
            raise UserDirectoryUnavailableError("unavailable", code="catalog_unavailable")
        svc = parse_service_subject(_normalize_email(subject))
        if svc is not None:
            entry = self._services.get(svc)
            if entry is None:
                return UserResolveResult(exists=False, roles=(), is_blocked=False)
            return UserResolveResult(
                exists=True,
                roles=entry.roles,
                is_blocked=entry.is_blocked,
                subject_type="service",
            )
        email = _normalize_email(subject)
        entry = self._users.get(email)
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
        needle = (email_contains or "").strip().lower()
        role_name = role.strip() if role else None
        out: list[UserRecord] = []
        for email, entry in sorted(self._users.items()):
            if is_blocked is not None and entry.is_blocked != is_blocked:
                continue
            if role_name is not None and role_name not in entry.roles:
                continue
            if needle and needle not in email:
                continue
            out.append(
                UserRecord(
                    email=email,
                    full_name=entry.full_name,
                    roles=entry.roles,
                    is_blocked=entry.is_blocked,
                    created_at=entry.created_at,
                    updated_at=entry.updated_at,
                    created_by=entry.created_by,
                    note=entry.note,
                )
            )
        return out

    async def ping(self) -> None:
        if self.unavailable:
            raise UserDirectoryUnavailableError("unavailable", code="catalog_unavailable")

    async def aclose(self) -> None:
        return None

    def _active_admins(self) -> int:
        return sum(
            1
            for entry in self._users.values()
            if _ROLE_ADMIN in entry.roles and not entry.is_blocked
        )

    async def create_user(
        self,
        *,
        email: str,
        full_name: str,
        roles: Sequence[str],
        note: str | None,
        actor: str,
    ) -> MutationResult:
        normalized = _normalize_email(email)
        if normalized in self._users:
            raise UserAlreadyExistsError(normalized)
        now = datetime.now(tz=UTC)
        entry = _Entry(
            full_name=full_name.strip(),
            roles=tuple(roles),
            is_blocked=False,
            note=note,
            created_by=actor,
            created_at=now,
            updated_at=now,
        )
        self._users[normalized] = entry
        return MutationResult(changed=True, created=True, user=UserRecord(
            email=normalized,
            full_name=entry.full_name,
            roles=entry.roles,
            is_blocked=False,
            created_at=now,
            updated_at=now,
            created_by=actor,
            note=note,
        ))

    async def update_user(
        self, *, email: str, full_name: str | None, note: str | None, actor: str
    ) -> MutationResult:
        normalized = _normalize_email(email)
        entry = self._users.get(normalized)
        if entry is None:
            raise UserNotFoundError(email)
        changed = False
        if full_name is not None and full_name != entry.full_name:
            entry.full_name = full_name
            changed = True
        if note is not None and note != entry.note:
            entry.note = note
            changed = True
        if changed:
            entry.updated_at = datetime.now(tz=UTC)
        user = UserRecord(
            email=normalized,
            full_name=entry.full_name,
            roles=entry.roles,
            is_blocked=entry.is_blocked,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            created_by=entry.created_by,
            note=entry.note,
        )
        return MutationResult(changed=changed, created=False, user=user)

    async def set_blocked(self, *, email: str, blocked: bool, actor: str) -> MutationResult:
        normalized = _normalize_email(email)
        entry = self._users.get(normalized)
        if entry is None:
            raise UserNotFoundError(email)
        if blocked and _ROLE_ADMIN in entry.roles and self._active_admins() <= 1:
            raise LastAdministratorError()
        if actor == normalized and blocked and _ROLE_ADMIN in entry.roles:
            raise SelfAdminMutationError("block")
        changed = entry.is_blocked != blocked
        entry.is_blocked = blocked
        if changed:
            entry.updated_at = datetime.now(tz=UTC)
        user = UserRecord(
            email=normalized,
            full_name=entry.full_name,
            roles=entry.roles,
            is_blocked=entry.is_blocked,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            created_by=entry.created_by,
            note=entry.note,
        )
        return MutationResult(changed=changed, created=False, user=user)

    async def replace_roles(
        self, *, email: str, roles: Sequence[str], actor: str
    ) -> MutationResult:
        normalized = _normalize_email(email)
        entry = self._users.get(normalized)
        if entry is None:
            raise UserNotFoundError(email)
        new_roles = tuple(roles)
        if _ROLE_ADMIN in entry.roles and _ROLE_ADMIN not in new_roles and self._active_admins() <= 1:
            raise LastAdministratorError()
        changed = entry.roles != new_roles
        entry.roles = new_roles
        if changed:
            entry.updated_at = datetime.now(tz=UTC)
        user = UserRecord(
            email=normalized,
            full_name=entry.full_name,
            roles=entry.roles,
            is_blocked=entry.is_blocked,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            created_by=entry.created_by,
            note=entry.note,
        )
        return MutationResult(changed=changed, created=False, user=user)

    async def grant_role(self, *, email: str, role: str, actor: str) -> MutationResult:
        from keystone_mcp.user_directory.errors import InvalidRoleError

        if not role or len(role) > 64:
            raise InvalidRoleError(role or "", reason="format")
        normalized = _normalize_email(email)
        entry = self._users.get(normalized)
        if entry is None:
            raise UserNotFoundError(email)
        if role in entry.roles:
            user = UserRecord(
                email=normalized,
                full_name=entry.full_name,
                roles=entry.roles,
                is_blocked=entry.is_blocked,
                created_at=entry.created_at,
                updated_at=entry.updated_at,
                created_by=entry.created_by,
                note=entry.note,
            )
            return MutationResult(changed=False, created=False, user=user)
        entry.roles = entry.roles + (role,)
        entry.updated_at = datetime.now(tz=UTC)
        user = UserRecord(
            email=normalized,
            full_name=entry.full_name,
            roles=entry.roles,
            is_blocked=entry.is_blocked,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            created_by=entry.created_by,
            note=entry.note,
        )
        return MutationResult(changed=True, created=False, user=user)

    async def revoke_role(self, *, email: str, role: str, actor: str) -> MutationResult:
        normalized = _normalize_email(email)
        entry = self._users.get(normalized)
        if entry is None:
            raise UserNotFoundError(email)
        if role not in entry.roles:
            user = UserRecord(
                email=normalized,
                full_name=entry.full_name,
                roles=entry.roles,
                is_blocked=entry.is_blocked,
                created_at=entry.created_at,
                updated_at=entry.updated_at,
                created_by=entry.created_by,
                note=entry.note,
            )
            return MutationResult(changed=False, created=False, user=user)
        if role == _ROLE_ADMIN and self._active_admins() <= 1:
            raise LastAdministratorError()
        if actor == normalized and role == _ROLE_ADMIN:
            raise SelfAdminMutationError("revoke administrator")
        entry.roles = tuple(r for r in entry.roles if r != role)
        entry.updated_at = datetime.now(tz=UTC)
        user = UserRecord(
            email=normalized,
            full_name=entry.full_name,
            roles=entry.roles,
            is_blocked=entry.is_blocked,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            created_by=entry.created_by,
            note=entry.note,
        )
        return MutationResult(changed=True, created=False, user=user)

    async def list_service_accounts(
        self, *, is_blocked: bool | None = False
    ) -> list[ServiceAccountRecord]:
        out: list[ServiceAccountRecord] = []
        for name, entry in sorted(self._services.items()):
            if is_blocked is not None and entry.is_blocked != is_blocked:
                continue
            out.append(
                ServiceAccountRecord(
                    name=name,
                    subject=service_subject(name),
                    description=entry.description,
                    roles=entry.roles,
                    is_blocked=entry.is_blocked,
                    created_at=entry.created_at,
                    updated_at=entry.updated_at,
                    created_by=entry.created_by,
                )
            )
        return out

    async def create_service_account(
        self,
        *,
        name: str,
        description: str | None,
        roles: Sequence[str],
        actor: str,
    ) -> ServiceAccountMutation:
        if not is_valid_service_account_name(name):
            from keystone_mcp.user_directory.errors import InvalidUserFieldError

            raise InvalidUserFieldError("field", "invalid")
        if _ROLE_ADMIN in roles:
            from keystone_mcp.user_directory.errors import InvalidRoleError

            raise InvalidRoleError(_ROLE_ADMIN, reason="reserved")
        if name in self._services:
            raise UserAlreadyExistsError(name)
        now = datetime.now(tz=UTC)
        self._services[name] = _ServiceEntry(
            description=description,
            roles=tuple(roles),
            is_blocked=False,
            created_by=actor,
            created_at=now,
            updated_at=now,
        )
        record = ServiceAccountRecord(
            name=name,
            subject=service_subject(name),
            description=description,
            roles=tuple(roles),
            is_blocked=False,
            created_at=now,
            updated_at=now,
            created_by=actor,
        )
        return ServiceAccountMutation(created=True, changed=True, account=record)

    async def update_service_account(
        self,
        *,
        name: str,
        description: str | None = None,
        roles: Sequence[str] | None = None,
        is_blocked: bool | None = None,
        actor: str,
    ) -> ServiceAccountMutation:
        entry = self._services.get(name)
        if entry is None:
            raise UserNotFoundError(name)
        changed = False
        if description is not None and description != entry.description:
            entry.description = description
            changed = True
        if roles is not None and tuple(roles) != entry.roles:
            if _ROLE_ADMIN in roles:
                from keystone_mcp.user_directory.errors import InvalidRoleError

                raise InvalidRoleError(_ROLE_ADMIN, reason="reserved")
            entry.roles = tuple(roles)
            changed = True
        if is_blocked is not None and is_blocked != entry.is_blocked:
            entry.is_blocked = is_blocked
            changed = True
        if changed:
            entry.updated_at = datetime.now(tz=UTC)
        record = ServiceAccountRecord(
            name=name,
            subject=service_subject(name),
            description=entry.description,
            roles=entry.roles,
            is_blocked=entry.is_blocked,
            created_at=entry.created_at,
            updated_at=entry.updated_at,
            created_by=entry.created_by,
        )
        return ServiceAccountMutation(created=False, changed=changed, account=record)

    async def issue_api_key(
        self,
        *,
        subject: str,
        label: str | None,
        expires_in_days: int | None,
        actor: str,
    ) -> IssuedApiKey:
        from keystone_mcp.user_directory.errors import InvalidUserFieldError

        if expires_in_days == 0:
            raise InvalidUserFieldError("field", "invalid")
        normalized = _normalize_email(subject)
        entry = self._users.get(normalized)
        if entry is None:
            raise UserNotFoundError(normalized)
        if entry.is_blocked:
            raise InvalidUserFieldError("field", "invalid")
        key_id = secrets.token_hex(8)
        secret = secrets.token_urlsafe(32)
        material = f"ksk_{key_id}_{secret}"
        digest = hashlib.sha256(material.encode()).hexdigest()
        now = datetime.now(tz=UTC)
        expires = now + timedelta(days=expires_in_days) if expires_in_days else None
        self._api_keys[key_id] = _ApiKeyEntry(
            key_id=key_id,
            subject=normalized,
            label=label,
            created_at=now,
            expires_at=expires,
        )
        self._api_secrets[digest] = key_id
        record = ApiKeyRecord(
            key_id=key_id,
            subject=normalized,
            label=label,
            created_at=now,
            expires_at=expires,
            revoked_at=None,
            revoked_by=None,
            created_by=actor,
        )
        return IssuedApiKey(key=material, record=record)

    async def list_api_keys(
        self,
        *,
        subject: str | None = None,
        include_revoked: bool = False,
    ) -> list[ApiKeyRecord]:
        out: list[ApiKeyRecord] = []
        for entry in self._api_keys.values():
            if subject is not None and entry.subject != _normalize_email(subject):
                continue
            if entry.revoked and not include_revoked:
                continue
            out.append(
                ApiKeyRecord(
                    key_id=entry.key_id,
                    subject=entry.subject,
                    label=entry.label,
                    created_at=entry.created_at,
                    expires_at=entry.expires_at,
                    revoked_at=entry.created_at if entry.revoked else None,
                    revoked_by=None,
                    created_by=None,
                )
            )
        return out

    async def revoke_api_key(self, *, key_id: str, actor: str) -> tuple[ApiKeyRecord, bool]:
        entry = self._api_keys.get(key_id)
        if entry is None:
            raise UserNotFoundError(key_id)
        if entry.revoked:
            record = ApiKeyRecord(
                key_id=entry.key_id,
                subject=entry.subject,
                label=entry.label,
                created_at=entry.created_at,
                expires_at=entry.expires_at,
                revoked_at=entry.created_at,
                revoked_by=None,
                created_by=None,
            )
            return record, False
        entry.revoked = True
        record = ApiKeyRecord(
            key_id=entry.key_id,
            subject=entry.subject,
            label=entry.label,
            created_at=entry.created_at,
            expires_at=entry.expires_at,
            revoked_at=datetime.now(tz=UTC),
            revoked_by=None,
            created_by=actor,
        )
        return record, True

    async def verify_api_key(self, key: str) -> ApiKeyVerification | None:
        digest = hashlib.sha256(key.encode()).hexdigest()
        key_id = self._api_secrets.get(digest)
        if key_id is None:
            return None
        entry = self._api_keys.get(key_id)
        if entry is None or entry.revoked:
            return None
        if entry.expires_at and entry.expires_at <= datetime.now(tz=UTC):
            return None
        return ApiKeyVerification(subject=entry.subject, subject_type="human", key_id=key_id, expires_at=entry.expires_at)


class Plugin05FormProvider:
    @property
    def name(self) -> str:
        return "form05"

    @property
    def kind(self) -> LoginKind:
        return "form"

    @property
    def title(self) -> str:
        return "Form 0.5"

    @property
    def interactive(self) -> bool:
        return True

    async def warm_up(self) -> None:
        return None

    async def aclose(self) -> None:
        return None

    def form_fields(self) -> Sequence[FormField]:
        return (FormField(name="email", input_type="email", label_key="email"),)

    async def verify(self, form: Mapping[str, str]) -> LoginIdentity:
        email = _normalize_email(form.get("email", ""))
        if not email:
            raise LoginRejected("invalid_credentials")
        return LoginIdentity(email=email, provider=self.name, interactive=True)


class Plugin05RedirectProvider:
    @property
    def name(self) -> str:
        return "redirect05"

    @property
    def kind(self) -> LoginKind:
        return "redirect"

    @property
    def title(self) -> str:
        return "Redirect 0.5"

    @property
    def interactive(self) -> bool:
        return True

    async def warm_up(self) -> None:
        return None

    async def aclose(self) -> None:
        return None

    async def begin(self, *, state: str, callback_url: str) -> LoginRedirect:
        return LoginRedirect(url=f"https://example.test/auth?state={state}", attempt={"state": state})

    async def complete(
        self, *, params: Mapping[str, str], callback_url: str, attempt: Mapping[str, str]
    ) -> LoginIdentity:
        if params.get("error"):
            raise LoginRejected("request_invalid")
        email = _normalize_email(params.get("email", "user@example.com"))
        return LoginIdentity(email=email, provider=self.name, interactive=True)


def create_directory(context: PluginContext, options: Mapping[str, object]) -> Plugin05Directory:
    del context, options
    return Plugin05Directory()


def create_form_provider(config: LoginProviderConfig, context: PluginContext) -> Plugin05FormProvider:
    del config, context
    return Plugin05FormProvider()


def create_redirect_provider(
    config: LoginProviderConfig, context: PluginContext
) -> Plugin05RedirectProvider:
    del config, context
    return Plugin05RedirectProvider()
