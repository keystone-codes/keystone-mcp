"""Built-in users directory: reads and administers the server's own database.

Implements the full :class:`~keystone_mcp.user_directory.protocol.UserDirectory`
plus :class:`~keystone_mcp.user_directory.protocol.UserDirectoryAdmin` on top
of :class:`~keystone_mcp.users.store.UsersStore` -- a thin translation layer.
The cache, circuit breaker, and revision-based invalidation in
:class:`~keystone_mcp.user_directory.resolver.CachedUserDirectoryResolver`
work exactly as they do with any other directory, because an unavailable
store raises the same kind of error an unreachable HTTP service would.

Role-against-policy checks happen in
:class:`~keystone_mcp.adapters.users_admin.UsersAdminAdapter`, before this
class is ever called: every mutating method here passes ``allowed_roles=None``
to the store, which still validates role-name *format* (and always accepts
``administrator``) but performs no policy filtering of its own.
"""

from __future__ import annotations

from collections.abc import Sequence

from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.types import (
    ApiKeyRecord,
    ApiKeyVerification,
    IssuedApiKey,
    MutationResult,
    ServiceAccountMutation,
    ServiceAccountRecord,
    UserRecord,
    UserResolveResult,
    parse_service_subject,
)
from keystone_mcp.user_directory.util import normalize_email
from keystone_mcp.users.errors import UsersStoreUnavailableError
from keystone_mcp.users.store import UsersStore


class LocalUserDirectory:
    """``UserDirectory`` + ``UserDirectoryAdmin`` over the built-in ``UsersStore``."""

    def __init__(self, store: UsersStore) -> None:
        self._store = store

    @property
    def name(self) -> str:
        return "local"

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset({"admin", "service_accounts", "api_keys"})

    async def ping(self) -> None:
        """Delegate to :meth:`UsersStore.ping` (``SELECT 1``) for readiness checks."""
        try:
            await self._store.ping()
        except UsersStoreUnavailableError as exc:
            raise UserDirectoryUnavailableError(
                "users directory is unavailable",
                code="catalog_unavailable",
            ) from exc

    async def resolve_user(self, subject: str) -> UserResolveResult:
        lookup = (
            subject.strip().lower() if parse_service_subject(subject) else normalize_email(subject)
        )
        try:
            resolved = await self._store.resolve(lookup)
        except UsersStoreUnavailableError as exc:
            raise UserDirectoryUnavailableError(
                "users directory is unavailable",
                code="catalog_unavailable",
            ) from exc
        return UserResolveResult(
            exists=resolved.exists,
            roles=resolved.roles,
            is_blocked=resolved.is_blocked,
            subject_type=resolved.subject_type,  # type: ignore[arg-type]
        )

    async def list_users(
        self,
        *,
        is_blocked: bool | None = False,
        role: str | None = None,
        email_contains: str | None = None,
    ) -> list[UserRecord]:
        # Unlike resolve_user/ping, errors here are *not* translated to
        # UserDirectoryUnavailableError: this method (and every
        # UserDirectoryAdmin method below) is only ever called from
        # UsersAdminAdapter, which expects the users_* skill's own error
        # vocabulary (UsersStoreUnavailableError -> code "service_unavailable").
        return await self._store.list_users(
            is_blocked=is_blocked, role=role, email_contains=email_contains
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
        return await self._store.create_user(
            email=email,
            full_name=full_name,
            roles=roles,
            note=note,
            created_by=actor,
            allowed_roles=None,
        )

    async def update_user(
        self,
        *,
        email: str,
        full_name: str | None,
        note: str | None,
        actor: str,  # noqa: ARG002 -- the built-in store does not record who edited a profile
    ) -> MutationResult:
        return await self._store.update_profile(email=email, full_name=full_name, note=note)

    async def set_blocked(self, *, email: str, blocked: bool, actor: str) -> MutationResult:
        return await self._store.set_blocked(email=email, blocked=blocked, actor_email=actor)

    async def replace_roles(
        self, *, email: str, roles: Sequence[str], actor: str
    ) -> MutationResult:
        return await self._store.replace_roles(
            email=email, roles=roles, actor_email=actor, allowed_roles=None
        )

    async def grant_role(self, *, email: str, role: str, actor: str) -> MutationResult:  # noqa: ARG002
        return await self._store.grant_role(email=email, role=role, allowed_roles=None)

    async def revoke_role(self, *, email: str, role: str, actor: str) -> MutationResult:
        return await self._store.revoke_role(email=email, role=role, actor_email=actor)

    async def list_service_accounts(
        self,
        *,
        is_blocked: bool | None = False,
    ) -> list[ServiceAccountRecord]:
        return await self._store.list_service_accounts(is_blocked=is_blocked)

    async def create_service_account(
        self,
        *,
        name: str,
        description: str | None,
        roles: Sequence[str],
        actor: str,
    ) -> ServiceAccountMutation:
        return await self._store.create_service_account(
            name=name,
            description=description,
            roles=roles,
            created_by=actor,
        )

    async def update_service_account(
        self,
        *,
        name: str,
        description: str | None = None,
        roles: Sequence[str] | None = None,
        is_blocked: bool | None = None,
        actor: str,
    ) -> ServiceAccountMutation:
        return await self._store.update_service_account(
            name=name,
            description=description,
            roles=roles,
            is_blocked=is_blocked,
            actor=actor,
        )

    async def issue_api_key(
        self,
        *,
        subject: str,
        label: str | None,
        expires_in_days: int | None,
        actor: str,
    ) -> IssuedApiKey:
        return await self._store.issue_api_key(
            subject=subject,
            label=label,
            expires_in_days=expires_in_days,
            created_by=actor,
        )

    async def list_api_keys(
        self,
        *,
        subject: str | None = None,
        include_revoked: bool = False,
    ) -> list[ApiKeyRecord]:
        return await self._store.list_api_keys(subject=subject, include_revoked=include_revoked)

    async def revoke_api_key(self, *, key_id: str, actor: str) -> tuple[ApiKeyRecord, bool]:
        return await self._store.revoke_api_key(key_id=key_id, actor=actor)

    async def verify_api_key(self, key: str) -> ApiKeyVerification | None:
        return await self._store.verify_api_key(key)

    async def active_api_key_ids(self) -> frozenset[str]:
        return await self._store.active_api_key_ids()

    async def aclose(self) -> None:
        # The store's engine is owned by whoever built it (the server), not
        # by this directory, so there is nothing to close here.
        return None


def create_local_directory(context, options) -> LocalUserDirectory:
    from collections.abc import Mapping

    from keystone_mcp.config import Settings
    from keystone_mcp.plugins import PluginContext
    from keystone_mcp.users.factory import build_users_store

    if not isinstance(context, PluginContext):
        raise TypeError("invalid factory arguments")
    if options and not isinstance(options, Mapping):
        raise TypeError("options must be a mapping")
    settings = context.settings
    if not isinstance(settings, Settings):
        raise TypeError("context.settings must be Settings")
    return LocalUserDirectory(build_users_store(settings))
