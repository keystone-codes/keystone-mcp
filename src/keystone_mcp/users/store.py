"""Async facade over the users directory database.

``UsersStore`` is the one point through which the server, the ``users_*``
tool adapter, and the CLI touch the users database. It wraps the synchronous
functions in :mod:`keystone_mcp.users.service` (each takes a ``Session`` and
never commits) in ``asyncio.to_thread``, commits (or rolls back) around them,
and — only after a successful commit, and only when something actually
changed — bumps the shared revision counter so cached resolvers elsewhere
notice.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Callable, Sequence

from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from keystone_mcp.user_directory.types import (
    ApiKeyRecord,
    ApiKeyVerification,
    DeleteMode,
    DeletionResult,
    IdentityBinding,
    IssuedApiKey,
    MutationResult,
    ServiceAccountMutation,
    ServiceAccountRecord,
    UserRecord,
)
from keystone_mcp.users import service
from keystone_mcp.users.db import describe_db_url, make_session_factory, session_scope
from keystone_mcp.users.errors import UsersError, UsersStoreUnavailableError
from keystone_mcp.users.migrate import upgrade_to_head
from keystone_mcp.users.records import (
    ImportedUser,
    ResolvedUser,
    api_key_record_from_row,
    service_account_record_from_row,
    user_record_from_row,
)
from keystone_mcp.users.revision import RevisionWriter
from keystone_mcp.users.service import ApiKeyMutation as ApiKeyWriteMutation
from keystone_mcp.users.service import ImportOutcome, Mutation
from keystone_mcp.users.service import ServiceAccountMutation as ServiceAccountWriteMutation

logger = logging.getLogger(__name__)

# Failures a revision bump can raise that must not fail the mutation itself:
# the data is already committed, and turning this into an error would only
# push the caller to retry a write that already succeeded.
_BUMP_FAILURE_TYPES = (RedisError, OSError)


def _mutation_result_from_mutation(mutation: Mutation) -> MutationResult:
    """Shape a service-layer :class:`Mutation` for callers outside this package."""
    return MutationResult(
        user=user_record_from_row(mutation.user),
        changed=mutation.changed,
        created=mutation.created,
        roles_before=mutation.roles_before,
        blocked_before=mutation.blocked_before,
    )


def _wrap_database_errors(exc: Exception) -> Exception:
    if isinstance(exc, UsersError):
        return exc
    if isinstance(exc, SQLAlchemyError | OSError):
        return UsersStoreUnavailableError("users directory database is unavailable")
    return exc


async def _to_thread_with_integrity_retry(call: Callable[[], object]) -> object:
    try:
        return await asyncio.to_thread(call)
    except IntegrityError:
        logger.info("users directory write raced with a concurrent write; retried once")
        try:
            return await asyncio.to_thread(call)
        except Exception as exc:
            raise _wrap_database_errors(exc) from exc
    except Exception as exc:
        raise _wrap_database_errors(exc) from exc


class UsersStore:
    """Owns the engine and session factory for one users directory database."""

    def __init__(self, engine: Engine, *, revision: RevisionWriter) -> None:
        self._engine = engine
        self._session_factory = make_session_factory(engine)
        self._revision = revision
        # SQLite's SELECT ... FOR UPDATE does not block: two concurrent writes
        # (e.g. two administrators each revoking the other) could both read
        # "I am not the last admin" and both proceed. A process-wide lock
        # around every write closes that race. PostgreSQL's row lock does the
        # job on its own, so no lock is needed there.
        self._write_lock = threading.Lock() if engine.dialect.name == "sqlite" else None
        self._change_listeners: list[Callable[[bool], None]] = []

    def add_change_listener(self, listener: Callable[[bool], None]) -> None:
        self._change_listeners.append(listener)

    async def _after_change(self) -> None:
        ok = True
        try:
            await self._revision.bump()
        except _BUMP_FAILURE_TYPES:
            logger.warning(
                "users directory revision bump failed; other replicas will "
                "notice the change after the cache TTL"
            )
            ok = False
        for listener in self._change_listeners:
            try:
                listener(ok)
            except Exception:
                logger.warning("users change listener failed", exc_info=True)

    @property
    def db_url_redacted(self) -> str:
        """The database URL for logs: an absolute path for SQLite, else redacted.

        See :func:`keystone_mcp.users.db.describe_db_url` for why SQLite gets
        an absolute path rather than whatever relative form was configured.
        """
        return describe_db_url(str(self._engine.url))

    async def migrate(self) -> None:
        await asyncio.to_thread(upgrade_to_head, self._engine)

    async def ping(self) -> None:
        def _ping() -> None:
            with self._engine.connect() as conn:
                conn.execute(text("SELECT 1"))

        try:
            await asyncio.to_thread(_ping)
        except (SQLAlchemyError, OSError) as exc:
            raise UsersStoreUnavailableError("users directory database is unavailable") from exc

    async def resolve(self, subject: str) -> ResolvedUser:
        return await self._read(service.resolve_user, subject=subject)

    async def get_identity_binding(self, email: str) -> IdentityBinding | None:
        return await self._read(service.get_identity_binding, email=email)

    async def bind_identity(self, *, email: str, issuer: str, subject: str) -> IdentityBinding:
        return await self._commit_binding(
            service.bind_identity, email=email, issuer=issuer, subject=subject
        )

    async def clear_identity_binding(self, *, email: str, actor: str) -> bool:
        return await self._commit_binding(service.clear_identity_binding, email=email, actor=actor)

    async def count_person_references(self, email: str) -> int:
        return await self._read(service.count_person_references, email=email)

    async def person_authored_records(self, email: str) -> dict[str, int]:
        return await self._read(service.person_authored_records, email=email)

    async def delete_user(
        self,
        *,
        email: str,
        actor: str,
        mode: DeleteMode,
        pseudonym: str,
    ) -> DeletionResult:
        def _call() -> DeletionResult:
            def _in_session() -> DeletionResult:
                with session_scope(self._session_factory) as session:
                    return service.delete_user(
                        session,
                        email=email,
                        actor=actor,
                        mode=mode,
                        pseudonym=pseudonym,
                    )

            if self._write_lock is not None:
                with self._write_lock:
                    return _in_session()
            return _in_session()

        try:
            result = await asyncio.to_thread(_call)
        except Exception as exc:
            raise _wrap_database_errors(exc) from exc
        await self._after_change()
        return result

    async def list_service_accounts(
        self,
        *,
        is_blocked: bool | None = False,
    ) -> list[ServiceAccountRecord]:
        rows = await self._read(service.list_service_accounts, is_blocked=is_blocked)
        return [service_account_record_from_row(row) for row in rows]

    async def issue_api_key(
        self,
        *,
        subject: str,
        label: str | None,
        expires_in_days: int | None,
        created_by: str | None,
    ) -> IssuedApiKey:
        def _call() -> tuple[ApiKeyWriteMutation, str]:
            def _in_session() -> tuple[ApiKeyWriteMutation, str]:
                with session_scope(self._session_factory) as session:
                    row, full_key = service.issue_api_key(
                        session,
                        subject=subject,
                        label=label,
                        expires_in_days=expires_in_days,
                        created_by=created_by,
                    )
                    return ApiKeyWriteMutation(row=row, changed=True), full_key

            if self._write_lock is not None:
                with self._write_lock:
                    return _in_session()
            return _in_session()

        mutation, full_key = await _to_thread_with_integrity_retry(_call)
        await self._after_change()
        record = api_key_record_from_row(mutation.row)
        return IssuedApiKey(record=record, key=full_key)

    async def list_api_keys(
        self,
        *,
        subject: str | None = None,
        include_revoked: bool = False,
    ) -> list[ApiKeyRecord]:
        rows = await self._read(
            service.list_api_keys, subject=subject, include_revoked=include_revoked
        )
        return [api_key_record_from_row(row) for row in rows]

    async def revoke_api_key(self, *, key_id: str, actor: str) -> tuple[ApiKeyRecord, bool]:
        def _call() -> ApiKeyWriteMutation:
            def _in_session() -> ApiKeyWriteMutation:
                with session_scope(self._session_factory) as session:
                    return service.revoke_api_key(session, key_id=key_id, actor=actor)

            if self._write_lock is not None:
                with self._write_lock:
                    return _in_session()
            return _in_session()

        try:
            mutation = await asyncio.to_thread(_call)
        except Exception as exc:
            raise _wrap_database_errors(exc) from exc
        if mutation.changed:
            await self._after_change()
        return api_key_record_from_row(mutation.row), mutation.changed

    async def verify_api_key(self, key: str) -> ApiKeyVerification | None:
        return await self._read(service.verify_api_key, key=key)

    async def active_api_key_ids(self) -> frozenset[str]:
        return await self._read(service.active_api_key_ids)

    async def create_service_account(
        self,
        *,
        name: str,
        description: str | None,
        roles: Sequence[str],
        created_by: str | None,
    ) -> ServiceAccountMutation:
        return await self._mutate_service_account(
            service.create_service_account,
            name=name,
            description=description,
            roles=roles,
            created_by=created_by,
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
        return await self._mutate_service_account(
            service.update_service_account,
            name=name,
            description=description,
            roles=roles,
            is_blocked=is_blocked,
            actor=actor,
        )

    async def list_users(
        self,
        *,
        is_blocked: bool | None = False,
        role: str | None = None,
        email_contains: str | None = None,
    ) -> list[UserRecord]:
        rows = await self._read(
            service.list_users,
            is_blocked=is_blocked,
            role=role,
            email_contains=email_contains,
        )
        return [user_record_from_row(row) for row in rows]

    async def count_active_administrators(self) -> int:
        return await self._read(service.count_active_administrators)

    async def create_user(
        self,
        *,
        email: str,
        full_name: str,
        roles: Sequence[str],
        note: str | None,
        created_by: str | None,
        allowed_roles: frozenset[str] | None,
    ) -> MutationResult:
        return await self._mutate(
            service.create_user,
            email=email,
            full_name=full_name,
            roles=roles,
            note=note,
            created_by=created_by,
            allowed_roles=allowed_roles,
        )

    async def update_profile(
        self,
        *,
        email: str,
        full_name: str | None,
        note: str | None,
    ) -> MutationResult:
        return await self._mutate(
            service.update_profile, email=email, full_name=full_name, note=note
        )

    async def set_blocked(
        self,
        *,
        email: str,
        blocked: bool,
        actor_email: str | None,
    ) -> MutationResult:
        return await self._mutate(
            service.set_blocked, email=email, blocked=blocked, actor_email=actor_email
        )

    async def replace_roles(
        self,
        *,
        email: str,
        roles: Sequence[str],
        actor_email: str | None,
        allowed_roles: frozenset[str] | None,
    ) -> MutationResult:
        return await self._mutate(
            service.replace_roles,
            email=email,
            roles=roles,
            actor_email=actor_email,
            allowed_roles=allowed_roles,
        )

    async def grant_role(
        self,
        *,
        email: str,
        role: str,
        allowed_roles: frozenset[str] | None,
    ) -> MutationResult:
        return await self._mutate(
            service.grant_role, email=email, role=role, allowed_roles=allowed_roles
        )

    async def revoke_role(
        self,
        *,
        email: str,
        role: str,
        actor_email: str | None,
    ) -> MutationResult:
        return await self._mutate(
            service.revoke_role, email=email, role=role, actor_email=actor_email
        )

    async def seed_superadmin(self, email: str) -> MutationResult:
        return await self._mutate(service.seed_superadmin, email=email)

    async def ensure_administrator(
        self,
        email: str,
        *,
        created_by: str,
        role: str | None = None,
    ) -> MutationResult:
        from keystone_mcp.users.roles import ROLE_ADMINISTRATOR

        grant_role = ROLE_ADMINISTRATOR if role is None else role
        return await self._mutate(
            service.ensure_administrator,
            email=email,
            created_by=created_by,
            role=grant_role,
        )

    async def import_users(
        self,
        users: Sequence[ImportedUser],
        *,
        allowed_roles: frozenset[str],
        dry_run: bool,
    ) -> list[ImportOutcome]:
        """Upsert a batch of imported users in one transaction.

        Unlike ``_mutate``, this does not always commit: ``dry_run=True``
        runs every upsert and then rolls back, so the returned outcomes
        describe what *would* change without writing anything or bumping the
        revision counter.

        A record that fails :func:`service.validate_imported_user` is never
        written: it comes back with ``status="invalid"`` and a reason instead
        of aborting the whole batch (see that function's docstring for why).
        Any other error — the database being unreachable, for one — still
        aborts the transaction and surfaces to the caller as
        ``UsersStoreUnavailableError``.
        """

        def _call() -> list[ImportOutcome]:
            def _in_session() -> list[ImportOutcome]:
                session = self._session_factory()
                try:
                    outcomes: list[ImportOutcome] = []
                    for index, user in enumerate(users):
                        # Validated *before* touching the session: a record
                        # that fails here (bad email, an over-length
                        # full_name, a malformed role) never reaches
                        # session.flush(), so it cannot turn into a
                        # PostgreSQL DataError that would abort every other
                        # record in this one-transaction batch.
                        reason = service.validate_imported_user(user, allowed_roles=allowed_roles)
                        if reason is not None:
                            identifier = user.email.strip() or f"record #{index}"
                            outcomes.append(
                                ImportOutcome(
                                    email=identifier,
                                    status="invalid",
                                    invalid_reason=reason,
                                )
                            )
                            continue
                        outcomes.append(
                            service.upsert_imported_user(session, user, allowed_roles=allowed_roles)
                        )
                    if dry_run:
                        session.rollback()
                    else:
                        session.commit()
                    return outcomes
                except Exception:
                    session.rollback()
                    raise
                finally:
                    session.close()

            if self._write_lock is not None:
                with self._write_lock:
                    return _in_session()
            return _in_session()

        try:
            outcomes = await asyncio.to_thread(_call)
        except Exception as exc:
            raise _wrap_database_errors(exc) from exc

        if not dry_run and any(outcome.status in ("created", "updated") for outcome in outcomes):
            await self._after_change()
        return outcomes

    def dispose(self) -> None:
        self._engine.dispose()

    async def _read(self, fn, **kwargs):  # noqa: ANN001, ANN202
        def _call():  # noqa: ANN202
            with session_scope(self._session_factory) as session:
                return fn(session, **kwargs)

        try:
            return await asyncio.to_thread(_call)
        except Exception as exc:
            raise _wrap_database_errors(exc) from exc

    async def _commit_binding(self, fn, **kwargs):  # noqa: ANN001, ANN202
        """Commit identity-binding writes without bumping the directory revision."""

        def _call():  # noqa: ANN202
            def _in_session():  # noqa: ANN202
                with session_scope(self._session_factory) as session:
                    return fn(session, **kwargs)

            if self._write_lock is not None:
                with self._write_lock:
                    return _in_session()
            return _in_session()

        try:
            return await asyncio.to_thread(_call)
        except Exception as exc:
            raise _wrap_database_errors(exc) from exc

    async def _mutate(self, fn, **kwargs) -> MutationResult:  # noqa: ANN001
        def _call() -> Mutation:
            def _in_session() -> Mutation:
                with session_scope(self._session_factory) as session:
                    mutation = fn(session, **kwargs)
                    # Force the roles collection to load now, while the
                    # session is still open: a freshly created user whose
                    # ``roles`` were never touched (e.g. an empty role list)
                    # is flushed but not necessarily loaded, and the session
                    # closes as soon as this ``with`` block exits.
                    len(mutation.user.roles)
                    return mutation

            if self._write_lock is not None:
                with self._write_lock:
                    return _in_session()
            return _in_session()

        mutation = await _to_thread_with_integrity_retry(_call)

        result = _mutation_result_from_mutation(mutation)
        if result.changed:
            await self._after_change()
        return result

    def _service_mutation_result(
        self, mutation: ServiceAccountWriteMutation
    ) -> ServiceAccountMutation:
        return ServiceAccountMutation(
            account=service_account_record_from_row(mutation.account),
            changed=mutation.changed,
            created=mutation.created,
            roles_before=mutation.roles_before,
            blocked_before=mutation.blocked_before,
        )

    async def _mutate_service_account(self, fn, **kwargs) -> ServiceAccountMutation:  # noqa: ANN001
        def _call() -> ServiceAccountWriteMutation:
            def _in_session() -> ServiceAccountWriteMutation:
                with session_scope(self._session_factory) as session:
                    mutation = fn(session, **kwargs)
                    len(mutation.account.roles)
                    return mutation

            if self._write_lock is not None:
                with self._write_lock:
                    return _in_session()
            return _in_session()

        mutation = await _to_thread_with_integrity_retry(_call)

        result = self._service_mutation_result(mutation)
        if result.changed:
            await self._after_change()
        return result
