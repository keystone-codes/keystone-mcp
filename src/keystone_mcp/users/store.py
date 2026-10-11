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
from collections.abc import Sequence
from dataclasses import dataclass

from redis.exceptions import RedisError
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from keystone_mcp.users import service
from keystone_mcp.users.db import describe_db_url, make_session_factory, session_scope
from keystone_mcp.users.errors import UsersError, UsersStoreUnavailableError
from keystone_mcp.users.migrate import upgrade_to_head
from keystone_mcp.users.records import ImportedUser, ResolvedUser, UserRecord
from keystone_mcp.users.revision import RevisionWriter
from keystone_mcp.users.service import ImportOutcome, Mutation

logger = logging.getLogger(__name__)

# Failures a revision bump can raise that must not fail the mutation itself:
# the data is already committed, and turning this into an error would only
# push the caller to retry a write that already succeeded.
_BUMP_FAILURE_TYPES = (RedisError, OSError)


@dataclass(frozen=True, slots=True)
class MutationResult:
    """A :class:`~keystone_mcp.users.service.Mutation`, shaped for callers outside this package."""

    user: UserRecord
    changed: bool
    created: bool = False
    roles_before: tuple[str, ...] = ()
    blocked_before: bool = False

    @classmethod
    def _from_mutation(cls, mutation: Mutation) -> MutationResult:
        return cls(
            user=UserRecord.from_row(mutation.user),
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

    async def resolve(self, email: str) -> ResolvedUser:
        return await self._read(service.resolve_user, email=email)

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
        return [UserRecord.from_row(row) for row in rows]

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

    async def ensure_administrator(self, email: str, *, created_by: str) -> MutationResult:
        return await self._mutate(service.ensure_administrator, email=email, created_by=created_by)

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
            try:
                await self._revision.bump()
            except _BUMP_FAILURE_TYPES:
                logger.warning(
                    "users directory revision bump failed; other replicas will "
                    "notice the change after the cache TTL"
                )
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

        try:
            mutation = await asyncio.to_thread(_call)
        except Exception as exc:
            raise _wrap_database_errors(exc) from exc

        result = MutationResult._from_mutation(mutation)
        if result.changed:
            # Bumped after the transaction above has already committed (we are
            # here only once asyncio.to_thread has returned): another request
            # that observes the new revision is guaranteed to read the data
            # this mutation just wrote, not a stale snapshot.
            try:
                await self._revision.bump()
            except _BUMP_FAILURE_TYPES:
                logger.warning(
                    "users directory revision bump failed; other replicas will "
                    "notice the change after the cache TTL"
                )
        return result
