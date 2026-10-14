"""Business rules for the users directory.

All functions here are synchronous, take a ``Session``, and never commit —
committing (and, after a successful commit, bumping the revision counter) is
the caller's job. Mutating functions return a ``Mutation`` describing what
happened, so the caller knows whether a revision bump is warranted.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from sqlalchemy import Table, func, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session, selectinload

from keystone_mcp.user_directory.types import (
    ApiKeyVerification,
    generate_api_key_material,
    is_valid_service_account_name,
    parse_api_key,
    parse_service_subject,
    service_subject,
    subject_type_of,
)
from keystone_mcp.users.emails import normalize_email, require_valid_email
from keystone_mcp.users.errors import (
    ActorEmailRequiredError,
    InvalidRoleError,
    InvalidUserFieldError,
    LastAdministratorError,
    SelfAdminMutationError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from keystone_mcp.users.models import (
    ApiKeyRow,
    ServiceAccountRoleRow,
    ServiceAccountRow,
    UserRoleRow,
    UserRow,
    utcnow,
)
from keystone_mcp.users.records import ImportedUser, ResolvedUser
from keystone_mcp.users.roles import ROLE_ADMINISTRATOR, check_role_name, normalize_roles

MAX_FULL_NAME_LENGTH = 255
# Matches UserRow.created_by (String(320)); only imported records carry an
# arbitrary-length created_by from an external source, so only
# validate_imported_user/upsert_imported_user need this constant.
MAX_CREATED_BY_LENGTH = 320


@dataclass(frozen=True, slots=True)
class Mutation:
    """The outcome of a service-layer write."""

    user: UserRow
    changed: bool
    created: bool = False
    roles_before: tuple[str, ...] = ()
    blocked_before: bool = False


def role_names(user: UserRow) -> list[str]:
    return sorted({assignment.role for assignment in user.roles})


def _load_user(session: Session, email: str) -> UserRow:
    normalized = normalize_email(email)
    user = session.scalar(
        select(UserRow).options(selectinload(UserRow.roles)).where(UserRow.email == normalized)
    )
    if user is None:
        raise UserNotFoundError(normalized)
    return user


def _require_actor(actor_email: str | None) -> str:
    if not actor_email:
        raise ActorEmailRequiredError()
    return normalize_email(actor_email)


def _lock_active_admin_emails(session: Session) -> set[str]:
    """Lock active administrator rows and return their emails."""
    users = (
        session.scalars(
            select(UserRow)
            .join(UserRoleRow, UserRow.email == UserRoleRow.email)
            .where(
                UserRow.is_blocked.is_(False),
                UserRoleRow.role == ROLE_ADMINISTRATOR,
            )
            .with_for_update()
        )
        .unique()
        .all()
    )
    return {user.email for user in users}


def _ensure_not_last_admin(
    session: Session,
    *,
    target_email: str,
    target_roles: set[str],
    next_roles: set[str] | None = None,
    will_block: bool = False,
) -> None:
    if ROLE_ADMINISTRATOR not in target_roles:
        return

    active_admins = _lock_active_admin_emails(session)
    remaining = active_admins - {normalize_email(target_email)}

    if will_block or (next_roles is not None and ROLE_ADMINISTRATOR not in next_roles):
        if not remaining:
            raise LastAdministratorError()


def count_active_administrators(session: Session) -> int:
    """Count non-blocked users holding the administrator role.

    Same query as :func:`_lock_active_admin_emails`, without ``FOR UPDATE``:
    this is a read used for a startup warning, not part of a mutation that
    needs the row lock.
    """
    return (
        session.scalar(
            select(func.count())
            .select_from(UserRow)
            .join(UserRoleRow, UserRow.email == UserRoleRow.email)
            .where(
                UserRow.is_blocked.is_(False),
                UserRoleRow.role == ROLE_ADMINISTRATOR,
            )
        )
        or 0
    )


def _ensure_not_self(actor_email: str, target_email: str, *, action: str) -> None:
    if normalize_email(actor_email) == normalize_email(target_email):
        raise SelfAdminMutationError(action)


def resolve_user(session: Session, subject: str) -> ResolvedUser:
    service_name = parse_service_subject(subject)
    if service_name is not None:
        account = session.scalar(
            select(ServiceAccountRow)
            .options(selectinload(ServiceAccountRow.roles))
            .where(ServiceAccountRow.name == service_name)
        )
        if account is None:
            return ResolvedUser(exists=False, roles=(), is_blocked=False, subject_type="service")
        return ResolvedUser(
            exists=True,
            roles=tuple(sorted({assignment.role for assignment in account.roles})),
            is_blocked=account.is_blocked,
            subject_type="service",
        )
    normalized = normalize_email(subject)
    user = session.scalar(
        select(UserRow).options(selectinload(UserRow.roles)).where(UserRow.email == normalized)
    )
    if user is None:
        return ResolvedUser(exists=False, roles=(), is_blocked=False)
    return ResolvedUser(exists=True, roles=tuple(role_names(user)), is_blocked=user.is_blocked)


def list_users(
    session: Session,
    *,
    is_blocked: bool | None = False,
    role: str | None = None,
    email_contains: str | None = None,
) -> list[UserRow]:
    stmt = select(UserRow).options(selectinload(UserRow.roles)).order_by(UserRow.email)
    if is_blocked is not None:
        stmt = stmt.where(UserRow.is_blocked.is_(is_blocked))
    if email_contains:
        stmt = stmt.where(UserRow.email.contains(normalize_email(email_contains), autoescape=True))
    if role:
        role_name = check_role_name(role)
        stmt = stmt.join(UserRoleRow).where(UserRoleRow.role == role_name)
    return list(session.scalars(stmt).unique().all())


def create_user(
    session: Session,
    *,
    email: str,
    full_name: str,
    roles: Sequence[str],
    note: str | None,
    created_by: str | None,
    allowed_roles: frozenset[str] | None,
) -> Mutation:
    normalized = require_valid_email(email)
    if session.get(UserRow, normalized) is not None:
        raise UserAlreadyExistsError(normalized)

    stripped_name = full_name.strip()
    if not stripped_name or len(stripped_name) > MAX_FULL_NAME_LENGTH:
        raise InvalidUserFieldError("full_name", "must be 1-255 characters after trimming")

    role_list = normalize_roles(roles, allowed=allowed_roles)
    user = UserRow(
        email=normalized,
        full_name=stripped_name,
        note=note,
        created_by=normalize_email(created_by) if created_by else None,
        is_blocked=False,
    )
    session.add(user)
    for role_name in role_list:
        user.roles.append(UserRoleRow(email=normalized, role=role_name))
    session.flush()
    return Mutation(user=user, changed=True, created=True)


def update_profile(
    session: Session,
    *,
    email: str,
    full_name: str | None,
    note: str | None,
) -> Mutation:
    user = _load_user(session, email)
    roles_before = tuple(role_names(user))
    changed = False

    if full_name is not None:
        stripped_name = full_name.strip()
        if not stripped_name or len(stripped_name) > MAX_FULL_NAME_LENGTH:
            raise InvalidUserFieldError("full_name", "must be 1-255 characters after trimming")
        if user.full_name != stripped_name:
            user.full_name = stripped_name
            changed = True

    if note is not None and user.note != note:
        user.note = note
        changed = True

    if not changed:
        return Mutation(user=user, changed=False, roles_before=roles_before)

    user.updated_at = utcnow()
    return Mutation(user=user, changed=True, roles_before=roles_before)


def set_blocked(
    session: Session,
    *,
    email: str,
    blocked: bool,
    actor_email: str | None,
) -> Mutation:
    user = _load_user(session, email)
    blocked_before = user.is_blocked
    if user.is_blocked == blocked:
        return Mutation(user=user, changed=False, blocked_before=blocked_before)

    if blocked:
        actor = _require_actor(actor_email)
        if ROLE_ADMINISTRATOR in role_names(user):
            _ensure_not_self(actor, user.email, action="block")
            _ensure_not_last_admin(
                session,
                target_email=user.email,
                target_roles=set(role_names(user)),
                will_block=True,
            )

    user.is_blocked = blocked
    user.updated_at = utcnow()
    return Mutation(user=user, changed=True, blocked_before=blocked_before)


def replace_roles(
    session: Session,
    *,
    email: str,
    roles: Sequence[str],
    actor_email: str | None,
    allowed_roles: frozenset[str] | None,
) -> Mutation:
    user = _load_user(session, email)
    current_roles = set(role_names(user))
    roles_before = tuple(sorted(current_roles))
    next_roles = set(normalize_roles(roles, allowed=allowed_roles))
    if current_roles == next_roles:
        return Mutation(user=user, changed=False, roles_before=roles_before)

    if ROLE_ADMINISTRATOR in current_roles and ROLE_ADMINISTRATOR not in next_roles:
        actor = _require_actor(actor_email)
        _ensure_not_self(actor, user.email, action="revoke administrator")
        _ensure_not_last_admin(
            session,
            target_email=user.email,
            target_roles=current_roles,
            next_roles=next_roles,
        )

    for assignment in list(user.roles):
        session.delete(assignment)
    session.flush()
    user.roles = [UserRoleRow(email=user.email, role=role_name) for role_name in sorted(next_roles)]
    user.updated_at = utcnow()
    return Mutation(user=user, changed=True, roles_before=roles_before)


def grant_role(
    session: Session,
    *,
    email: str,
    role: str,
    allowed_roles: frozenset[str] | None,
) -> Mutation:
    user = _load_user(session, email)
    roles_before = tuple(role_names(user))
    role_name = normalize_roles([role], allowed=allowed_roles)[0]
    if role_name in roles_before:
        return Mutation(user=user, changed=False, roles_before=roles_before)

    user.roles.append(UserRoleRow(email=user.email, role=role_name))
    user.updated_at = utcnow()
    return Mutation(user=user, changed=True, roles_before=roles_before)


def revoke_role(
    session: Session,
    *,
    email: str,
    role: str,
    actor_email: str | None,
) -> Mutation:
    user = _load_user(session, email)
    current_roles = set(role_names(user))
    roles_before = tuple(sorted(current_roles))
    role_name = check_role_name(role)
    if role_name not in current_roles:
        return Mutation(user=user, changed=False, roles_before=roles_before)

    if role_name == ROLE_ADMINISTRATOR:
        actor = _require_actor(actor_email)
        _ensure_not_self(actor, user.email, action="revoke administrator")
        _ensure_not_last_admin(
            session,
            target_email=user.email,
            target_roles=current_roles,
            next_roles=current_roles - {ROLE_ADMINISTRATOR},
        )

    user.roles = [assignment for assignment in user.roles if assignment.role != role_name]
    user.updated_at = utcnow()
    return Mutation(user=user, changed=True, roles_before=roles_before)


def _insert_ignore(
    session: Session,
    table: Table,
    values: dict[str, Any],
    index_elements: list[str],
) -> None:
    """Insert a row, doing nothing if it already exists (cross-dialect)."""
    dialect_name = session.get_bind().dialect.name
    if dialect_name == "postgresql":
        stmt = postgresql.insert(table).values(**values)
    elif dialect_name == "sqlite":
        stmt = sqlite.insert(table).values(**values)
    else:
        raise RuntimeError(f"unsupported dialect for insert-ignore: {dialect_name}")
    session.execute(stmt.on_conflict_do_nothing(index_elements=index_elements))


def seed_superadmin(session: Session, email: str) -> Mutation:
    """Idempotently ensure ``email`` exists with the administrator role.

    Does not unblock an already-blocked seed user: this call runs on every
    server start, and a deliberately blocked administrator should stay
    blocked. If the administrator role was revoked from this user, the next
    start restores it (same behavior as the legacy directory service).
    """
    normalized = require_valid_email(email)
    now = utcnow()

    existing = session.scalar(
        select(UserRow).options(selectinload(UserRow.roles)).where(UserRow.email == normalized)
    )
    had_admin = existing is not None and ROLE_ADMINISTRATOR in role_names(existing)

    _insert_ignore(
        session,
        UserRow.__table__,
        {
            "email": normalized,
            "full_name": normalized,
            "is_blocked": False,
            "note": "Initial administrator from KEYSTONE_MCP_SUPERADMIN_EMAIL",
            "created_by": "system:seed",
            "created_at": now,
            "updated_at": now,
        },
        index_elements=["email"],
    )
    _insert_ignore(
        session,
        UserRoleRow.__table__,
        {"email": normalized, "role": ROLE_ADMINISTRATOR},
        index_elements=["email", "role"],
    )
    session.flush()

    # populate_existing: the inserts above went through Core, bypassing the
    # ORM identity map, so without it this would hand back the same (now
    # stale) object `existing` pointed at, with its roles collection frozen
    # at the pre-insert state.
    user = session.scalar(
        select(UserRow)
        .options(selectinload(UserRow.roles))
        .where(UserRow.email == normalized)
        .execution_options(populate_existing=True)
    )
    assert user is not None  # the insert above guarantees the row exists

    created = existing is None
    has_admin = ROLE_ADMINISTRATOR in role_names(user)
    changed = created or (has_admin and not had_admin)
    return Mutation(user=user, changed=changed, created=created)


def ensure_administrator(
    session: Session,
    email: str,
    *,
    created_by: str | None,
    role: str = ROLE_ADMINISTRATOR,
) -> Mutation:
    """Emergency access recovery: grant administrator and clear any block.

    Like ``seed_superadmin``, but it also unblocks the user if blocked — this
    is the one path meant for someone recovering access, not routine startup.
    """
    normalized = require_valid_email(email)
    now = utcnow()

    user = session.scalar(
        select(UserRow).options(selectinload(UserRow.roles)).where(UserRow.email == normalized)
    )

    created = user is None
    if user is None:
        user = UserRow(
            email=normalized,
            full_name=normalized,
            is_blocked=False,
            note=None,
            created_by=normalize_email(created_by) if created_by else None,
            created_at=now,
            updated_at=now,
        )
        session.add(user)

    grant_role = check_role_name(role)
    roles_before = tuple(role_names(user)) if not created else ()
    had_admin = grant_role in roles_before
    was_blocked = user.is_blocked
    changed = created

    if not had_admin:
        user.roles.append(UserRoleRow(email=user.email, role=grant_role))
        changed = True

    if was_blocked:
        user.is_blocked = False
        changed = True

    if changed and not created:
        user.updated_at = now

    session.flush()
    return Mutation(
        user=user,
        changed=changed,
        created=created,
        roles_before=roles_before,
        blocked_before=was_blocked,
    )


@dataclass(frozen=True, slots=True)
class ImportOutcome:
    """What happened to one user while importing from an external directory."""

    email: str
    status: Literal["created", "updated", "unchanged", "invalid"]
    skipped_roles: tuple[str, ...] = ()
    invalid_reason: str | None = None
    # Only meaningful for status == "updated": the source is authoritative on
    # every re-run (see upsert_imported_user's docstring), so a second import
    # can silently undo a block, an `administrator` grant/revoke, or any other
    # role grant made locally after the first import. These flag exactly
    # that, so `--dry-run` can warn about it before anyone is surprised by a
    # real run. ``block_lifted``/``block_reapplied`` and
    # ``roles_revoked``/``administrator_changed`` are deliberately not merged
    # into one boolean each: a caller that only cares about one direction (or
    # about `administrator` specifically) can still ask for it, while
    # `keystone-mcp users import`'s own `admin_or_block_changes` count (see
    # `cli.py`) treats all of them as the same kind of risk.
    block_lifted: bool = False
    block_reapplied: bool = False
    administrator_changed: bool = False
    # Every role the user had before this run that the source no longer
    # lists (so it was just removed to match the source) -- independent of
    # whether that role was granted locally (through `users_grant_role`) or
    # by an earlier import; there is no record of a role's origin, so any
    # role disappearing on a re-run is the same risk either way. Includes
    # `administrator` when it is the role being revoked (`administrator_changed`
    # also covers that case, for a grant as much as a revoke).
    roles_revoked: tuple[str, ...] = ()


def validate_imported_user(imported: ImportedUser, *, allowed_roles: frozenset[str]) -> str | None:
    """Check one source record for problems that ``upsert_imported_user`` cannot write.

    Returns ``None`` when the record is fine to write, or a short,
    human-readable reason otherwise (never the source's raw payload or a
    token — only the field and why it was rejected). Call this *before*
    writing: a malformed record reaching ``session.flush()`` is, on
    PostgreSQL, a ``DataError`` for the whole transaction (an over-length
    ``full_name`` violates the column's ``VARCHAR(255)``, for example);
    SQLite would not even catch it, since it does not enforce column length.
    Checking here means one bad source record is reported and skipped instead
    of aborting every record in the batch, on either database.

    Only the roles that would actually be written are checked for format:
    a role the active policy does not recognize is dropped before writing
    (see ``upsert_imported_user``), so a malformed name among *those* does
    not matter.
    """
    try:
        require_valid_email(imported.email)
    except InvalidUserFieldError as exc:
        return f"email: {exc}"

    stripped_name = imported.full_name.strip()
    if not stripped_name or len(stripped_name) > MAX_FULL_NAME_LENGTH:
        return f"full_name: must be 1-{MAX_FULL_NAME_LENGTH} characters after trimming"

    if imported.created_by is not None and len(imported.created_by.strip()) > MAX_CREATED_BY_LENGTH:
        return f"created_by: must be at most {MAX_CREATED_BY_LENGTH} characters after trimming"

    kept_roles = [
        role for role in imported.roles if role == ROLE_ADMINISTRATOR or role in allowed_roles
    ]
    try:
        normalize_roles(kept_roles, allowed=None)
    except InvalidRoleError as exc:
        return f"role: {exc}"

    return None


def upsert_imported_user(
    session: Session,
    imported: ImportedUser,
    *,
    allowed_roles: frozenset[str],
) -> ImportOutcome:
    """Create or update one user from an external users directory.

    The source wins, on every run, not only the first: for an existing user,
    ``full_name``, ``note``, ``is_blocked`` and the role set are all
    overwritten with what the source currently reports; ``created_at``/
    ``created_by`` are left alone. Concretely, running this command again can,
    in either direction: lift a block the source no longer has, or
    re-apply one the source still has even though someone unblocked that
    person locally through ``users_*`` in the meantime; regrant or revoke
    ``administrator`` to match the source; and silently drop any other role
    granted locally (through ``users_grant_role``) that the source does not
    report, since there is no record of which role came from where. This is a
    data migration, not an administrator action, so none of the "last
    administrator" or "cannot mutate your own admin access" rules apply —
    those guard a person acting through ``users_*``, not a one-time (or
    repeated) transfer of records from the system that used to own them.
    Callers that want to know whether a re-run is about to do any of this
    should check ``ImportOutcome.block_lifted``, ``.block_reapplied``,
    ``.administrator_changed`` and ``.roles_revoked``.

    Roles the active policy does not recognize are dropped rather than
    rejected: ``administrator`` is always kept. A user who ends up with no
    roles at all is still imported (their account state and history still
    matter even if the policy does not currently grant them anything).
    """
    normalized = normalize_email(imported.email)
    # The same values validate_imported_user checked (stripped full_name,
    # stripped+length-capped created_by) must be what gets written -- writing
    # the raw, untrimmed field here would defeat that check (e.g. stored
    # leading/trailing whitespace the validation rule disallows, or a
    # created_by value only a hair under the column limit once trimmed).
    stripped_full_name = imported.full_name.strip()
    stripped_created_by = imported.created_by.strip() if imported.created_by else ""
    skipped_roles = tuple(
        role for role in imported.roles if role != ROLE_ADMINISTRATOR and role not in allowed_roles
    )
    kept_roles = [role for role in imported.roles if role not in skipped_roles]
    # allowed=None: roles already passed the policy filter above, so only the
    # name-format check and de-duplication from normalize_roles are wanted here.
    role_list = normalize_roles(kept_roles, allowed=None)

    now = utcnow()
    existing = session.scalar(
        select(UserRow).options(selectinload(UserRow.roles)).where(UserRow.email == normalized)
    )

    if existing is None:
        user = UserRow(
            email=normalized,
            full_name=stripped_full_name,
            note=imported.note,
            is_blocked=imported.is_blocked,
            created_by=stripped_created_by or "system:import",
            created_at=imported.created_at or now,
            updated_at=imported.updated_at or now,
        )
        session.add(user)
        for role_name in role_list:
            user.roles.append(UserRoleRow(email=normalized, role=role_name))
        session.flush()
        return ImportOutcome(email=normalized, status="created", skipped_roles=skipped_roles)

    changed = False
    was_blocked = existing.is_blocked
    current_roles = set(role_names(existing))
    was_admin = ROLE_ADMINISTRATOR in current_roles

    if existing.full_name != stripped_full_name:
        existing.full_name = stripped_full_name
        changed = True

    if existing.note != imported.note:
        existing.note = imported.note
        changed = True

    if existing.is_blocked != imported.is_blocked:
        existing.is_blocked = imported.is_blocked
        changed = True

    next_roles = set(role_list)
    if current_roles != next_roles:
        for assignment in list(existing.roles):
            session.delete(assignment)
        session.flush()
        existing.roles = [
            UserRoleRow(email=existing.email, role=role_name) for role_name in sorted(next_roles)
        ]
        changed = True

    if changed:
        existing.updated_at = now

    session.flush()
    return ImportOutcome(
        email=normalized,
        status="updated" if changed else "unchanged",
        skipped_roles=skipped_roles,
        block_lifted=was_blocked and not imported.is_blocked,
        block_reapplied=(not was_blocked) and imported.is_blocked,
        administrator_changed=was_admin != (ROLE_ADMINISTRATOR in next_roles),
        roles_revoked=tuple(sorted(current_roles - next_roles)),
    )


@dataclass(frozen=True, slots=True)
class ServiceAccountMutation:
    account: ServiceAccountRow
    changed: bool
    created: bool = False
    roles_before: tuple[str, ...] = ()
    blocked_before: bool = False


def _service_role_names(account: ServiceAccountRow) -> list[str]:
    return sorted({assignment.role for assignment in account.roles})


def _load_service_account(session: Session, name: str) -> ServiceAccountRow:
    account = session.scalar(
        select(ServiceAccountRow)
        .options(selectinload(ServiceAccountRow.roles))
        .where(ServiceAccountRow.name == name)
    )
    if account is None:
        raise UserNotFoundError(
            service_subject(name),
            message=f"Service account not found: {service_subject(name)}",
        )
    return account


def _reject_administrator_for_service(role_list: Sequence[str]) -> None:
    for role_name in role_list:
        if role_name == ROLE_ADMINISTRATOR:
            raise InvalidRoleError(ROLE_ADMINISTRATOR, reason="reserved")


def create_service_account(
    session: Session,
    *,
    name: str,
    description: str | None,
    roles: Sequence[str],
    created_by: str | None,
) -> ServiceAccountMutation:
    if not is_valid_service_account_name(name):
        raise InvalidUserFieldError("name", "must match ^[a-z][a-z0-9-]{1,62}$")
    if session.get(ServiceAccountRow, name) is not None:
        raise UserAlreadyExistsError(service_subject(name))
    role_list = normalize_roles(roles, allowed=None)
    _reject_administrator_for_service(role_list)
    account = ServiceAccountRow(
        name=name,
        description=description,
        created_by=created_by,
        is_blocked=False,
    )
    session.add(account)
    for role_name in role_list:
        account.roles.append(ServiceAccountRoleRow(name=name, role=role_name))
    session.flush()
    return ServiceAccountMutation(account=account, changed=True, created=True)


def update_service_account(
    session: Session,
    *,
    name: str,
    description: str | None = None,
    roles: Sequence[str] | None = None,
    is_blocked: bool | None = None,
    actor: str,  # noqa: ARG001
) -> ServiceAccountMutation:
    account = _load_service_account(session, name)
    roles_before = tuple(_service_role_names(account))
    blocked_before = account.is_blocked
    changed = False
    if description is not None and account.description != description:
        account.description = description
        changed = True
    if is_blocked is not None and account.is_blocked != is_blocked:
        account.is_blocked = is_blocked
        changed = True
    if roles is not None:
        role_list = normalize_roles(roles, allowed=None)
        _reject_administrator_for_service(role_list)
        next_roles = set(role_list)
        if set(roles_before) != next_roles:
            for assignment in list(account.roles):
                session.delete(assignment)
            session.flush()
            account.roles = [
                ServiceAccountRoleRow(name=name, role=role_name) for role_name in sorted(next_roles)
            ]
            changed = True
    if changed:
        account.updated_at = utcnow()
    session.flush()
    return ServiceAccountMutation(
        account=account,
        changed=changed,
        roles_before=roles_before,
        blocked_before=blocked_before,
    )


def list_service_accounts(
    session: Session,
    *,
    is_blocked: bool | None = False,
) -> list[ServiceAccountRow]:
    stmt = (
        select(ServiceAccountRow)
        .options(selectinload(ServiceAccountRow.roles))
        .order_by(ServiceAccountRow.name)
    )
    if is_blocked is not None:
        stmt = stmt.where(ServiceAccountRow.is_blocked.is_(is_blocked))
    return list(session.scalars(stmt).unique().all())


MAX_API_KEY_LABEL_LENGTH = 255


@dataclass(frozen=True, slots=True)
class ApiKeyMutation:
    row: ApiKeyRow
    changed: bool


def _secret_hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _load_api_key_row(session: Session, key_id: str) -> ApiKeyRow:
    row = session.get(ApiKeyRow, key_id)
    if row is None:
        raise UserNotFoundError(key_id, message=f"API key not found: {key_id}")
    return row


def _ensure_api_key_subject_active(session: Session, subject: str) -> None:
    service_name = parse_service_subject(subject)
    if service_name is not None:
        account = session.get(ServiceAccountRow, service_name)
        if account is None:
            raise UserNotFoundError(subject)
        if account.is_blocked:
            raise InvalidUserFieldError("subject", "subject is blocked")
        return
    normalized = normalize_email(subject)
    user = session.get(UserRow, normalized)
    if user is None:
        raise UserNotFoundError(normalized)
    if user.is_blocked:
        raise InvalidUserFieldError("subject", "subject is blocked")


def issue_api_key(
    session: Session,
    *,
    subject: str,
    label: str | None,
    expires_in_days: int | None,
    created_by: str | None,
) -> tuple[ApiKeyRow, str]:
    lookup_subject = (
        subject.strip().lower() if parse_service_subject(subject) else normalize_email(subject)
    )
    _ensure_api_key_subject_active(session, lookup_subject)
    if expires_in_days is not None and not (1 <= expires_in_days <= 365):
        raise InvalidUserFieldError("expires_in_days", "must be between 1 and 365 inclusive")
    if label is not None and len(label) > MAX_API_KEY_LABEL_LENGTH:
        raise InvalidUserFieldError(
            "label", f"must be at most {MAX_API_KEY_LABEL_LENGTH} characters"
        )
    key_id, secret, full_key = generate_api_key_material()
    now = utcnow()
    expires_at = None
    if expires_in_days is not None:
        from datetime import timedelta

        expires_at = now + timedelta(days=expires_in_days)
    row = ApiKeyRow(
        key_id=key_id,
        subject=lookup_subject,
        secret_hash=_secret_hash(secret),
        label=label,
        created_by=created_by,
        created_at=now,
        expires_at=expires_at,
    )
    session.add(row)
    session.flush()
    return row, full_key


def list_api_keys(
    session: Session,
    *,
    subject: str | None = None,
    include_revoked: bool = False,
) -> list[ApiKeyRow]:
    stmt = select(ApiKeyRow).order_by(ApiKeyRow.created_at.desc())
    if subject is not None:
        lookup = (
            subject.strip().lower() if parse_service_subject(subject) else normalize_email(subject)
        )
        stmt = stmt.where(ApiKeyRow.subject == lookup)
    if not include_revoked:
        stmt = stmt.where(ApiKeyRow.revoked_at.is_(None))
    return list(session.scalars(stmt).all())


def revoke_api_key(session: Session, *, key_id: str, actor: str) -> ApiKeyMutation:
    row = _load_api_key_row(session, key_id)
    if row.revoked_at is not None:
        return ApiKeyMutation(row=row, changed=False)
    row.revoked_at = utcnow()
    row.revoked_by = actor
    session.flush()
    return ApiKeyMutation(row=row, changed=True)


def verify_api_key(session: Session, key: str) -> ApiKeyVerification | None:
    parsed = parse_api_key(key)
    if parsed is None:
        return None
    key_id, secret = parsed
    row = session.get(ApiKeyRow, key_id)
    if row is None or row.revoked_at is not None:
        return None
    now = utcnow()
    if row.expires_at is not None and row.expires_at <= now:
        return None
    expected = row.secret_hash
    if not hmac.compare_digest(expected, _secret_hash(secret)):
        return None
    return ApiKeyVerification(
        key_id=row.key_id,
        subject=row.subject,
        subject_type=subject_type_of(row.subject),
        expires_at=row.expires_at,
    )
