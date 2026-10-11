"""Tests for keystone_mcp.users domain rules: emails, roles, and the service layer.

Parametrized over SQLite and Postgres via the ``users_engine`` fixture
(``tests/support/users_db.py``); Postgres cases skip without
``KEYSTONE_TEST_POSTGRES_URL``.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from keystone_mcp.users import service
from keystone_mcp.users.db import make_session_factory, session_scope
from keystone_mcp.users.emails import normalize_email
from keystone_mcp.users.errors import (
    ActorEmailRequiredError,
    InvalidRoleError,
    LastAdministratorError,
    SelfAdminMutationError,
    UserAlreadyExistsError,
)
from keystone_mcp.users.records import ResolvedUser, UserRecord
from keystone_mcp.users.roles import normalize_roles
from support.users_db import users_engine  # noqa: F401 -- fixture import


@pytest.fixture
def session_factory(users_engine):  # noqa: ANN001, F811 -- pytest fixture injection
    return make_session_factory(users_engine)


def test_users_package_has_no_back_imports() -> None:
    """Importing keystone_mcp.users alone must not pull in server/config/etc.

    Run in a fresh subprocess: in-process, other test modules already loaded
    in this same pytest session would have imported those modules long
    before this test runs, making an in-process sys.modules check meaningless.
    """
    code = (
        "import keystone_mcp.users, sys; "
        "assert 'keystone_mcp.user_directory' not in sys.modules; "
        "assert 'keystone_mcp.server' not in sys.modules; "
        "assert 'keystone_mcp.adapters' not in sys.modules; "
        "assert 'keystone_mcp.config' not in sys.modules"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_normalize_email_lowercase_and_trim() -> None:
    assert normalize_email("  User@Example.COM ") == "user@example.com"


def test_normalize_roles_deduplicates_and_keeps_order() -> None:
    assert normalize_roles(["operator", "analyst", "operator"], allowed=None) == [
        "operator",
        "analyst",
    ]


def test_normalize_roles_rejects_role_outside_policy() -> None:
    with pytest.raises(InvalidRoleError) as exc_info:
        normalize_roles(["ghost"], allowed=frozenset({"member"}))
    assert exc_info.value.code == "validation_error"
    assert "unknown role" in str(exc_info.value)


def test_normalize_roles_accepts_administrator_without_policy_entry() -> None:
    assert normalize_roles(["administrator"], allowed=frozenset({"member"})) == ["administrator"]


def test_normalize_roles_skips_policy_check_when_allowed_is_none() -> None:
    assert normalize_roles(["anything-goes"], allowed=None) == ["anything-goes"]


def test_role_name_format_is_checked() -> None:
    with pytest.raises(InvalidRoleError):
        normalize_roles([""], allowed=None)
    with pytest.raises(InvalidRoleError):
        normalize_roles(["x" * 65], allowed=None)


def test_resolve_unknown_user(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        result = service.resolve_user(session, "nobody@example.com")
    assert result == ResolvedUser(False, (), False)


def test_create_then_duplicate_is_conflict(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        service.create_user(
            session,
            email="dup@example.com",
            full_name="Dup",
            roles=[],
            note=None,
            created_by=None,
            allowed_roles=None,
        )

    with session_scope(session_factory) as session:
        with pytest.raises(UserAlreadyExistsError) as exc_info:
            service.create_user(
                session,
                email="dup@example.com",
                full_name="Dup Again",
                roles=[],
                note=None,
                created_by=None,
                allowed_roles=None,
            )
    assert exc_info.value.code == "conflict"


def test_create_rejects_bad_email_and_empty_full_name(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        with pytest.raises(Exception) as exc_info:  # noqa: PT011 - InvalidUserFieldError
            service.create_user(
                session,
                email="not-an-email",
                full_name="Someone",
                roles=[],
                note=None,
                created_by=None,
                allowed_roles=None,
            )
        assert exc_info.value.code == "validation_error"

    with session_scope(session_factory) as session:
        with pytest.raises(Exception) as exc_info:  # noqa: PT011
            service.create_user(
                session,
                email="ok@example.com",
                full_name="   ",
                roles=[],
                note=None,
                created_by=None,
                allowed_roles=None,
            )
        assert exc_info.value.code == "validation_error"


def test_multi_role_union_on_user(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        service.create_user(
            session,
            email="multi@example.com",
            full_name="Multi",
            roles=["analyst"],
            note=None,
            created_by="admin@example.com",
            allowed_roles=None,
        )

    with session_scope(session_factory) as session:
        user = service._load_user(session, "multi@example.com")
        assert service.role_names(user) == ["analyst"]

    with session_scope(session_factory) as session:
        service.grant_role(session, email="multi@example.com", role="operator", allowed_roles=None)

    with session_scope(session_factory) as session:
        user = service._load_user(session, "multi@example.com")
        assert service.role_names(user) == ["analyst", "operator"]

    with session_scope(session_factory) as session:
        service.revoke_role(
            session,
            email="multi@example.com",
            role="analyst",
            actor_email="admin@example.com",
        )

    with session_scope(session_factory) as session:
        user = service._load_user(session, "multi@example.com")
        assert service.role_names(user) == ["operator"]


def test_user_can_have_zero_roles(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        service.create_user(
            session,
            email="noroles@example.com",
            full_name="No Roles",
            roles=[],
            note=None,
            created_by=None,
            allowed_roles=None,
        )

    with session_scope(session_factory) as session:
        user = service._load_user(session, "noroles@example.com")
        assert service.role_names(user) == []

    with session_scope(session_factory) as session:
        service.grant_role(session, email="noroles@example.com", role="analyst", allowed_roles=None)

    with session_scope(session_factory) as session:
        service.revoke_role(
            session,
            email="noroles@example.com",
            role="analyst",
            actor_email=None,
        )

    with session_scope(session_factory) as session:
        user = service._load_user(session, "noroles@example.com")
        assert service.role_names(user) == []


def test_last_administrator_invariants(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        service.create_user(
            session,
            email="sole-admin@example.com",
            full_name="Sole Admin",
            roles=["administrator"],
            note=None,
            created_by=None,
            allowed_roles=None,
        )

    with session_scope(session_factory) as session:
        with pytest.raises(LastAdministratorError):
            service.revoke_role(
                session,
                email="sole-admin@example.com",
                role="administrator",
                actor_email="someone-else@example.com",
            )

    with session_scope(session_factory) as session:
        with pytest.raises(LastAdministratorError):
            service.replace_roles(
                session,
                email="sole-admin@example.com",
                roles=[],
                actor_email="someone-else@example.com",
                allowed_roles=None,
            )

    with session_scope(session_factory) as session:
        with pytest.raises(LastAdministratorError):
            service.set_blocked(
                session,
                email="sole-admin@example.com",
                blocked=True,
                actor_email="someone-else@example.com",
            )


def test_actor_email_required_for_protected_mutations(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        service.create_user(
            session,
            email="admin2@example.com",
            full_name="Admin Two",
            roles=["administrator"],
            note=None,
            created_by=None,
            allowed_roles=None,
        )
        service.create_user(
            session,
            email="admin3@example.com",
            full_name="Admin Three",
            roles=["administrator"],
            note=None,
            created_by=None,
            allowed_roles=None,
        )

    with session_scope(session_factory) as session:
        with pytest.raises(ActorEmailRequiredError):
            service.revoke_role(
                session,
                email="admin2@example.com",
                role="administrator",
                actor_email=None,
            )

    with session_scope(session_factory) as session:
        with pytest.raises(ActorEmailRequiredError):
            service.replace_roles(
                session,
                email="admin2@example.com",
                roles=[],
                actor_email=None,
                allowed_roles=None,
            )

    with session_scope(session_factory) as session:
        with pytest.raises(ActorEmailRequiredError):
            service.set_blocked(
                session,
                email="admin2@example.com",
                blocked=True,
                actor_email=None,
            )


def test_self_admin_mutations_rejected(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        service.create_user(
            session,
            email="self1@example.com",
            full_name="Self One",
            roles=["administrator"],
            note=None,
            created_by=None,
            allowed_roles=None,
        )
        service.create_user(
            session,
            email="self2@example.com",
            full_name="Self Two",
            roles=["administrator"],
            note=None,
            created_by=None,
            allowed_roles=None,
        )

    with session_scope(session_factory) as session:
        with pytest.raises(SelfAdminMutationError):
            service.set_blocked(
                session,
                email="self1@example.com",
                blocked=True,
                actor_email="self1@example.com",
            )

    with session_scope(session_factory) as session:
        with pytest.raises(SelfAdminMutationError):
            service.revoke_role(
                session,
                email="self1@example.com",
                role="administrator",
                actor_email="self1@example.com",
            )


def test_unchanged_mutations_report_changed_false(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        service.create_user(
            session,
            email="idempotent@example.com",
            full_name="Idempotent",
            roles=["analyst"],
            note="hello",
            created_by=None,
            allowed_roles=None,
        )

    with session_scope(session_factory) as session:
        mutation = service.grant_role(
            session, email="idempotent@example.com", role="analyst", allowed_roles=None
        )
        assert mutation.changed is False

    with session_scope(session_factory) as session:
        mutation = service.set_blocked(
            session, email="idempotent@example.com", blocked=False, actor_email=None
        )
        assert mutation.changed is False

    with session_scope(session_factory) as session:
        mutation = service.update_profile(
            session, email="idempotent@example.com", full_name="Idempotent", note="hello"
        )
        assert mutation.changed is False

    with session_scope(session_factory) as session:
        mutation = service.replace_roles(
            session,
            email="idempotent@example.com",
            roles=["analyst"],
            actor_email=None,
            allowed_roles=None,
        )
        assert mutation.changed is False


def test_list_defaults_to_non_blocked(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        service.create_user(
            session,
            email="active@example.com",
            full_name="Active",
            roles=[],
            note=None,
            created_by=None,
            allowed_roles=None,
        )
        service.create_user(
            session,
            email="blocked@example.com",
            full_name="Blocked",
            roles=[],
            note=None,
            created_by=None,
            allowed_roles=None,
        )
        service.set_blocked(
            session, email="blocked@example.com", blocked=True, actor_email="active@example.com"
        )

    with session_scope(session_factory) as session:
        emails = {u.email for u in service.list_users(session)}
        assert "active@example.com" in emails
        assert "blocked@example.com" not in emails

        emails_blocked = {u.email for u in service.list_users(session, is_blocked=True)}
        assert emails_blocked == {"blocked@example.com"}


def test_list_filters_by_role_and_email_fragment(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        service.create_user(
            session,
            email="a_b@example.com",
            full_name="A_B",
            roles=["operator"],
            note=None,
            created_by=None,
            allowed_roles=None,
        )
        service.create_user(
            session,
            email="axb@example.com",
            full_name="AxB",
            roles=[],
            note=None,
            created_by=None,
            allowed_roles=None,
        )

    with session_scope(session_factory) as session:
        by_role = {u.email for u in service.list_users(session, is_blocked=None, role="operator")}
        assert by_role == {"a_b@example.com"}

        by_fragment = {
            u.email for u in service.list_users(session, is_blocked=None, email_contains="a_b")
        }
        assert by_fragment == {"a_b@example.com"}
        assert "axb@example.com" not in by_fragment


def test_list_with_unknown_role_returns_empty(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        service.create_user(
            session,
            email="someone@example.com",
            full_name="Someone",
            roles=["analyst"],
            note=None,
            created_by=None,
            allowed_roles=None,
        )

    with session_scope(session_factory) as session:
        results = service.list_users(session, is_blocked=None, role="no-such-role")
        assert results == []


def test_seed_superadmin_idempotent(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        mutation = service.seed_superadmin(session, "root@example.com")
        assert mutation.created is True
        assert mutation.changed is True

    with session_scope(session_factory) as session:
        mutation = service.seed_superadmin(session, "root@example.com")
        assert mutation.changed is False

    with session_scope(session_factory) as session:
        matches = service.list_users(session, is_blocked=None, email_contains="root@example.com")
        assert len(matches) == 1


def test_seed_restores_administrator_role_but_not_unblock(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        service.seed_superadmin(session, "seed@example.com")
        # Add a second administrator so we can revoke the seed user's role.
        service.create_user(
            session,
            email="other-admin@example.com",
            full_name="Other Admin",
            roles=["administrator"],
            note=None,
            created_by=None,
            allowed_roles=None,
        )

    with session_scope(session_factory) as session:
        service.revoke_role(
            session,
            email="seed@example.com",
            role="administrator",
            actor_email="other-admin@example.com",
        )
        service.set_blocked(
            session, email="seed@example.com", blocked=True, actor_email="other-admin@example.com"
        )

    with session_scope(session_factory) as session:
        mutation = service.seed_superadmin(session, "seed@example.com")
        assert mutation.changed is True

    with session_scope(session_factory) as session:
        user = service._load_user(session, "seed@example.com")
        assert "administrator" in service.role_names(user)
        assert user.is_blocked is True


def test_ensure_administrator_creates_grants_and_unblocks(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        mutation = service.ensure_administrator(
            session, "rescue@example.com", created_by="cli:grant-admin"
        )
        assert mutation.created is True
        assert mutation.changed is True

    with session_scope(session_factory) as session:
        service.set_blocked(
            session, email="rescue@example.com", blocked=False, actor_email=None
        )  # no-op, already unblocked
        service.create_user(
            session,
            email="another-admin@example.com",
            full_name="Another",
            roles=["administrator"],
            note=None,
            created_by=None,
            allowed_roles=None,
        )
        service.set_blocked(
            session,
            email="rescue@example.com",
            blocked=True,
            actor_email="another-admin@example.com",
        )
        service.revoke_role(
            session,
            email="rescue@example.com",
            role="administrator",
            actor_email="another-admin@example.com",
        )

    with session_scope(session_factory) as session:
        mutation = service.ensure_administrator(
            session, "rescue@example.com", created_by="cli:grant-admin"
        )
        assert mutation.created is False
        assert mutation.changed is True

    with session_scope(session_factory) as session:
        user = service._load_user(session, "rescue@example.com")
        assert "administrator" in service.role_names(user)
        assert user.is_blocked is False


def test_user_record_to_dict_shape(session_factory) -> None:  # noqa: ANN001
    with session_scope(session_factory) as session:
        service.create_user(
            session,
            email="shape@example.com",
            full_name="Shape",
            roles=["analyst"],
            note="a note",
            created_by="creator@example.com",
            allowed_roles=None,
        )

    with session_scope(session_factory) as session:
        user = service._load_user(session, "shape@example.com")
        record = UserRecord.from_row(user)
        payload = record.to_dict()

    assert set(payload.keys()) == {
        "email",
        "full_name",
        "roles",
        "is_blocked",
        "created_at",
        "updated_at",
        "created_by",
        "note",
    }
    assert payload["created_at"].endswith("Z")
    assert payload["updated_at"].endswith("Z")
