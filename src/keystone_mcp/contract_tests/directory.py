"""Executable contract tests for ``UserDirectory`` implementations."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import pytest

from keystone_mcp.observability.subject import hash_subject
from keystone_mcp.user_directory.errors import (
    UserDirectoryUnavailableError,
    UsersError,
)
from keystone_mcp.user_directory.protocol import (
    ApiKeyDirectory,
    IdentityBindingDirectory,
    ServiceAccountDirectory,
    UserDeletionDirectory,
    UserDirectory,
    UserDirectoryAdmin,
)
from keystone_mcp.user_directory.types import service_subject

_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_ALLOWED_CAPABILITIES = frozenset(
    {"admin", "service_accounts", "api_keys", "identity_binding", "delete"}
)
_UNAVAILABLE_FIXTURE_HINT = (
    "add keystone_unavailable_directory_factory fixture to run availability contract tests"
)


def _contract_lenient_reason_for_class(cls: type | None) -> str | None:
    if cls is None:
        return None
    marks = getattr(cls, "pytestmark", [])
    if not isinstance(marks, list):
        marks = [marks]
    for mark in marks:
        if mark.name == "keystone_contract_lenient":
            reason = mark.kwargs.get("reason")
            if reason is None and mark.args:
                reason = mark.args[0]
            if not str(reason or "").strip():
                pytest.fail("keystone_contract_lenient needs a reason")
            return str(reason)
    return None


def _contract_lenient_reason(request: pytest.FixtureRequest) -> str | None:
    return _contract_lenient_reason_for_class(request.cls)


def _require_capability_contract_class(
    test_cls: type | None,
    capability: str,
    contract_cls: type,
) -> None:
    reason = _contract_lenient_reason_for_class(test_cls)
    if reason:
        pytest.skip(f"keystone_contract_lenient: {reason}")
    cls = test_cls
    if cls is None or not issubclass(cls, contract_cls):
        pytest.fail(
            f"directory declares {capability!r}: inherit {contract_cls.__name__} in "
            f"{cls.__name__ if cls else '<class>'} (or mark the class "
            "keystone_contract_lenient(reason=...))"
        )


@dataclass(frozen=True, slots=True)
class ContractPerson:
    email: str
    full_name: str
    roles: tuple[str, ...]
    blocked: bool


CONTRACT_DATASET: tuple[ContractPerson, ...] = (
    ContractPerson("alice@example.com", "Alice Admin", ("administrator",), blocked=False),
    ContractPerson("bob@example.com", "Bob Member", ("member",), blocked=False),
    ContractPerson("carol@example.com", "Carol Blocked", ("member",), blocked=True),
)

_SEED_ACTOR = "contract-seed@example.com"


async def seed_contract_dataset(directory: UserDirectoryAdmin) -> None:
    for person in CONTRACT_DATASET:
        await directory.create_user(
            email=person.email,
            full_name=person.full_name,
            roles=person.roles,
            note=None,
            actor=_SEED_ACTOR,
        )
        if person.blocked:
            await directory.set_blocked(
                email=person.email,
                blocked=True,
                actor=_SEED_ACTOR,
            )


def _run(factory: Callable[[], Awaitable[UserDirectory]], body: Any) -> None:
    async def _exercise() -> None:
        directory = await factory()
        try:
            await body(directory)
        finally:
            await directory.aclose()

    asyncio.run(_exercise())


def _require_unavailable_factory(request: pytest.FixtureRequest) -> Any:
    reason = _contract_lenient_reason(request)
    if reason:
        pytest.skip(f"keystone_contract_lenient: {reason}")
    try:
        return request.getfixturevalue("keystone_unavailable_directory_factory")
    except pytest.FixtureLookupError:
        pytest.fail(_UNAVAILABLE_FIXTURE_HINT)


def _person(email: str) -> ContractPerson:
    for person in CONTRACT_DATASET:
        if person.email == email:
            return person
    raise KeyError(email)


class UserDirectoryContract:
    pytestmark = pytest.mark.keystone_contract

    def test_name_and_capabilities(
        self,
        keystone_directory_factory: Callable[[], Awaitable[UserDirectory]],
    ):
        test_cls = type(self)

        async def body(directory: UserDirectory) -> None:
            assert _NAME_RE.fullmatch(directory.name), (
                f"directory name {directory.name!r} must match {_NAME_RE.pattern}"
            )
            assert directory.capabilities <= _ALLOWED_CAPABILITIES, (
                f"unknown capabilities: {directory.capabilities - _ALLOWED_CAPABILITIES}"
            )
            if "admin" in directory.capabilities:
                _require_capability_contract_class(test_cls, "admin", AdminDirectoryContract)
            if "service_accounts" in directory.capabilities:
                _require_capability_contract_class(
                    test_cls, "service_accounts", ServiceAccountDirectoryContract
                )
            if "api_keys" in directory.capabilities:
                _require_capability_contract_class(test_cls, "api_keys", ApiKeyDirectoryContract)
            if "identity_binding" in directory.capabilities:
                _require_capability_contract_class(
                    test_cls, "identity_binding", IdentityBindingDirectoryContract
                )
            if "delete" in directory.capabilities:
                _require_capability_contract_class(
                    test_cls, "delete", DeletionDirectoryContract
                )

        _run(keystone_directory_factory, body)

    def test_resolve_known_user(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            result = await directory.resolve_user("alice@example.com")
            assert result.exists is True
            assert result.is_blocked is False
            assert set(result.roles) == set(_person("alice@example.com").roles)

        _run(keystone_directory_factory, body)

    def test_resolve_unknown_user(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            try:
                result = await directory.resolve_user("nobody@example.com")
            except Exception as exc:
                raise AssertionError(
                    "resolve_user('nobody@example.com') must return exists=False, "
                    f"got {type(exc).__name__}: {exc}"
                ) from exc
            assert result.exists is False, (
                "resolve_user('nobody@example.com') must return exists=False, "
                f"got exists={result.exists}"
            )

        _run(keystone_directory_factory, body)

    def test_resolve_blocked_user(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            result = await directory.resolve_user("carol@example.com")
            assert result.exists is True
            assert result.is_blocked is True

        _run(keystone_directory_factory, body)

    def test_resolve_normalizes_email(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            result = await directory.resolve_user(" Alice@Example.COM ")
            assert result.exists is True, (
                "resolve_user must normalize email (strip and lower-case); "
                "' Alice@Example.COM ' should match alice@example.com"
            )

        _run(keystone_directory_factory, body)

    def test_resolve_unknown_service_without_capability(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            if "service_accounts" in directory.capabilities:
                return
            result = await directory.resolve_user("svc:no-such")
            assert result.exists is False, (
                "resolve_user('svc:no-such') must return exists=False when "
                "service_accounts capability is not declared"
            )

        _run(keystone_directory_factory, body)

    def test_list_users_defaults(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            users = await directory.list_users()
            emails = {u.email for u in users}
            assert "carol@example.com" not in emails
            assert "alice@example.com" in emails
            assert "bob@example.com" in emails

        _run(keystone_directory_factory, body)

    def test_list_users_blocked_filter(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            users = await directory.list_users(is_blocked=True)
            emails = [u.email for u in users]
            assert emails == ["carol@example.com"]

        _run(keystone_directory_factory, body)

    def test_list_users_role_filter(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            users = await directory.list_users(role="member")
            emails = {u.email for u in users}
            assert emails == {"bob@example.com"}

        _run(keystone_directory_factory, body)

    def test_list_users_email_contains(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            users = await directory.list_users(email_contains="ali")
            assert [u.email for u in users] == ["alice@example.com"]

        _run(keystone_directory_factory, body)

    def test_list_users_lowercase_emails(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            users = await directory.list_users(is_blocked=None)
            for record in users:
                assert record.email == record.email.lower(), (
                    f"list_users() must return lower-case emails, got {record.email!r}"
                )

        _run(keystone_directory_factory, body)

    def test_user_record_to_dict_keys(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        expected_keys = frozenset(
            {
                "email",
                "full_name",
                "roles",
                "is_blocked",
                "created_at",
                "updated_at",
                "created_by",
                "note",
            }
        )

        async def body(directory: UserDirectory) -> None:
            users = await directory.list_users(is_blocked=None)
            assert users, "contract dataset must not be empty"
            for record in users:
                keys = frozenset(record.to_dict())
                assert keys == expected_keys, (
                    f"UserRecord.to_dict() must expose exactly eight keys, got {sorted(keys)}"
                )

        _run(keystone_directory_factory, body)

    def test_ping(self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]):
        async def body(directory: UserDirectory) -> None:
            await directory.ping()

        _run(keystone_directory_factory, body)

    def test_unavailable_resolve_raises(
        self,
        request: pytest.FixtureRequest,
    ):
        factory = _require_unavailable_factory(request)

        async def body(directory: UserDirectory) -> None:
            try:
                await directory.resolve_user("alice@example.com")
            except UserDirectoryUnavailableError:
                return
            except Exception as exc:
                raise AssertionError(
                    "resolve_user must raise UserDirectoryUnavailableError when the "
                    f"directory backend is unavailable, got {type(exc).__name__}: {exc}"
                ) from exc
            raise AssertionError(
                "resolve_user must raise UserDirectoryUnavailableError when unavailable"
            )

        _run(factory, body)

    def test_unavailable_ping_raises(
        self,
        request: pytest.FixtureRequest,
    ):
        factory = _require_unavailable_factory(request)

        async def body(directory: UserDirectory) -> None:
            try:
                await directory.ping()
            except UserDirectoryUnavailableError:
                return
            except Exception as exc:
                raise AssertionError(
                    "ping() must raise UserDirectoryUnavailableError when the directory "
                    f"backend is unavailable, got {type(exc).__name__}: {exc}"
                ) from exc
            raise AssertionError("ping() must raise UserDirectoryUnavailableError when unavailable")

        _run(factory, body)


class AdminDirectoryContract(UserDirectoryContract):
    def test_create_user(self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDirectoryAdmin)
            result = await directory.create_user(
                email=" Dave@Example.COM ",
                full_name="Dave",
                roles=("member",),
                note=None,
                actor="alice@example.com",
            )
            assert result.created is True
            assert result.user.email == "dave@example.com"
            assert result.user.created_by == "alice@example.com"

        _run(keystone_directory_factory, body)

    def test_create_user_conflict(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDirectoryAdmin)
            try:
                await directory.create_user(
                    email="alice@example.com",
                    full_name="Dup",
                    roles=("member",),
                    note=None,
                    actor="alice@example.com",
                )
            except UsersError as exc:
                assert exc.code == "conflict"
            else:
                raise AssertionError("duplicate create_user must raise UsersError(code='conflict')")

        _run(keystone_directory_factory, body)

    def test_idempotent_mutations(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDirectoryAdmin)
            actor = "alice@example.com"
            grant = await directory.grant_role(email="bob@example.com", role="member", actor=actor)
            assert grant.changed is False
            revoke = await directory.revoke_role(
                email="bob@example.com", role="nonexistent-role", actor=actor
            )
            assert revoke.changed is False
            replace = await directory.replace_roles(
                email="bob@example.com", roles=("member",), actor=actor
            )
            assert replace.changed is False
            users = await directory.list_users(email_contains="bob@")
            bob_record = next(u for u in users if u.email == "bob@example.com")
            update = await directory.update_user(
                email="bob@example.com",
                full_name=bob_record.full_name,
                note=bob_record.note,
                actor=actor,
            )
            assert update.changed is False
            block = await directory.set_blocked(
                email="carol@example.com", blocked=True, actor=actor
            )
            assert block.changed is False

        _run(keystone_directory_factory, body)

    def test_last_administrator_guard(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDirectoryAdmin)
            actor = "bob@example.com"
            try:
                await directory.revoke_role(
                    email="alice@example.com", role="administrator", actor=actor
                )
            except UsersError as exc:
                assert exc.code == "last_administrator"
            else:
                raise AssertionError(
                    "revoking last administrator must raise UsersError(code='last_administrator')"
                )
            try:
                await directory.set_blocked(email="alice@example.com", blocked=True, actor=actor)
            except UsersError as exc:
                assert exc.code == "last_administrator"
            else:
                raise AssertionError(
                    "blocking last administrator must raise UsersError(code='last_administrator')"
                )
            try:
                await directory.replace_roles(
                    email="alice@example.com", roles=("member",), actor=actor
                )
            except UsersError as exc:
                assert exc.code == "last_administrator"
            else:
                raise AssertionError(
                    "demoting last administrator must raise UsersError(code='last_administrator')"
                )

        _run(keystone_directory_factory, body)

    def test_self_admin_mutation_forbidden(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDirectoryAdmin)
            await directory.create_user(
                email="dave@example.com",
                full_name="Dave Admin",
                roles=("administrator",),
                note=None,
                actor="alice@example.com",
            )
            actor = "dave@example.com"
            for action in (
                lambda: directory.set_blocked(email=actor, blocked=True, actor=actor),
                lambda: directory.revoke_role(email=actor, role="administrator", actor=actor),
            ):
                try:
                    await action()
                except UsersError as exc:
                    assert exc.code == "self_admin_mutation_forbidden"
                else:
                    raise AssertionError(
                        "administrator mutating own admin access must raise "
                        "UsersError(code='self_admin_mutation_forbidden')"
                    )

        _run(keystone_directory_factory, body)

    def test_unknown_email_mutations(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDirectoryAdmin)
            actor = "alice@example.com"
            email = "ghost@example.com"
            calls = (
                lambda: directory.update_user(email=email, full_name="X", note=None, actor=actor),
                lambda: directory.set_blocked(email=email, blocked=True, actor=actor),
                lambda: directory.grant_role(email=email, role="member", actor=actor),
                lambda: directory.revoke_role(email=email, role="member", actor=actor),
                lambda: directory.replace_roles(email=email, roles=("member",), actor=actor),
            )
            for call in calls:
                try:
                    await call()
                except UsersError as exc:
                    assert exc.code == "user_not_found"
                else:
                    raise AssertionError(
                        "mutation for unknown email must raise UsersError(code='user_not_found')"
                    )

        _run(keystone_directory_factory, body)

    def test_block_visible_in_resolve(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDirectoryAdmin)
            await directory.set_blocked(
                email="bob@example.com", blocked=True, actor="alice@example.com"
            )
            result = await directory.resolve_user("bob@example.com")
            assert result.is_blocked is True

        _run(keystone_directory_factory, body)

    def test_invalid_role_name(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDirectoryAdmin)
            actor = "alice@example.com"
            for role in ("", "x" * 65):
                try:
                    await directory.grant_role(email="bob@example.com", role=role, actor=actor)
                except UsersError as exc:
                    assert exc.code == "validation_error"
                else:
                    raise AssertionError(
                        "invalid role name must raise UsersError(code='validation_error')"
                    )

        _run(keystone_directory_factory, body)


class ServiceAccountDirectoryContract:
    pytestmark = pytest.mark.keystone_contract

    def test_service_account_lifecycle(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ServiceAccountDirectory)
            actor = "alice@example.com"
            created = await directory.create_service_account(
                name="ci-bot",
                description="CI",
                roles=("member",),
                actor=actor,
            )
            assert created.created is True
            resolved = await directory.resolve_user(service_subject("ci-bot"))
            assert resolved.exists is True
            assert resolved.subject_type == "service"

        _run(keystone_directory_factory, body)

    def test_service_account_administrator_role_rejected(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ServiceAccountDirectory)
            try:
                await directory.create_service_account(
                    name="bad-admin",
                    description=None,
                    roles=("administrator",),
                    actor="alice@example.com",
                )
            except UsersError as exc:
                assert exc.code == "validation_error"
            else:
                raise AssertionError("administrator role on service account must be rejected")

        _run(keystone_directory_factory, body)

    def test_service_account_bad_name(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ServiceAccountDirectory)
            try:
                await directory.create_service_account(
                    name="X",
                    description=None,
                    roles=("member",),
                    actor="alice@example.com",
                )
            except UsersError as exc:
                assert exc.code == "validation_error"
            else:
                raise AssertionError("invalid service account name must raise validation_error")

        _run(keystone_directory_factory, body)

    def test_service_account_duplicate(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ServiceAccountDirectory)
            actor = "alice@example.com"
            await directory.create_service_account(
                name="ci-bot",
                description=None,
                roles=("member",),
                actor=actor,
            )
            try:
                await directory.create_service_account(
                    name="ci-bot",
                    description=None,
                    roles=("member",),
                    actor=actor,
                )
            except UsersError as exc:
                assert exc.code == "conflict"
            else:
                raise AssertionError("duplicate service account must raise conflict")

        _run(keystone_directory_factory, body)

    def test_service_account_block_and_list(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ServiceAccountDirectory)
            actor = "alice@example.com"
            await directory.create_service_account(
                name="ci-bot",
                description=None,
                roles=("member",),
                actor=actor,
            )
            await directory.update_service_account(
                name="ci-bot",
                is_blocked=True,
                actor=actor,
            )
            listed = await directory.list_service_accounts()
            names = {a.name for a in listed}
            assert "ci-bot" not in names
            blocked = await directory.list_service_accounts(is_blocked=True)
            assert [a.name for a in blocked] == ["ci-bot"]

        _run(keystone_directory_factory, body)


class ApiKeyDirectoryContract:
    pytestmark = pytest.mark.keystone_contract

    def test_issue_and_verify_human_key(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ApiKeyDirectory)
            issued = await directory.issue_api_key(
                subject="bob@example.com",
                label="bob-key",
                expires_in_days=None,
                actor="alice@example.com",
            )
            verification = await directory.verify_api_key(issued.key)
            assert verification is not None
            assert verification.subject == "bob@example.com"
            assert verification.subject_type == "human"

        _run(keystone_directory_factory, body)

    def test_list_api_keys_never_leaks_secret(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ApiKeyDirectory)
            issued = await directory.issue_api_key(
                subject="bob@example.com",
                label=None,
                expires_in_days=None,
                actor="alice@example.com",
            )
            keys = await directory.list_api_keys()
            secret = issued.key
            for record in keys:
                payload = record.to_dict()
                for value in payload.values():
                    if isinstance(value, str) and secret in value:
                        raise AssertionError("list_api_keys() must not expose the secret material")
                assert secret not in str(payload)

        _run(keystone_directory_factory, body)

    def test_verify_bad_and_revoked_keys(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ApiKeyDirectory)
            issued = await directory.issue_api_key(
                subject="bob@example.com",
                label=None,
                expires_in_days=None,
                actor="alice@example.com",
            )
            assert await directory.verify_api_key("not-a-key") is None
            assert await directory.verify_api_key("ksk_deadbeef_" + ("x" * 43)) is None
            await directory.revoke_api_key(key_id=issued.record.key_id, actor="alice@example.com")
            assert await directory.verify_api_key(issued.key) is None

        _run(keystone_directory_factory, body)

    def test_revoke_idempotent(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ApiKeyDirectory)
            issued = await directory.issue_api_key(
                subject="bob@example.com",
                label=None,
                expires_in_days=None,
                actor="alice@example.com",
            )
            await directory.revoke_api_key(key_id=issued.record.key_id, actor="alice@example.com")
            _record, changed = await directory.revoke_api_key(
                key_id=issued.record.key_id, actor="alice@example.com"
            )
            assert changed is False

        _run(keystone_directory_factory, body)

    def test_issue_for_blocked_user(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ApiKeyDirectory)
            try:
                await directory.issue_api_key(
                    subject="carol@example.com",
                    label=None,
                    expires_in_days=None,
                    actor="alice@example.com",
                )
            except UsersError as exc:
                assert exc.code == "validation_error"
            else:
                raise AssertionError("issuing a key for a blocked user must raise validation_error")

        _run(keystone_directory_factory, body)

    def test_issue_zero_expiry_rejected(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ApiKeyDirectory)
            try:
                await directory.issue_api_key(
                    subject="bob@example.com",
                    label=None,
                    expires_in_days=0,
                    actor="alice@example.com",
                )
            except UsersError as exc:
                assert exc.code == "validation_error"
            else:
                raise AssertionError("expires_in_days=0 must raise validation_error")

        _run(keystone_directory_factory, body)


class IdentityBindingDirectoryContract:
    pytestmark = pytest.mark.keystone_contract

    def test_bind_and_rebind_idempotent(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, IdentityBindingDirectory)
            first = await directory.bind_identity(
                email="bob@example.com",
                issuer="https://idp.test",
                subject="sub-1",
            )
            second = await directory.bind_identity(
                email="bob@example.com",
                issuer="https://idp.test",
                subject="sub-2",
            )
            assert second == first

        _run(keystone_directory_factory, body)

    def test_same_pair_for_another_person_is_conflict(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, IdentityBindingDirectory)
            await directory.bind_identity(
                email="alice@example.com",
                issuer="https://idp.test",
                subject="shared",
            )
            try:
                await directory.bind_identity(
                    email="bob@example.com",
                    issuer="https://idp.test",
                    subject="shared",
                )
            except UsersError as exc:
                assert exc.code == "identity_binding_conflict"
            else:
                raise AssertionError("duplicate pair must raise identity_binding_conflict")

        _run(keystone_directory_factory, body)

    def test_unknown_email_is_not_found(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, IdentityBindingDirectory)
            try:
                await directory.bind_identity(
                    email="missing@example.com",
                    issuer="https://idp.test",
                    subject="sub",
                )
            except UsersError as exc:
                assert exc.code == "user_not_found"
            else:
                raise AssertionError("unknown email must raise user_not_found")

        _run(keystone_directory_factory, body)

    def test_clear_binding(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, IdentityBindingDirectory)
            await directory.bind_identity(
                email="bob@example.com",
                issuer="https://idp.test",
                subject="sub-clear",
            )
            assert await directory.clear_identity_binding(
                email="bob@example.com", actor="alice@example.com"
            )
            assert await directory.get_identity_binding("bob@example.com") is None
            assert not await directory.clear_identity_binding(
                email="bob@example.com", actor="alice@example.com"
            )

        _run(keystone_directory_factory, body)


class DeletionDirectoryContract:
    pytestmark = pytest.mark.keystone_contract

    def test_delete_anonymize_and_hard_delete(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDeletionDirectory)
            actor = "alice@example.com"
            target = "carol@example.com"
            pseudonym = hash_subject(target, salt="contract-salt") or ""
            result = await directory.delete_user(
                email=target,
                actor=actor,
                mode="anonymize",
                pseudonym=pseudonym,
            )
            assert result.mode == "anonymize"
            assert result.pseudonym == pseudonym
            resolved = await directory.resolve_user(target)
            assert resolved.exists is False
            rows = await directory.list_users()
            assert all(row.email != f"deleted:{pseudonym}" for row in rows)
            await directory.delete_user(
                email="bob@example.com",
                actor=actor,
                mode="delete",
                pseudonym=hash_subject("bob@example.com", salt="contract-salt") or "",
            )
            assert (await directory.resolve_user("bob@example.com")).exists is False

        _run(keystone_directory_factory, body)

    def test_repeat_delete_is_not_found(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDeletionDirectory)
            target = "carol@example.com"
            pseudonym = hash_subject(target, salt="contract-salt") or ""
            await directory.delete_user(
                email=target,
                actor="alice@example.com",
                mode="delete",
                pseudonym=pseudonym,
            )
            try:
                await directory.delete_user(
                    email=target,
                    actor="alice@example.com",
                    mode="delete",
                    pseudonym=pseudonym,
                )
            except UsersError as exc:
                assert exc.code == "user_not_found"
            else:
                raise AssertionError("repeat delete must raise user_not_found")

        _run(keystone_directory_factory, body)

    def test_last_administrator_guard(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDeletionDirectory)
            try:
                await directory.delete_user(
                    email="alice@example.com",
                    actor="bob@example.com",
                    mode="delete",
                    pseudonym="sub_deadbeef",
                )
            except UsersError as exc:
                assert exc.code == "last_administrator"
            else:
                raise AssertionError("deleting last administrator must raise last_administrator")

        _run(keystone_directory_factory, body)

    def test_self_delete_forbidden(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDeletionDirectory)
            try:
                await directory.delete_user(
                    email="bob@example.com",
                    actor="bob@example.com",
                    mode="delete",
                    pseudonym="sub_deadbeef",
                )
            except UsersError as exc:
                assert exc.code == "self_admin_mutation_forbidden"
            else:
                raise AssertionError("self delete must raise self_admin_mutation_forbidden")

        _run(keystone_directory_factory, body)

    def test_anonymized_record_hidden(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDeletionDirectory)
            target = "bob@example.com"
            pseudonym = hash_subject(target, salt="contract-salt") or ""
            await directory.delete_user(
                email=target,
                actor="alice@example.com",
                mode="anonymize",
                pseudonym=pseudonym,
            )
            assert (await directory.resolve_user(target)).exists is False
            listed = await directory.list_users(is_blocked=None)
            assert all(not row.email.startswith("deleted:") for row in listed)

        _run(keystone_directory_factory, body)

    def test_delete_bumps_revision(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            from keystone_mcp.user_directory.local import LocalUserDirectory

            if not isinstance(directory, LocalUserDirectory):
                return
            bumps: list[bool] = []
            directory._store.add_change_listener(bumps.append)
            pseudonym = hash_subject("carol@example.com", salt="contract-salt") or ""
            await directory.delete_user(
                email="carol@example.com",
                actor="alice@example.com",
                mode="delete",
                pseudonym=pseudonym,
            )
            assert bumps == [True]

        _run(keystone_directory_factory, body)


_CHECKS06_DOC = (
    "Checks added in 0.6.0; opt in by mixing this class in. "
    "They become part of the main contract classes in 2.0."
)

_KNOWN_UNAVAILABLE_CODES = frozenset({"catalog_unavailable", "catalog_timeout"})


def _api_key_secret_suffix(key_material: str) -> str:
    if not key_material.startswith("ksk_"):
        return key_material
    rest = key_material[4:]
    sep = rest.find("_")
    if sep < 0:
        return rest
    return rest[sep + 1 :]


class UserDirectoryChecks06:
    __doc__ = _CHECKS06_DOC

    pytestmark = pytest.mark.keystone_contract

    def test_unavailable_error_code_is_known(self, request: pytest.FixtureRequest):
        factory = _require_unavailable_factory(request)

        async def body(directory: UserDirectory) -> None:
            try:
                await directory.resolve_user("alice@example.com")
            except UserDirectoryUnavailableError as exc:
                assert exc.code in _KNOWN_UNAVAILABLE_CODES, (
                    f"UserDirectoryUnavailableError.code must be one of "
                    f"{sorted(_KNOWN_UNAVAILABLE_CODES)}, got {exc.code!r}"
                )
                return
            except Exception as exc:
                raise AssertionError(
                    "resolve_user must raise UserDirectoryUnavailableError when unavailable, "
                    f"got {type(exc).__name__}: {exc}"
                ) from exc
            raise AssertionError(
                "resolve_user must raise UserDirectoryUnavailableError when unavailable"
            )

        _run(factory, body)

    def test_list_users_excludes_service_accounts(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            if "service_accounts" not in directory.capabilities:
                pytest.skip("directory does not declare service_accounts")
            assert isinstance(directory, ServiceAccountDirectory)
            await directory.create_service_account(
                name="ci-bot",
                description=None,
                roles=("member",),
                actor="alice@example.com",
            )
            users = await directory.list_users(is_blocked=None)
            for record in users:
                assert not record.email.startswith("svc:"), (
                    "list_users() must not include service account subjects"
                )

        _run(keystone_directory_factory, body)


class AdminDirectoryChecks06:
    __doc__ = _CHECKS06_DOC

    pytestmark = pytest.mark.keystone_contract

    def test_blocked_second_admin_does_not_count(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDirectoryAdmin)
            actor = "alice@example.com"
            await directory.create_user(
                email="dave@example.com",
                full_name="Dave Admin",
                roles=("administrator",),
                note=None,
                actor=actor,
            )
            await directory.set_blocked(email="dave@example.com", blocked=True, actor=actor)
            bob = "bob@example.com"
            try:
                await directory.revoke_role(
                    email="alice@example.com", role="administrator", actor=bob
                )
            except UsersError as exc:
                assert exc.code == "last_administrator"
            else:
                raise AssertionError(
                    "revoking last active administrator must raise last_administrator "
                    "when a blocked administrator remains"
                )

        _run(keystone_directory_factory, body)

    def test_self_admin_via_replace_roles_forbidden(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDirectoryAdmin)
            for actor in ("alice@example.com", " Alice@Example.COM "):
                try:
                    await directory.replace_roles(
                        email="alice@example.com", roles=("member",), actor=actor
                    )
                except UsersError as exc:
                    assert exc.code == "self_admin_mutation_forbidden"
                else:
                    raise AssertionError(
                        "administrator demoting self via replace_roles must raise "
                        "self_admin_mutation_forbidden"
                    )

        _run(keystone_directory_factory, body)

    def test_mutations_normalize_email(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDirectoryAdmin)
            actor = "alice@example.com"
            await directory.update_user(
                email=" Bob@Example.COM ",
                full_name="Bob Updated",
                note=None,
                actor=actor,
            )
            await directory.set_blocked(email=" Bob@Example.COM ", blocked=False, actor=actor)
            await directory.grant_role(email=" Bob@Example.COM ", role="member", actor=actor)
            users = await directory.list_users(email_contains="bob@")
            assert any(u.email == "bob@example.com" for u in users)
            try:
                await directory.create_user(
                    email="ALICE@Example.com",
                    full_name="Dup",
                    roles=("member",),
                    note=None,
                    actor=actor,
                )
            except UsersError as exc:
                assert exc.code == "conflict"
            else:
                raise AssertionError("duplicate email with different casing must raise conflict")

        _run(keystone_directory_factory, body)

    def test_invalid_input_raises_users_error(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDirectoryAdmin)
            actor = "alice@example.com"
            cases: tuple[tuple[str, Callable[[], Awaitable[Any]]], ...] = (
                (
                    "validation_error",
                    lambda: directory.create_user(
                        email="not-an-email",
                        full_name="Bad",
                        roles=("member",),
                        note=None,
                        actor=actor,
                    ),
                ),
                (
                    "validation_error",
                    lambda: directory.grant_role(email="bob@example.com", role="", actor=actor),
                ),
                (
                    "user_not_found",
                    lambda: directory.grant_role(
                        email="ghost@example.com", role="member", actor=actor
                    ),
                ),
            )
            for expected_code, call in cases:
                try:
                    await call()
                except UsersError as exc:
                    assert exc.code == expected_code
                except (ValueError, KeyError, TypeError) as exc:
                    raise AssertionError(
                        f"invalid input must raise UsersError, not {type(exc).__name__}"
                    ) from exc
                else:
                    raise AssertionError("invalid input must raise UsersError")

        _run(keystone_directory_factory, body)

    def test_mutation_bumps_revision(
        self,
        keystone_directory_factory: Callable[[], Awaitable[UserDirectory]],
        request: pytest.FixtureRequest,
    ):
        try:
            revision_probe = request.getfixturevalue("keystone_revision_probe")
        except pytest.FixtureLookupError:
            pytest.skip("keystone_revision_probe fixture not provided")

        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, UserDirectoryAdmin)
            before = await revision_probe()
            users = await directory.list_users(email_contains="bob@")
            bob = next(u for u in users if u.email == "bob@example.com")
            await directory.update_user(
                email="bob@example.com",
                full_name=bob.full_name,
                note="contract-revision-probe",
                actor="alice@example.com",
            )
            after = await revision_probe()
            assert after > before, "mutations must bump the directory revision"

        _run(keystone_directory_factory, body)


class ServiceAccountDirectoryChecks06:
    __doc__ = _CHECKS06_DOC

    pytestmark = pytest.mark.keystone_contract

    def test_update_unknown_service_account(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ServiceAccountDirectory)
            try:
                await directory.update_service_account(
                    name="missing-bot",
                    description="x",
                    actor="alice@example.com",
                )
            except UsersError as exc:
                assert exc.code == "user_not_found"
            else:
                raise AssertionError("unknown service account must raise user_not_found")

        _run(keystone_directory_factory, body)

    def test_service_account_unknown_role_rejected(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ServiceAccountDirectory)
            actor = "alice@example.com"
            await directory.create_service_account(
                name="ci-bot",
                description=None,
                roles=("member",),
                actor=actor,
            )
            try:
                await directory.update_service_account(
                    name="ci-bot",
                    roles=("",),
                    actor=actor,
                )
            except UsersError as exc:
                assert exc.code == "validation_error"
            else:
                raise AssertionError("invalid service account role must raise validation_error")

        _run(keystone_directory_factory, body)

    def test_resolve_blocked_service_account(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ServiceAccountDirectory)
            actor = "alice@example.com"
            await directory.create_service_account(
                name="ci-bot",
                description=None,
                roles=("member",),
                actor=actor,
            )
            await directory.update_service_account(
                name="ci-bot",
                is_blocked=True,
                actor=actor,
            )
            result = await directory.resolve_user(service_subject("ci-bot"))
            assert result.exists is True
            assert result.is_blocked is True

        _run(keystone_directory_factory, body)


class ApiKeyDirectoryChecks06:
    __doc__ = _CHECKS06_DOC

    pytestmark = pytest.mark.keystone_contract

    def test_expired_key_is_not_verified(
        self,
        keystone_directory_factory: Callable[[], Awaitable[UserDirectory]],
        request: pytest.FixtureRequest,
    ):
        try:
            advance_clock = request.getfixturevalue("keystone_advance_clock")
        except pytest.FixtureLookupError:
            pytest.skip("keystone_advance_clock fixture not provided")

        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ApiKeyDirectory)
            issued = await directory.issue_api_key(
                subject="bob@example.com",
                label="expiring",
                expires_in_days=1,
                actor="alice@example.com",
            )
            advance_clock(86400 * 2)
            assert await directory.verify_api_key(issued.key) is None

        _run(keystone_directory_factory, body)

    def test_service_account_key_verifies_as_service(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            if "service_accounts" not in directory.capabilities:
                pytest.skip("directory does not declare service_accounts")
            assert isinstance(directory, ApiKeyDirectory)
            assert isinstance(directory, ServiceAccountDirectory)
            actor = "alice@example.com"
            await directory.create_service_account(
                name="ci-bot",
                description=None,
                roles=("member",),
                actor=actor,
            )
            issued = await directory.issue_api_key(
                subject=service_subject("ci-bot"),
                label="bot-key",
                expires_in_days=None,
                actor=actor,
            )
            verification = await directory.verify_api_key(issued.key)
            assert verification is not None
            assert verification.subject_type == "service"

        _run(keystone_directory_factory, body)

    def test_list_never_leaks_secret_part(
        self, keystone_directory_factory: Callable[[], Awaitable[UserDirectory]]
    ):
        async def body(directory: UserDirectory) -> None:
            assert isinstance(directory, ApiKeyDirectory)
            issued = await directory.issue_api_key(
                subject="bob@example.com",
                label=None,
                expires_in_days=None,
                actor="alice@example.com",
            )
            secret_suffix = _api_key_secret_suffix(issued.key)
            assert secret_suffix
            keys = await directory.list_api_keys()
            for record in keys:
                payload = record.to_dict()
                for value in payload.values():
                    if isinstance(value, str) and secret_suffix in value:
                        raise AssertionError(
                            "list_api_keys() must not expose the secret part of the key material"
                        )

        _run(keystone_directory_factory, body)
