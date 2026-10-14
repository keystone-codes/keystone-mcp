"""Executable contract tests for ``UserDirectory`` implementations."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import pytest

from keystone_mcp.user_directory.errors import (
    UserDirectoryUnavailableError,
    UsersError,
)
from keystone_mcp.user_directory.protocol import (
    ApiKeyDirectory,
    ServiceAccountDirectory,
    UserDirectory,
    UserDirectoryAdmin,
)
from keystone_mcp.user_directory.types import service_subject

_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_ALLOWED_CAPABILITIES = frozenset({"admin", "service_accounts", "api_keys"})
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
