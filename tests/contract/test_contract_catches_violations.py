"""Verify contract suites fail on deliberately broken implementations."""

from __future__ import annotations

import pytest

pytest_plugins = ["pytester"]


def test_broken_directory_fails_resolve_contract(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
from collections.abc import Awaitable, Callable
import pytest
from keystone_mcp.contract_tests import UserDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory
from keystone_mcp.user_directory.types import UserResolveResult

class BrokenDirectory(InMemoryUserDirectory):
    async def resolve_user(self, subject: str) -> UserResolveResult:
        if "@" in subject and subject.strip().lower() not in self._users:
            raise KeyError(subject)
        return await super().resolve_user(subject)

@pytest.fixture
def keystone_directory_factory() -> Callable[[], Awaitable[UserDirectory]]:
    async def factory() -> UserDirectory:
        directory = BrokenDirectory()
        await seed_contract_dataset(directory)
        return directory
    return factory

class TestBroken(UserDirectoryContract):
    pass
"""
    )
    pytester.makeconftest('pytest_plugins = ["keystone_mcp.contract_tests"]')
    result = pytester.runpytest("-p", "keystone_mcp.contract_tests", "-q")
    assert result.parseoutcomes().get("failed", 0) >= 1


def test_no_normalize_directory_fails(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
from collections.abc import Awaitable, Callable
import pytest
from keystone_mcp.contract_tests import UserDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory
class NoNormalizeDirectory(InMemoryUserDirectory):
    async def resolve_user(self, subject: str):
        from keystone_mcp.user_directory.types import UserResolveResult, parse_service_subject

        if parse_service_subject(subject.strip().lower()) is not None:
            return await super().resolve_user(subject)
        key = subject.strip()
        entry = self._users.get(key)
        if entry is None:
            return UserResolveResult(exists=False, roles=(), is_blocked=False)
        return UserResolveResult(exists=True, roles=entry.roles, is_blocked=entry.is_blocked)

@pytest.fixture
def keystone_directory_factory():
    async def factory():
        directory = NoNormalizeDirectory()
        await seed_contract_dataset(directory)
        return directory
    return factory

class TestBroken(UserDirectoryContract):
    pass
"""
    )
    pytester.makeconftest('pytest_plugins = ["keystone_mcp.contract_tests"]')
    result = pytester.runpytest("-p", "keystone_mcp.contract_tests", "-q")
    assert result.parseoutcomes().get("failed", 0) >= 1


def test_lenient_oidc_fails(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
from collections.abc import Callable
import pytest
from keystone_mcp.contract_tests import OidcLoginProviderContract
from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.login.oidc import OidcLoginProvider
from keystone_mcp.login.protocol import LoginIdentity, RedirectLoginProvider

class LenientOidc(OidcLoginProvider):
    async def complete(self, *, params, callback_url, attempt):
        if params.get("error"):
            from keystone_mcp.login.protocol import LoginRejected
            raise LoginRejected("request_invalid")
        return LoginIdentity(email="alice@example.com", provider=self.name, interactive=True)

@pytest.fixture
def keystone_oidc_provider_factory() -> Callable[[FakeOidcIssuer], RedirectLoginProvider]:
    def factory(issuer: FakeOidcIssuer) -> RedirectLoginProvider:
        return LenientOidc(
            issuer.config(name="lenient"),
            http_client_factory=issuer.http_client,
            cache_ttl_seconds=0.0,
        )
    return factory

class TestLenient(OidcLoginProviderContract):
    pass
"""
    )
    pytester.makeconftest('pytest_plugins = ["keystone_mcp.contract_tests"]')
    result = pytester.runpytest("-p", "keystone_mcp.contract_tests", "-q")
    assert result.ret != 0
    assert result.parseoutcomes().get("failed", 0) >= 1


def test_admin_capability_without_admin_contract_fails(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
from collections.abc import Awaitable, Callable
import pytest
from keystone_mcp.contract_tests import UserDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory

class Adminless(InMemoryUserDirectory):
    @property
    def capabilities(self):
        return frozenset({"admin"})

@pytest.fixture
def keystone_directory_factory() -> Callable[[], Awaitable[UserDirectory]]:
    async def factory() -> UserDirectory:
        directory = Adminless()
        await seed_contract_dataset(directory)
        return directory
    return factory

class TestBroken(UserDirectoryContract):
    pass
"""
    )
    pytester.makeconftest('pytest_plugins = ["keystone_mcp.contract_tests"]')
    result = pytester.runpytest("-p", "keystone_mcp.contract_tests", "-q")
    assert result.parseoutcomes().get("failed", 0) >= 1
    assert "inherit AdminDirectoryContract" in result.stdout.str()


def test_lenient_marker_skips_capability_match_with_reason(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
from collections.abc import Awaitable, Callable
import pytest
from keystone_mcp.contract_tests import UserDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory

class Adminless(InMemoryUserDirectory):
    @property
    def capabilities(self):
        return frozenset({"admin"})

@pytest.fixture
def keystone_directory_factory():
    async def factory():
        directory = Adminless()
        await seed_contract_dataset(directory)
        return directory
    return factory

@pytest.mark.keystone_contract_lenient(reason="demo plugin without admin contract suite")
class TestBroken(UserDirectoryContract):
    pass
"""
    )
    pytester.makeconftest('pytest_plugins = ["keystone_mcp.contract_tests"]')
    result = pytester.runpytest("-p", "keystone_mcp.contract_tests", "-q", "-rs")
    assert result.parseoutcomes().get("skipped", 0) >= 1
    assert "demo plugin without admin contract suite" in result.stdout.str()


def test_overwriting_identity_binding_fails_contract(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
from collections.abc import Awaitable, Callable
import pytest
from keystone_mcp.contract_tests import IdentityBindingDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory
from keystone_mcp.user_directory.types import IdentityBinding
from datetime import UTC, datetime
from support.users_store import make_users_store

class OverwritingBinding(LocalUserDirectory):
    async def bind_identity(self, *, email: str, issuer: str, subject: str) -> IdentityBinding:
        return IdentityBinding(
            issuer=issuer,
            subject=subject,
            bound_at=datetime.now(UTC),
        )

@pytest.fixture
def keystone_directory_factory(tmp_path) -> Callable[[], Awaitable[UserDirectory]]:
    async def factory() -> UserDirectory:
        store, _revision = await make_users_store(tmp_path / "binding")
        directory = OverwritingBinding(store)
        await seed_contract_dataset(directory)
        return directory
    return factory

class TestBroken(IdentityBindingDirectoryContract):
    pass
"""
    )
    pytester.makeconftest('pytest_plugins = ["keystone_mcp.contract_tests"]')
    result = pytester.runpytest("-p", "keystone_mcp.contract_tests", "-q")
    assert result.parseoutcomes().get("failed", 0) >= 1


def test_lenient_marker_without_reason_fails(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
from collections.abc import Awaitable, Callable
import pytest
from keystone_mcp.contract_tests import UserDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.memory import InMemoryUserDirectory

class Adminless(InMemoryUserDirectory):
    @property
    def capabilities(self):
        return frozenset({"admin"})

@pytest.fixture
def keystone_directory_factory():
    async def factory():
        directory = Adminless()
        await seed_contract_dataset(directory)
        return directory
    return factory

@pytest.mark.keystone_contract_lenient
class TestBroken(UserDirectoryContract):
    pass
"""
    )
    pytester.makeconftest('pytest_plugins = ["keystone_mcp.contract_tests"]')
    result = pytester.runpytest("-p", "keystone_mcp.contract_tests", "-q")
    assert result.parseoutcomes().get("failed", 0) >= 1


def test_deletion_that_allows_last_administrator_fails_contract(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
from collections.abc import Awaitable, Callable
import pytest
from keystone_mcp.contract_tests import DeletionDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory
from keystone_mcp.user_directory.types import DeletionResult, DeleteMode

class PermissiveDelete(InMemoryUserDirectory):
    async def delete_user(
        self, *, email: str, actor: str, mode: DeleteMode, pseudonym: str
    ) -> DeletionResult:
        from keystone_mcp.user_directory.util import normalize_email

        normalized = normalize_email(email)
        entry = self._users.pop(normalized, None)
        if entry is None:
            from keystone_mcp.user_directory.errors import UserNotFoundError
            raise UserNotFoundError(normalized)
        return DeletionResult(
            email=normalized,
            mode=mode,
            pseudonym=pseudonym,
            roles_before=tuple(sorted(entry.roles)),
            api_keys_revoked=0,
            references_rewritten=0,
        )

@pytest.fixture
def keystone_directory_factory() -> Callable[[], Awaitable[UserDirectory]]:
    async def factory() -> UserDirectory:
        directory = PermissiveDelete()
        await seed_contract_dataset(directory)
        return directory
    return factory

class TestBroken(DeletionDirectoryContract):
    pass
"""
    )
    pytester.makeconftest('pytest_plugins = ["keystone_mcp.contract_tests"]')
    result = pytester.runpytest("-p", "keystone_mcp.contract_tests", "-q")
    assert result.parseoutcomes().get("failed", 0) >= 1


def test_missing_unavailable_fixture_fails(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
from collections.abc import Awaitable, Callable
import pytest
from keystone_mcp.contract_tests import UserDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory

@pytest.fixture
def keystone_directory_factory() -> Callable[[], Awaitable[UserDirectory]]:
    async def factory() -> UserDirectory:
        directory = InMemoryUserDirectory()
        await seed_contract_dataset(directory)
        return directory
    return factory

class TestBroken(UserDirectoryContract):
    pass
"""
    )
    pytester.makeconftest('pytest_plugins = ["keystone_mcp.contract_tests"]')
    result = pytester.runpytest("-p", "keystone_mcp.contract_tests", "-q")
    assert result.parseoutcomes().get("failed", 0) >= 1
    assert "keystone_unavailable_directory_factory" in result.stdout.str()


def _run_contract_pytester(pytester: pytest.Pytester) -> pytest.RunResult:
    pytester.makeconftest('pytest_plugins = ["keystone_mcp.contract_tests"]')
    return pytester.runpytest("-p", "keystone_mcp.contract_tests", "-q")


def test_blocked_second_admin_catches_counting_blocked_admins(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
from collections.abc import Awaitable, Callable
import pytest
from keystone_mcp.contract_tests import AdminDirectoryChecks06, AdminDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory
from keystone_mcp.users.roles import ROLE_ADMINISTRATOR

class CountingBlockedAdmins(InMemoryUserDirectory):
    @property
    def capabilities(self):
        return frozenset({"admin"})

    def _active_administrators(self):
        return {
            email
            for email, entry in self._users.items()
            if not email.startswith("deleted:") and ROLE_ADMINISTRATOR in entry.roles
        }

@pytest.fixture
def keystone_directory_factory():
    async def factory():
        directory = CountingBlockedAdmins()
        await seed_contract_dataset(directory)
        return directory
    return factory

class TestBroken(AdminDirectoryContract, AdminDirectoryChecks06):
    pass
"""
    )
    result = _run_contract_pytester(pytester)
    assert result.parseoutcomes().get("failed", 0) >= 1
    assert "test_blocked_second_admin_does_not_count" in result.stdout.str()


def test_new_checks_do_not_run_without_opt_in(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
from collections.abc import Awaitable, Callable
import pytest
from keystone_mcp.contract_tests import AdminDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory
from keystone_mcp.users.roles import ROLE_ADMINISTRATOR

class CountingBlockedAdmins(InMemoryUserDirectory):
    @property
    def capabilities(self):
        return frozenset({"admin"})

    def _active_administrators(self):
        return {
            email
            for email, entry in self._users.items()
            if not email.startswith("deleted:") and ROLE_ADMINISTRATOR in entry.roles
        }

@pytest.fixture
def keystone_directory_factory():
    async def factory():
        directory = CountingBlockedAdmins()
        await seed_contract_dataset(directory)
        return directory
    return factory

@pytest.fixture
def keystone_unavailable_directory_factory():
    from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError

    async def factory():
        directory = CountingBlockedAdmins()
        await seed_contract_dataset(directory)

        async def unavailable_op(*_args, **_kwargs):
            raise UserDirectoryUnavailableError("down", code="catalog_unavailable")

        directory.resolve_user = unavailable_op
        directory.ping = unavailable_op
        return directory

    return factory

class TestPasses05Only(AdminDirectoryContract):
    pass
"""
    )
    result = _run_contract_pytester(pytester)
    assert result.parseoutcomes().get("failed", 0) == 0
    assert "test_blocked_second_admin_does_not_count" not in result.stdout.str()


def test_self_admin_via_replace_roles_catches_missing_guard(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
import pytest
from keystone_mcp.contract_tests import AdminDirectoryChecks06, AdminDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.memory import InMemoryUserDirectory

class PermissiveSelfAdmin(InMemoryUserDirectory):
    async def replace_roles(self, *, email, roles, actor):
        from keystone_mcp.user_directory.types import MutationResult
        from keystone_mcp.users.roles import check_role_name

        normalized, entry = self._require(email)
        roles_before = tuple(sorted(entry.roles))
        next_roles = tuple(dict.fromkeys(check_role_name(role) for role in roles))
        entry.roles = next_roles
        return MutationResult(
            user=self._record(normalized, entry),
            changed=set(roles_before) != set(next_roles),
            roles_before=roles_before,
        )

@pytest.fixture
def keystone_directory_factory():
    async def factory():
        directory = PermissiveSelfAdmin()
        await seed_contract_dataset(directory)
        return directory
    return factory

class TestBroken(AdminDirectoryContract, AdminDirectoryChecks06):
    pass
"""
    )
    result = _run_contract_pytester(pytester)
    assert result.parseoutcomes().get("failed", 0) >= 1
    assert "test_self_admin_via_replace_roles_forbidden" in result.stdout.str()


def test_mutations_normalize_email_catches_case_sensitive_store(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
import pytest
from keystone_mcp.contract_tests import AdminDirectoryChecks06, AdminDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.memory import InMemoryUserDirectory

class CaseSensitiveStore(InMemoryUserDirectory):
    async def update_user(self, *, email, full_name, note, actor):
        key = email.strip()
        entry = self._users.get(key)
        if entry is None:
            from keystone_mcp.user_directory.errors import UserNotFoundError
            raise UserNotFoundError(key)
        if full_name is not None:
            entry.full_name = full_name
        if note is not None:
            entry.note = note
        from keystone_mcp.user_directory.types import MutationResult
        return MutationResult(user=self._record(key, entry), changed=True)

@pytest.fixture
def keystone_directory_factory():
    async def factory():
        directory = CaseSensitiveStore()
        await seed_contract_dataset(directory)
        return directory
    return factory

class TestBroken(AdminDirectoryContract, AdminDirectoryChecks06):
    pass
"""
    )
    result = _run_contract_pytester(pytester)
    assert result.parseoutcomes().get("failed", 0) >= 1
    assert "test_mutations_normalize_email" in result.stdout.str()


def test_unavailable_error_code_catches_custom_code(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
import pytest
from keystone_mcp.contract_tests import UserDirectoryChecks06, UserDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.memory import InMemoryUserDirectory

class WrongUnavailableCode(InMemoryUserDirectory):
    async def resolve_user(self, subject):
        exc = UserDirectoryUnavailableError("nope", code="catalog_unavailable")
        exc.code = "custom_offline"
        raise exc

@pytest.fixture
def keystone_unavailable_directory_factory():
    async def factory():
        directory = WrongUnavailableCode()
        await seed_contract_dataset(directory)
        return directory
    return factory

@pytest.fixture
def keystone_directory_factory():
    async def factory():
        directory = InMemoryUserDirectory()
        await seed_contract_dataset(directory)
        return directory
    return factory

class TestBroken(UserDirectoryContract, UserDirectoryChecks06):
    pass
"""
    )
    result = _run_contract_pytester(pytester)
    assert result.parseoutcomes().get("failed", 0) >= 1
    assert "test_unavailable_error_code_is_known" in result.stdout.str()


def test_invalid_input_catches_value_error(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
import pytest
from keystone_mcp.contract_tests import AdminDirectoryChecks06, AdminDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.memory import InMemoryUserDirectory

class ValueErrorOnBadEmail(InMemoryUserDirectory):
    async def create_user(self, *, email, full_name, roles, note, actor):
        if "@" not in email:
            raise ValueError("bad email")
        return await super().create_user(
            email=email, full_name=full_name, roles=roles, note=note, actor=actor
        )

@pytest.fixture
def keystone_directory_factory():
    async def factory():
        directory = ValueErrorOnBadEmail()
        await seed_contract_dataset(directory)
        return directory
    return factory

class TestBroken(AdminDirectoryContract, AdminDirectoryChecks06):
    pass
"""
    )
    result = _run_contract_pytester(pytester)
    assert result.parseoutcomes().get("failed", 0) >= 1
    assert "test_invalid_input_raises_users_error" in result.stdout.str()


def test_hs256_catches_lenient_algorithms(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
import pytest
from keystone_mcp.contract_tests import OidcLoginProviderChecks06, OidcLoginProviderContract
from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.login.oidc import OidcLoginProvider
from keystone_mcp.login.protocol import LoginIdentity, RedirectLoginProvider

class LenientOidc(OidcLoginProvider):
    async def complete(self, *, params, callback_url, attempt):
        if params.get("error"):
            from keystone_mcp.login.protocol import LoginRejected
            raise LoginRejected("request_invalid")
        return LoginIdentity(email="alice@example.com", provider=self.name, interactive=True)

@pytest.fixture
def keystone_oidc_provider_factory():
    def factory(issuer: FakeOidcIssuer) -> RedirectLoginProvider:
        return LenientOidc(
            issuer.config(name="lenient"),
            http_client_factory=issuer.http_client,
            cache_ttl_seconds=0.0,
        )
    return factory

class TestBroken(OidcLoginProviderContract, OidcLoginProviderChecks06):
    pass
"""
    )
    result = _run_contract_pytester(pytester)
    assert result.parseoutcomes().get("failed", 0) >= 1
    assert "test_hs256_token_rejected" in result.stdout.str()


def test_empty_form_catches_key_error(pytester: pytest.Pytester) -> None:
    pytester.makepyfile(
        """
import pytest
from collections.abc import Awaitable, Callable, Mapping, Sequence
from keystone_mcp.contract_tests import FormLoginProviderChecks06, FormLoginProviderContract, FormProviderCase
from keystone_mcp.login.protocol import FormField, FormLoginProvider, LoginIdentity

class KeyErrorFormProvider:
    kind = "form"
    name = "broken-form"
    title = "Broken"
    interactive = True

    async def warm_up(self):
        return None

    async def aclose(self):
        return None

    def form_fields(self) -> Sequence[FormField]:
        return (FormField(name="email", input_type="email", label_key="email"),)

    async def verify(self, form: Mapping[str, str]) -> LoginIdentity:
        raise KeyError(form["email"])

@pytest.fixture
def keystone_form_provider_case():
    async def factory() -> FormLoginProvider:
        return KeyErrorFormProvider()

    return FormProviderCase(
        factory=factory,
        valid_form={"email": "bob@example.com"},
        expected_email="bob@example.com",
        invalid_forms=({"email": ""},),
    )

class TestBroken(FormLoginProviderContract, FormLoginProviderChecks06):
    pass
"""
    )
    result = _run_contract_pytester(pytester)
    assert result.parseoutcomes().get("failed", 0) >= 1
    assert "test_empty_form_is_rejected" in result.stdout.str()
