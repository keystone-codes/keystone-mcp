"""Verify contract suites fail on deliberately broken implementations."""

from __future__ import annotations

import pytest

pytest_plugins = ["keystone_mcp.contract_tests", "pytester"]


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
