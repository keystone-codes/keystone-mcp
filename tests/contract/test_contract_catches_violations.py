"""Verify contract suites fail on deliberately broken implementations."""

from __future__ import annotations

pytest_plugins = ["keystone_mcp.contract_tests", "pytester"]

import pytest


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
