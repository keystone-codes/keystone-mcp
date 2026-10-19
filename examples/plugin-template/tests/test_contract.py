"""Contract tests for the example plugin."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest
import yaml
from keystone_plugin_example.directory import StaticFileUserDirectory
from keystone_plugin_example.login import ExampleOidcProvider

from keystone_mcp.contract_tests import (
    OidcLoginProviderChecks06,
    OidcLoginProviderContract,
    UserDirectoryChecks06,
    UserDirectoryContract,
)
from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.login.protocol import RedirectLoginProvider
from keystone_mcp.user_directory.errors import UserDirectoryUnavailableError
from keystone_mcp.user_directory.protocol import UserDirectory


@pytest.fixture
def keystone_unavailable_directory_factory() -> Callable[[], Awaitable[UserDirectory]]:
    async def factory() -> UserDirectory:
        directory = StaticFileUserDirectory([])

        async def resolve_user(subject: str) -> None:
            raise UserDirectoryUnavailableError("unavailable", code="catalog_unavailable")

        async def ping() -> None:
            raise UserDirectoryUnavailableError("unavailable", code="catalog_unavailable")

        directory.resolve_user = resolve_user  # type: ignore[method-assign]
        directory.ping = ping  # type: ignore[method-assign]
        return directory

    return factory


@pytest.fixture
def keystone_directory_factory() -> Callable[[], Awaitable[UserDirectory]]:
    data_path = Path(__file__).parent / "data" / "people.yaml"

    async def factory() -> UserDirectory:
        people = yaml.safe_load(data_path.read_text(encoding="utf-8"))
        return StaticFileUserDirectory(people)

    return factory


class TestStaticFileDirectory(UserDirectoryContract, UserDirectoryChecks06):
    pass


@pytest.fixture
def keystone_oidc_provider_factory() -> Callable[[FakeOidcIssuer], RedirectLoginProvider]:
    def factory(issuer: FakeOidcIssuer) -> RedirectLoginProvider:
        return ExampleOidcProvider(
            issuer.config(name="example-oidc", title="Example OIDC", groups_claim="roles"),
            http_client_factory=issuer.http_client,
        )

    return factory


class TestExampleOidc(OidcLoginProviderContract, OidcLoginProviderChecks06):
    pass
