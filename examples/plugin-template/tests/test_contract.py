"""Contract tests for the example plugin."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

import pytest
import yaml
from keystone_plugin_example.directory import StaticFileUserDirectory
from keystone_plugin_example.login import ExampleOidcProvider

from keystone_mcp.contract_tests import OidcLoginProviderContract, UserDirectoryContract
from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.login.protocol import RedirectLoginProvider
from keystone_mcp.user_directory.protocol import UserDirectory


@pytest.fixture
def keystone_directory_factory() -> Callable[[], Awaitable[UserDirectory]]:
    data_path = Path(__file__).parent / "data" / "people.yaml"

    async def factory() -> UserDirectory:
        people = yaml.safe_load(data_path.read_text(encoding="utf-8"))
        return StaticFileUserDirectory(people)

    return factory


class TestStaticFileDirectory(UserDirectoryContract):
    pass


@pytest.fixture
def keystone_oidc_provider_factory() -> Callable[[FakeOidcIssuer], RedirectLoginProvider]:
    def factory(issuer: FakeOidcIssuer) -> RedirectLoginProvider:
        return ExampleOidcProvider(
            issuer.config(name="example-oidc", title="Example OIDC", groups_claim="roles"),
            http_client_factory=issuer.http_client,
        )

    return factory


class TestExampleOidc(OidcLoginProviderContract):
    pass
