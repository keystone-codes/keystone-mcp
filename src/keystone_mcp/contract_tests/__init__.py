"""Keystone-MCP extension contract tests (pytest plugin: ``-p keystone_mcp.contract_tests``)."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from keystone_mcp.contract_tests.directory import (
    CONTRACT_DATASET,
    AdminDirectoryContract,
    ApiKeyDirectoryContract,
    ContractPerson,
    DeletionDirectoryContract,
    IdentityBindingDirectoryContract,
    ServiceAccountDirectoryContract,
    UserDirectoryContract,
    seed_contract_dataset,
)
from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer, FakeTamper
from keystone_mcp.contract_tests.login import (
    FormLoginProviderContract,
    FormProviderCase,
    OidcLoginProviderContract,
)
from keystone_mcp.login.protocol import RedirectLoginProvider

__all__ = [
    "CONTRACT_DATASET",
    "AdminDirectoryContract",
    "ApiKeyDirectoryContract",
    "ContractPerson",
    "FakeOidcIssuer",
    "FakeTamper",
    "FormLoginProviderContract",
    "FormProviderCase",
    "DeletionDirectoryContract",
    "IdentityBindingDirectoryContract",
    "OidcLoginProviderContract",
    "ServiceAccountDirectoryContract",
    "UserDirectoryContract",
    "seed_contract_dataset",
]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "keystone_contract: Keystone-MCP extension contract test",
    )
    config.addinivalue_line(
        "markers",
        "keystone_contract_lenient(reason): opt out of capability/contract-class "
        "match and mandatory availability tests; reason is required",
    )


@pytest.fixture
def fake_oidc_issuer() -> FakeOidcIssuer:
    return FakeOidcIssuer()


@pytest.fixture
def keystone_oidc_provider(
    fake_oidc_issuer: FakeOidcIssuer,
    keystone_oidc_provider_factory: Callable[[FakeOidcIssuer], RedirectLoginProvider],
) -> RedirectLoginProvider:
    return keystone_oidc_provider_factory(fake_oidc_issuer)
