"""Contract tests for built-in OIDC login providers."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from keystone_mcp.contract_tests import OidcLoginProviderChecks06, OidcLoginProviderContract
from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.login.oidc import OidcLoginProvider, google_provider_config
from keystone_mcp.login.protocol import RedirectLoginProvider


@pytest.fixture
def keystone_oidc_provider_factory() -> Callable[[FakeOidcIssuer], RedirectLoginProvider]:
    def factory(issuer: FakeOidcIssuer) -> RedirectLoginProvider:
        return OidcLoginProvider(
            issuer.config(name="contract-oidc", title="Contract OIDC"),
            http_client_factory=issuer.http_client,
            cache_ttl_seconds=0.0,
        )

    return factory


class TestOidcLoginProvider(OidcLoginProviderContract, OidcLoginProviderChecks06):
    pass


@pytest.fixture
def keystone_oidc_provider_factory_google() -> Callable[[FakeOidcIssuer], RedirectLoginProvider]:
    def factory(issuer: FakeOidcIssuer) -> RedirectLoginProvider:
        config = google_provider_config(
            client_id=issuer.client_id,
            client_secret=issuer.client_secret,
            name="google",
            title="Google",
        )
        return OidcLoginProvider(
            config,
            http_client_factory=issuer.http_client,
            cache_ttl_seconds=0.0,
        )

    return factory


class TestGoogleOidcProvider(OidcLoginProviderContract, OidcLoginProviderChecks06):
    @pytest.fixture
    def keystone_oidc_provider_factory(
        self,
        keystone_oidc_provider_factory_google: Callable[[FakeOidcIssuer], RedirectLoginProvider],
    ) -> Callable[[FakeOidcIssuer], RedirectLoginProvider]:
        return keystone_oidc_provider_factory_google

    @pytest.fixture
    def fake_oidc_issuer(self) -> FakeOidcIssuer:
        return FakeOidcIssuer(issuer="https://accounts.google.com")
