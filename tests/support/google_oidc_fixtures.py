"""Compatibility helpers: Google-shaped OIDC tests on ``FakeOidcIssuer``."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.login.oidc import OidcLoginProvider, google_provider_config


@dataclass
class MockGoogleOidc:
    fake: FakeOidcIssuer
    provider: OidcLoginProvider
    token_calls: list[dict[str, str]] = field(default_factory=list)
    last_nonce: str | None = None
    last_email: str | None = None

    def set_pending_identity(
        self,
        *,
        email: str,
        nonce: str,
        email_verified: bool = True,
        hd: str | None = None,
        iss: str | None = None,
        expired: bool = False,
        wrong_aud: bool = False,
        wrong_nonce: str | None = None,
        **_: Any,
    ) -> None:
        self.fake.user.email = email
        self.fake.user.email_verified = email_verified
        self.fake.user.hd = hd
        self.fake.tamper.reset()
        self.fake.tamper.expired = expired
        self.fake.tamper.wrong_audience = wrong_aud
        if wrong_nonce is not None:
            self.fake.tamper.wrong_nonce = True
        if iss is not None and iss != self.fake.issuer:
            self.fake.tamper.wrong_issuer = iss
        self.last_nonce = nonce
        self.last_email = email.strip().lower()


def build_mock_google_oidc(
    redirect_uri: str,
    *,
    client_id: str = "test-google-client",
    client_secret: str = "test-secret",
    allowed_domain: str = "",
) -> MockGoogleOidc:
    del redirect_uri
    fake = FakeOidcIssuer(
        issuer="https://accounts.google.com",
        client_id=client_id,
        client_secret=client_secret,
    )
    config = google_provider_config(
        client_id=client_id,
        client_secret=client_secret,
        allowed_domain=allowed_domain,
    )
    provider = OidcLoginProvider(config, http_client_factory=fake.http_client)
    return MockGoogleOidc(fake=fake, provider=provider)
