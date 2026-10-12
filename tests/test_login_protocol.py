"""The ``LoginProvider`` protocol itself, and the two built-in implementations (X03).

``keystone_mcp.login.protocol`` is a frozen public surface: it must stay
importable with nothing but the standard library on the path, so a plugin
author can depend on it without pulling in fastmcp, mcp, starlette or httpx.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from keystone_mcp.auth.google_oidc import GoogleTokenExchangeError
from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.login.api_key import ApiKeyLoginProvider
from keystone_mcp.login.factory import validate_login_providers
from keystone_mcp.login.google import GoogleLoginProvider
from keystone_mcp.login.protocol import FormLoginProvider, LoginRejected, RedirectLoginProvider
from support.fake_login import FakeRedirectProvider
from support.google_oidc_fixtures import build_mock_google_oidc

pytestmark = pytest.mark.asyncio


def test_protocol_module_is_framework_free():
    """Importing ``keystone_mcp.login`` must not pull in any framework dependency."""
    code = (
        "import keystone_mcp.login, sys; "
        "bad=[m for m in sys.modules if m.split('.')[0] in "
        "{'fastmcp', 'mcp', 'starlette', 'httpx', 'httpx2', 'sqlalchemy'}]; "
        "assert not bad, bad"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_google_provider_satisfies_redirect_protocol():
    mock = build_mock_google_oidc("http://localhost/login/google/callback")
    provider = GoogleLoginProvider(mock.client)
    assert isinstance(provider, RedirectLoginProvider)
    assert provider.kind == "redirect"
    assert provider.name == "google"
    assert provider.interactive is True


def test_api_key_provider_satisfies_form_protocol():
    provider = ApiKeyLoginProvider(StaticIdentityProvider({"tok"}))
    assert isinstance(provider, FormLoginProvider)
    assert provider.kind == "form"
    assert provider.name == "api_key"
    assert provider.interactive is False
    field_names = {field.name for field in provider.form_fields()}
    assert field_names == {"email", "api_token"}


def test_validate_login_providers_rejects_duplicates_bad_names_and_two_forms():
    # Duplicate names.
    with pytest.raises(ValueError, match="duplicate"):
        validate_login_providers([FakeRedirectProvider("acme"), FakeRedirectProvider("acme")])

    # A name outside ^[a-z][a-z0-9_-]{0,31}$.
    with pytest.raises(ValueError, match="not valid"):
        validate_login_providers([FakeRedirectProvider("Acme")])

    # More than one form-kind provider.
    from support.fake_login import FakeFormProvider

    with pytest.raises(ValueError, match="form"):
        validate_login_providers(
            [
                ApiKeyLoginProvider(StaticIdentityProvider(set())),
                FakeFormProvider("other_form"),
            ]
        )

    # Declares kind="redirect" but does not implement begin/complete.
    class _BrokenRedirect:
        @property
        def name(self) -> str:
            return "broken"

        @property
        def kind(self) -> str:
            return "redirect"

        @property
        def title(self) -> str:
            return "Broken"

        @property
        def interactive(self) -> bool:
            return True

        async def warm_up(self) -> None:
            return None

        async def aclose(self) -> None:
            return None

    with pytest.raises(ValueError, match="RedirectLoginProvider"):
        validate_login_providers([_BrokenRedirect()])


async def test_google_begin_puts_nonce_and_verifier_into_attempt():
    from urllib.parse import parse_qs, urlparse

    mock = build_mock_google_oidc("http://localhost/login/google/callback")
    provider = GoogleLoginProvider(mock.client, allowed_domain="example.com")

    redirect = await provider.begin(state="abc123", callback_url="http://localhost/unused")

    assert "nonce" in redirect.attempt
    assert "verifier" in redirect.attempt
    query = parse_qs(urlparse(redirect.url).query)
    assert query["state"] == ["abc123"]
    assert query["nonce"] == [redirect.attempt["nonce"]]
    assert query["code_challenge"]
    assert query["hd"] == ["example.com"]


async def test_google_complete_maps_errors():
    # error=... from the provider itself -> request_invalid.
    mock = build_mock_google_oidc("http://localhost/login/google/callback")
    provider = GoogleLoginProvider(mock.client)
    with pytest.raises(LoginRejected) as exc_info:
        await provider.complete(
            params={"error": "access_denied"}, callback_url="unused", attempt={}
        )
    assert exc_info.value.reason == "request_invalid"

    # Token exchange failure -> identity_invalid.
    mock2 = build_mock_google_oidc("http://localhost/login/google/callback")

    async def failing_exchange(code: str, verifier: str):
        raise GoogleTokenExchangeError("boom")

    mock2.client.exchange_code = failing_exchange  # type: ignore[method-assign]
    provider2 = GoogleLoginProvider(mock2.client)
    with pytest.raises(LoginRejected) as exc_info2:
        await provider2.complete(
            params={"code": "x"},
            callback_url="unused",
            attempt={"nonce": "n", "verifier": "v"},
        )
    assert exc_info2.value.reason == "identity_invalid"

    # Email outside the allowed domain -> domain_not_allowed.
    mock3 = build_mock_google_oidc("http://localhost/login/google/callback")
    provider3 = GoogleLoginProvider(mock3.client, allowed_domain="example.com")
    nonce = "nonce-1"
    mock3.set_pending_identity(email="alice@other.com", nonce=nonce, hd="other.com")
    with pytest.raises(LoginRejected) as exc_info3:
        await provider3.complete(
            params={"code": "x"},
            callback_url="unused",
            attempt={"nonce": nonce, "verifier": "v"},
        )
    assert exc_info3.value.reason == "domain_not_allowed"


async def test_api_key_verify_lowercases_email_and_rejects_bad_token():
    provider = ApiKeyLoginProvider(StaticIdentityProvider({"good-token"}))

    identity = await provider.verify({"email": " Alice@Example.COM ", "api_token": "good-token"})
    assert identity.email == "alice@example.com"
    assert identity.provider == "api_key"
    assert identity.interactive is False

    with pytest.raises(LoginRejected) as exc_info:
        await provider.verify({"email": "alice@example.com", "api_token": "wrong"})
    assert exc_info.value.reason == "invalid_credentials"
