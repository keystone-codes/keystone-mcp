"""The ``LoginProvider`` protocol itself, and the two built-in implementations (X03)."""

from __future__ import annotations

import subprocess
import sys
from urllib.parse import parse_qs, urlparse

import pytest

from keystone_mcp.login.factory import validate_login_providers
from keystone_mcp.login.protocol import (
    FormField,
    FormLoginProvider,
    LoginRejected,
    RedirectLoginProvider,
)
from support.fake_login import FakeRedirectProvider
from support.google_oidc_fixtures import build_mock_google_oidc
from support.login import dev_token_login


def test_protocol_module_is_framework_free():
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
    provider = mock.provider
    assert isinstance(provider, RedirectLoginProvider)
    assert provider.kind == "redirect"
    assert provider.name == "google"
    assert provider.interactive is True


def test_api_key_provider_satisfies_form_protocol():
    provider = dev_token_login({"tok"})
    assert isinstance(provider, FormLoginProvider)
    assert provider.kind == "form"
    assert provider.name == "api_key"
    assert provider.interactive is False
    field_names = {field.name for field in provider.form_fields()}
    assert field_names == {"email", "api_token"}


def test_validate_login_providers_rejects_duplicates_bad_names_and_two_forms():
    with pytest.raises(ValueError, match="duplicate"):
        validate_login_providers([FakeRedirectProvider("acme"), FakeRedirectProvider("acme")])

    with pytest.raises(ValueError, match="not valid"):
        validate_login_providers([FakeRedirectProvider("Acme")])

    from support.fake_login import FakeFormProvider

    with pytest.raises(ValueError, match="form"):
        validate_login_providers(
            [
                dev_token_login(set()),
                FakeFormProvider("other_form"),
            ]
        )

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


def test_validate_login_providers_rejects_name_with_trailing_newline():
    with pytest.raises(ValueError, match="not valid"):
        validate_login_providers([FakeRedirectProvider("acme\n")])


def test_validate_login_providers_reserves_google_and_redirect_not_allowed():
    with pytest.raises(ValueError, match="google"):
        validate_login_providers([FakeRedirectProvider("google")])

    with pytest.raises(ValueError, match="reserved"):
        validate_login_providers([FakeRedirectProvider("redirect-not-allowed")])

    mock = build_mock_google_oidc("http://localhost/login/google/callback")
    validate_login_providers([mock.provider])


def test_validate_login_providers_rejects_unsafe_form_fields():
    from support.fake_login import FakeFormProvider

    class _BadFieldName(FakeFormProvider):
        def form_fields(self):
            return (FormField("not safe!", "email", "email_label"),)

    with pytest.raises(ValueError, match="unsafe"):
        validate_login_providers([_BadFieldName("acme_form")])

    class _BadInputType(FakeFormProvider):
        def form_fields(self):
            return (FormField("email", "not_a_real_type", "email_label"),)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="input_type"):
        validate_login_providers([_BadInputType("acme_form")])


async def test_google_begin_puts_nonce_and_verifier_into_attempt():
    mock = build_mock_google_oidc(
        "http://localhost/login/google/callback", allowed_domain="example.com"
    )
    provider = mock.provider

    redirect = await provider.begin(
        state="abc123", callback_url="http://localhost/login/google/callback"
    )

    assert "nonce" in redirect.attempt
    assert "verifier" in redirect.attempt
    query = parse_qs(urlparse(redirect.url).query)
    assert query["state"] == ["abc123"]
    assert query["nonce"] == [redirect.attempt["nonce"]]
    assert query["code_challenge"]
    assert query["hd"] == ["example.com"]


async def test_google_complete_maps_errors():
    mock = build_mock_google_oidc("http://localhost/login/google/callback")
    provider = mock.provider
    with pytest.raises(LoginRejected) as exc_info:
        await provider.complete(
            params={"error": "access_denied"}, callback_url="unused", attempt={}
        )
    assert exc_info.value.reason == "request_invalid"

    mock2 = build_mock_google_oidc("http://localhost/login/google/callback")
    provider2 = mock2.provider
    mock2.fake.tamper.token_endpoint_status = 503
    with pytest.raises(LoginRejected) as exc_info2:
        await provider2.complete(
            params={"code": "x"},
            callback_url="http://localhost/cb",
            attempt={"nonce": "n", "verifier": "v"},
        )
    assert exc_info2.value.reason == "identity_invalid"

    mock3 = build_mock_google_oidc(
        "http://localhost/login/google/callback", allowed_domain="example.com"
    )
    provider3 = mock3.provider
    redirect = await provider3.begin(state="s", callback_url="http://localhost/cb")
    mock3.set_pending_identity(
        email="alice@other.com", nonce=redirect.attempt["nonce"], hd="other.com"
    )
    callback = await mock3.fake.authorize(redirect.url)
    with pytest.raises(LoginRejected) as exc_info3:
        await provider3.complete(
            params=callback,
            callback_url="http://localhost/cb",
            attempt=redirect.attempt,
        )
    assert exc_info3.value.reason == "domain_not_allowed"


async def test_api_key_verify_lowercases_email_and_rejects_bad_token():
    provider = dev_token_login(
        {"good-token"}
        if isinstance({"good-token"}, set)
        else set({"good-token"})
        if False
        else {"good-token"}
    )

    identity = await provider.verify({"email": " Alice@Example.COM ", "api_token": "good-token"})
    assert identity.email == "alice@example.com"
    assert identity.provider == "api_key"
    assert identity.interactive is False

    with pytest.raises(LoginRejected) as exc_info:
        await provider.verify({"email": "alice@example.com", "api_token": "wrong"})
    assert exc_info.value.reason == "invalid_credentials"
