"""Executable contract tests for sign-in providers."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import pytest

from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.login.protocol import (
    FormLoginProvider,
    LoginRejected,
    RedirectLoginProvider,
)

_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


@dataclass(frozen=True, slots=True)
class FormProviderCase:
    factory: Callable[[], Awaitable[FormLoginProvider]]
    valid_form: Mapping[str, str]
    expected_email: str
    invalid_forms: Sequence[Mapping[str, str]]


def _run_async(coro: Any) -> None:
    asyncio.run(coro)


class OidcLoginProviderContract:
    pytestmark = pytest.mark.keystone_contract

    def test_redirect_metadata(self, keystone_oidc_provider: RedirectLoginProvider):
        assert keystone_oidc_provider.kind == "redirect"
        assert keystone_oidc_provider.interactive is True
        assert _NAME_RE.fullmatch(keystone_oidc_provider.name)
        assert (
            isinstance(keystone_oidc_provider.title, str) and keystone_oidc_provider.title.strip()
        )

    def test_successful_oidc_flow(
        self, keystone_oidc_provider: RedirectLoginProvider, fake_oidc_issuer: FakeOidcIssuer
    ):
        async def exercise() -> None:
            provider = keystone_oidc_provider
            fake_oidc_issuer.user.email = "alice@example.com"
            redirect = await provider.begin(state="txn-state", callback_url="http://app.test/cb")
            assert fake_oidc_issuer.client_secret not in redirect.attempt.values()
            assert "client_secret" not in redirect.attempt
            params = await fake_oidc_issuer.authorize(redirect.url)
            identity = await provider.complete(
                params=params,
                callback_url="http://app.test/cb",
                attempt=redirect.attempt,
            )
            assert identity.email == "alice@example.com"
            assert identity.provider == provider.name

        _run_async(exercise())

    def test_wrong_nonce_rejected(
        self, keystone_oidc_provider: RedirectLoginProvider, fake_oidc_issuer: FakeOidcIssuer
    ):
        async def exercise() -> None:
            provider = keystone_oidc_provider
            redirect = await provider.begin(state="s", callback_url="http://app.test/cb")
            fake_oidc_issuer.tamper.wrong_nonce = True
            params = await fake_oidc_issuer.authorize(redirect.url)
            with pytest.raises(LoginRejected) as exc:
                await provider.complete(
                    params=params, callback_url="http://app.test/cb", attempt=redirect.attempt
                )
            assert exc.value.reason == "identity_invalid"

        _run_async(exercise())

    def test_bad_signature_rejected(
        self, keystone_oidc_provider: RedirectLoginProvider, fake_oidc_issuer: FakeOidcIssuer
    ):
        async def exercise() -> None:
            provider = keystone_oidc_provider
            redirect = await provider.begin(state="s", callback_url="http://app.test/cb")
            fake_oidc_issuer.tamper.bad_signature = True
            params = await fake_oidc_issuer.authorize(redirect.url)
            with pytest.raises(LoginRejected) as exc:
                await provider.complete(
                    params=params, callback_url="http://app.test/cb", attempt=redirect.attempt
                )
            assert exc.value.reason == "identity_invalid"

        _run_async(exercise())

    def test_wrong_issuer_rejected(
        self, keystone_oidc_provider: RedirectLoginProvider, fake_oidc_issuer: FakeOidcIssuer
    ):
        async def exercise() -> None:
            provider = keystone_oidc_provider
            redirect = await provider.begin(state="s", callback_url="http://app.test/cb")
            fake_oidc_issuer.tamper.wrong_issuer = "https://evil.test"
            params = await fake_oidc_issuer.authorize(redirect.url)
            with pytest.raises(LoginRejected) as exc:
                await provider.complete(
                    params=params, callback_url="http://app.test/cb", attempt=redirect.attempt
                )
            assert exc.value.reason == "identity_invalid"

        _run_async(exercise())

    def test_wrong_audience_rejected(
        self, keystone_oidc_provider: RedirectLoginProvider, fake_oidc_issuer: FakeOidcIssuer
    ):
        async def exercise() -> None:
            provider = keystone_oidc_provider
            redirect = await provider.begin(state="s", callback_url="http://app.test/cb")
            fake_oidc_issuer.tamper.wrong_audience = True
            params = await fake_oidc_issuer.authorize(redirect.url)
            with pytest.raises(LoginRejected) as exc:
                await provider.complete(
                    params=params, callback_url="http://app.test/cb", attempt=redirect.attempt
                )
            assert exc.value.reason == "identity_invalid"

        _run_async(exercise())

    def test_expired_token_rejected(
        self, keystone_oidc_provider: RedirectLoginProvider, fake_oidc_issuer: FakeOidcIssuer
    ):
        async def exercise() -> None:
            provider = keystone_oidc_provider
            redirect = await provider.begin(state="s", callback_url="http://app.test/cb")
            fake_oidc_issuer.tamper.expired = True
            params = await fake_oidc_issuer.authorize(redirect.url)
            with pytest.raises(LoginRejected) as exc:
                await provider.complete(
                    params=params, callback_url="http://app.test/cb", attempt=redirect.attempt
                )
            assert exc.value.reason == "identity_invalid"

        _run_async(exercise())

    def test_unverified_email_rejected(
        self, keystone_oidc_provider: RedirectLoginProvider, fake_oidc_issuer: FakeOidcIssuer
    ):
        async def exercise() -> None:
            provider = keystone_oidc_provider
            redirect = await provider.begin(state="s", callback_url="http://app.test/cb")
            fake_oidc_issuer.user.email_verified = False
            params = await fake_oidc_issuer.authorize(redirect.url)
            with pytest.raises(LoginRejected) as exc:
                await provider.complete(
                    params=params, callback_url="http://app.test/cb", attempt=redirect.attempt
                )
            assert exc.value.reason == "email_unverified"

        _run_async(exercise())

    def test_access_denied_rejected(
        self, keystone_oidc_provider: RedirectLoginProvider, fake_oidc_issuer: FakeOidcIssuer
    ):
        async def exercise() -> None:
            provider = keystone_oidc_provider
            with pytest.raises(LoginRejected) as exc:
                await provider.complete(
                    params={"error": "access_denied"},
                    callback_url="http://app.test/cb",
                    attempt={},
                )
            assert exc.value.reason == "request_invalid"

        _run_async(exercise())

    def test_provider_unavailable_on_complete(
        self, keystone_oidc_provider: RedirectLoginProvider, fake_oidc_issuer: FakeOidcIssuer
    ):
        async def exercise() -> None:
            provider = keystone_oidc_provider
            redirect = await provider.begin(state="s", callback_url="http://app.test/cb")
            params = await fake_oidc_issuer.authorize(redirect.url)
            fake_oidc_issuer.tamper.unavailable = True
            with pytest.raises(LoginRejected) as exc:
                await provider.complete(
                    params=params, callback_url="http://app.test/cb", attempt=redirect.attempt
                )
            assert exc.value.reason == "provider_unavailable"

        _run_async(exercise())

    def test_warm_up_tolerates_unavailable_discovery(
        self, keystone_oidc_provider: RedirectLoginProvider, fake_oidc_issuer: FakeOidcIssuer
    ):
        async def exercise() -> None:
            fake_oidc_issuer.tamper.discovery_status = 503
            await keystone_oidc_provider.warm_up()

        _run_async(exercise())

    def test_complete_only_raises_login_rejected(
        self, keystone_oidc_provider: RedirectLoginProvider, fake_oidc_issuer: FakeOidcIssuer
    ):
        scenarios = (
            lambda: fake_oidc_issuer.tamper.__setattr__("wrong_nonce", True),
            lambda: fake_oidc_issuer.tamper.__setattr__("bad_signature", True),
            lambda: fake_oidc_issuer.tamper.__setattr__("wrong_audience", True),
            lambda: fake_oidc_issuer.tamper.__setattr__("expired", True),
            lambda: fake_oidc_issuer.user.__setattr__("email_verified", False),
        )

        async def exercise() -> None:
            provider = keystone_oidc_provider
            for setup in scenarios:
                fake_oidc_issuer.tamper.reset()
                fake_oidc_issuer.user.email_verified = True
                setup()
                redirect = await provider.begin(state="s", callback_url="http://app.test/cb")
                params = await fake_oidc_issuer.authorize(redirect.url)
                try:
                    await provider.complete(
                        params=params, callback_url="http://app.test/cb", attempt=redirect.attempt
                    )
                except LoginRejected:
                    continue
                except Exception as exc:
                    raise AssertionError(
                        f"complete() must only raise LoginRejected, got {type(exc).__name__}"
                    ) from exc
                raise AssertionError("expected LoginRejected from complete()")

        _run_async(exercise())


class FormLoginProviderContract:
    pytestmark = pytest.mark.keystone_contract

    def test_form_metadata(self, keystone_form_provider_case: FormProviderCase):
        async def exercise() -> None:
            provider = await keystone_form_provider_case.factory()
            assert provider.kind == "form"
            fields = {f.name for f in provider.form_fields()}
            assert fields >= set(keystone_form_provider_case.valid_form)

        _run_async(exercise())

    def test_valid_form(self, keystone_form_provider_case: FormProviderCase):
        async def exercise() -> None:
            provider = await keystone_form_provider_case.factory()
            identity = await provider.verify(keystone_form_provider_case.valid_form)
            assert identity.email == keystone_form_provider_case.expected_email.lower()

        _run_async(exercise())

    def test_invalid_forms(self, keystone_form_provider_case: FormProviderCase):
        async def exercise() -> None:
            provider = await keystone_form_provider_case.factory()
            for form in keystone_form_provider_case.invalid_forms:
                with pytest.raises(LoginRejected) as exc:
                    await provider.verify(form)
                assert exc.value.reason == "invalid_credentials"

        _run_async(exercise())

    def test_email_normalization(self, keystone_form_provider_case: FormProviderCase):
        async def exercise() -> None:
            provider = await keystone_form_provider_case.factory()
            form = dict(keystone_form_provider_case.valid_form)
            if "email" in form:
                form["email"] = f"  {form['email'].upper()}  "
            identity = await provider.verify(form)
            assert identity.email == keystone_form_provider_case.expected_email.lower()

        _run_async(exercise())
