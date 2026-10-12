"""Unit tests for ``OidcLoginProvider`` using ``FakeOidcIssuer`` (no network)."""

from __future__ import annotations

import logging

import pytest

from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.login.oidc import OidcLoginProvider, google_provider_config
from keystone_mcp.login.protocol import LoginRejected

pytestmark = pytest.mark.asyncio


def _provider(fake: FakeOidcIssuer, **config_overrides) -> OidcLoginProvider:
    cache_ttl = float(config_overrides.pop("cache_ttl_seconds", 3600.0))
    return OidcLoginProvider(
        fake.config(name="fake", **config_overrides),
        http_client_factory=fake.http_client,
        cache_ttl_seconds=cache_ttl,
    )


async def test_full_flow_returns_identity():
    fake = FakeOidcIssuer()
    provider = _provider(fake)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.user.email = "alice@example.com"
    params = await fake.authorize(redirect.url)
    identity = await provider.complete(
        params=params, callback_url="http://app/cb", attempt=redirect.attempt
    )
    assert identity.email == "alice@example.com"
    assert identity.provider == "fake"
    assert identity.interactive is True


async def test_discovery_issuer_mismatch_is_unavailable():
    fake = FakeOidcIssuer()
    fake.tamper.discovery_issuer = "https://other.test"
    provider = _provider(fake)
    with pytest.raises(LoginRejected) as exc:
        await provider.begin(state="s", callback_url="http://app/cb")
    assert exc.value.reason == "provider_unavailable"


async def test_discovery_is_cached():
    fake = FakeOidcIssuer()
    provider = _provider(fake, cache_ttl_seconds=3600.0)
    await provider.begin(state="a", callback_url="http://app/cb")
    fake.tamper.discovery_status = 503
    await provider.begin(state="b", callback_url="http://app/cb")


async def test_wrong_nonce_is_refused():
    fake = FakeOidcIssuer()
    provider = _provider(fake)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.tamper.wrong_nonce = True
    params = await fake.authorize(redirect.url)
    with pytest.raises(LoginRejected) as exc:
        await provider.complete(
            params=params, callback_url="http://app/cb", attempt=redirect.attempt
        )
    assert exc.value.reason == "identity_invalid"


async def test_bad_signature_is_refused():
    fake = FakeOidcIssuer()
    provider = _provider(fake)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.tamper.bad_signature = True
    params = await fake.authorize(redirect.url)
    with pytest.raises(LoginRejected) as exc:
        await provider.complete(
            params=params, callback_url="http://app/cb", attempt=redirect.attempt
        )
    assert exc.value.reason == "identity_invalid"


async def test_wrong_issuer_is_refused():
    fake = FakeOidcIssuer()
    provider = _provider(fake)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.tamper.wrong_issuer = "https://evil.test"
    params = await fake.authorize(redirect.url)
    with pytest.raises(LoginRejected) as exc:
        await provider.complete(
            params=params, callback_url="http://app/cb", attempt=redirect.attempt
        )
    assert exc.value.reason == "identity_invalid"


async def test_additional_issuer_is_accepted():
    fake = FakeOidcIssuer(issuer="https://accounts.google.com")
    provider = OidcLoginProvider(
        fake.config(name="google", additional_issuers=("accounts.google.com",)),
        http_client_factory=fake.http_client,
    )
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.tamper.wrong_issuer = "accounts.google.com"
    params = await fake.authorize(redirect.url)
    identity = await provider.complete(
        params=params, callback_url="http://app/cb", attempt=redirect.attempt
    )
    assert identity.email == fake.user.email


async def test_wrong_audience_is_refused():
    fake = FakeOidcIssuer()
    provider = _provider(fake)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.tamper.wrong_audience = True
    params = await fake.authorize(redirect.url)
    with pytest.raises(LoginRejected) as exc:
        await provider.complete(
            params=params, callback_url="http://app/cb", attempt=redirect.attempt
        )
    assert exc.value.reason == "identity_invalid"


async def test_expired_token_is_refused():
    fake = FakeOidcIssuer()
    provider = _provider(fake)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.tamper.expired = True
    params = await fake.authorize(redirect.url)
    with pytest.raises(LoginRejected) as exc:
        await provider.complete(
            params=params, callback_url="http://app/cb", attempt=redirect.attempt
        )
    assert exc.value.reason == "identity_invalid"


async def test_hs256_and_none_are_refused():
    fake = FakeOidcIssuer()
    provider = _provider(fake)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.tamper.alg_hs256 = True
    params = await fake.authorize(redirect.url)
    with pytest.raises(LoginRejected) as exc:
        await provider.complete(
            params=params, callback_url="http://app/cb", attempt=redirect.attempt
        )
    assert exc.value.reason == "identity_invalid"


async def test_unverified_email_is_refused():
    fake = FakeOidcIssuer()
    provider = _provider(fake)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.user.email_verified = False
    params = await fake.authorize(redirect.url)
    with pytest.raises(LoginRejected) as exc:
        await provider.complete(
            params=params, callback_url="http://app/cb", attempt=redirect.attempt
        )
    assert exc.value.reason == "email_unverified"


async def test_unverified_email_allowed_when_not_required():
    fake = FakeOidcIssuer()
    provider = _provider(fake, require_email_verified=False)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.user.email_verified = False
    params = await fake.authorize(redirect.url)
    identity = await provider.complete(
        params=params, callback_url="http://app/cb", attempt=redirect.attempt
    )
    assert identity.email == fake.user.email


async def test_string_true_email_verified_is_accepted():
    fake = FakeOidcIssuer()
    provider = _provider(fake)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.user.extra_claims["email_verified"] = "true"
    fake.user.email_verified = False
    params = await fake.authorize(redirect.url)
    identity = await provider.complete(
        params=params, callback_url="http://app/cb", attempt=redirect.attempt
    )
    assert identity.email == fake.user.email


async def test_allowed_domains():
    fake = FakeOidcIssuer()
    provider = _provider(fake, allowed_domains=("example.com",))
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.user.email = "alice@other.com"
    params = await fake.authorize(redirect.url)
    with pytest.raises(LoginRejected) as exc:
        await provider.complete(
            params=params, callback_url="http://app/cb", attempt=redirect.attempt
        )
    assert exc.value.reason == "domain_not_allowed"


async def test_hosted_domain_must_match_hd_claim():
    fake = FakeOidcIssuer()
    provider = _provider(fake, hosted_domain="example.com")
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.user.hd = "other.com"
    params = await fake.authorize(redirect.url)
    with pytest.raises(LoginRejected) as exc:
        await provider.complete(
            params=params, callback_url="http://app/cb", attempt=redirect.attempt
        )
    assert exc.value.reason == "domain_not_allowed"


async def test_key_rotation_refetches_jwks_once():
    fake = FakeOidcIssuer()
    provider = _provider(fake)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    await provider._load_jwks()
    fake.tamper.rotate_key = True
    params = await fake.authorize(redirect.url)
    identity = await provider.complete(
        params=params, callback_url="http://app/cb", attempt=redirect.attempt
    )
    assert identity.email == fake.user.email


async def test_token_endpoint_error_is_identity_invalid():
    fake = FakeOidcIssuer()
    provider = _provider(fake)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.tamper.token_endpoint_status = 503
    params = await fake.authorize(redirect.url)
    with pytest.raises(LoginRejected) as exc:
        await provider.complete(
            params=params, callback_url="http://app/cb", attempt=redirect.attempt
        )
    assert exc.value.reason == "identity_invalid"


@pytest.mark.parametrize("auth_method", ["client_secret_basic", "client_secret_post"])
async def test_basic_and_post_client_auth(auth_method: str):
    fake = FakeOidcIssuer()
    provider = _provider(fake, token_auth_method=auth_method)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    params = await fake.authorize(redirect.url)
    identity = await provider.complete(
        params=params, callback_url="http://app/cb", attempt=redirect.attempt
    )
    assert identity.email == fake.user.email


async def test_groups_claim():
    fake = FakeOidcIssuer()
    provider = _provider(fake, groups_claim="groups")
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    fake.user.groups = ["admins", "devs"]
    params = await fake.authorize(redirect.url)
    identity = await provider.complete(
        params=params, callback_url="http://app/cb", attempt=redirect.attempt
    )
    assert identity.groups == ("admins", "devs")


def test_reserved_extra_param_is_rejected():
    fake = FakeOidcIssuer()
    with pytest.raises(ValueError, match="reserved"):
        _provider(fake, extra_authorize_params={"state": "x"})


def test_google_preset_values():
    cfg = google_provider_config(client_id="cid", client_secret="sec", allowed_domain="example.com")
    assert cfg.issuer == "https://accounts.google.com"
    assert cfg.token_auth_method == "client_secret_post"
    assert cfg.hosted_domain == "example.com"
    assert cfg.allowed_domains == ("example.com",)


async def test_secrets_and_tokens_not_logged(caplog):
    caplog.set_level(logging.WARNING)
    fake = FakeOidcIssuer(client_secret="top-secret-value")
    provider = _provider(fake)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    params = await fake.authorize(redirect.url)
    await provider.complete(params=params, callback_url="http://app/cb", attempt=redirect.attempt)
    blob = caplog.text + " ".join(r.getMessage() for r in caplog.records)
    assert "top-secret-value" not in blob
    assert params["code"] not in blob
