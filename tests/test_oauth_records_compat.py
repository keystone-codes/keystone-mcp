"""Redis records written by fastmcp 3.4.4 / mcp 1.28.1 must still parse on 4.1.0 / 2.3.0.

OAuth clients, access and refresh tokens, pending login transactions,
authorization codes and the refresh-token auth-method marker (A15) all
persist in Redis with no migration step across the fastmcp 4 upgrade (X02).
These are the six record shapes captured on fastmcp 3.4.4 / mcp 1.28.1 before
the upgrade, reproduced verbatim as string constants -- see
``internal/tasks-0.5.0/X-extensibility/X01-spike-report.md``, section
"Образцы записей" (sampled by ``scripts/spike_capture_records.py`` on the
pre-upgrade branch, scenario B2: "Записи из шага 1 читаются новой версией").

Each test reads its record the same way the running code does: the OAuth
store's own ``model_validate_json`` calls, or the provider's own envelope
parsers -- not a store round trip, so the result does not depend on whether
the sample's fixed ``expires_at`` timestamp (minted during the spike) has
since passed.
"""

from __future__ import annotations

from mcp.server.auth.provider import AccessToken, AuthorizationParams, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull

from keystone_mcp.auth.keystone_oauth_provider import (
    KeystoneOAuthProvider,
    _parse_auth_code_envelope,
    _parse_pending_txn_raw,
)
from keystone_mcp.auth.login_pending_store import InMemoryLoginPendingStore
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from support.login import dev_token_login

# Captured on fastmcp 3.4.4 / mcp 1.28.1 -- see the module docstring.
_CLIENT_RECORD_3X = (
    '{"redirect_uris":["https://client.example/callback"],'
    '"token_endpoint_auth_method":"none",'
    '"grant_types":["authorization_code","refresh_token"],'
    '"response_types":["code"],"scope":null,"client_name":"Spike Client",'
    '"client_uri":null,"logo_uri":null,"contacts":null,"tos_uri":null,'
    '"policy_uri":null,"jwks_uri":null,"jwks":null,"software_id":null,'
    '"software_version":null,"client_id":"spike-client-id",'
    '"client_secret":"spike-client-secret","client_id_issued_at":null,'
    '"client_secret_expires_at":null}'
)

_ACCESS_TOKEN_RECORD_3X = (
    '{"token":"km_at_spike0000000000000000000000","client_id":"spike-client-id",'
    '"scopes":["keystone"],"expires_at":1791804026,'
    '"resource":"https://keystone.example/mcp","subject":"user@example.com",'
    '"claims":{"email":"user@example.com","auth_method":"google"}}'
)

_REFRESH_TOKEN_RECORD_3X = (
    '{"token":"km_rt_spike0000000000000000000000","client_id":"spike-client-id",'
    '"scopes":["keystone"],"expires_at":1794392426,"subject":"user@example.com"}'
)

_PENDING_LOGIN_TXN_ENVELOPE_3X = (
    "spike-client-id\n"
    '{"state":"spike-state","scopes":["keystone"],'
    '"code_challenge":"spike-code-challenge",'
    '"redirect_uri":"https://client.example/callback",'
    '"redirect_uri_provided_explicitly":true,'
    '"resource":"https://keystone.example/mcp"}'
)

_AUTH_CODE_ENVELOPE_3X = (
    '{"code": {"code": "km_code_spike0000000000000000000000", '
    '"scopes": ["keystone"], "expires_at": 1791800726.87454, '
    '"client_id": "spike-client-id", "code_challenge": "spike-code-challenge", '
    '"redirect_uri": "https://client.example/callback", '
    '"redirect_uri_provided_explicitly": true, '
    '"resource": "https://keystone.example/mcp", '
    '"subject": "user@example.com"}, "auth_method": "google"}'
)

_REFRESH_META_MARKER_3X = '{"auth_method": "google", "resource": "https://keystone.example/mcp"}'


def test_client_record_from_3x_is_readable():
    client = OAuthClientInformationFull.model_validate_json(_CLIENT_RECORD_3X)

    assert client.client_id == "spike-client-id"
    assert [str(uri) for uri in client.redirect_uris] == ["https://client.example/callback"]
    assert client.client_name == "Spike Client"


def test_access_token_from_3x_keeps_claims():
    access = AccessToken.model_validate_json(_ACCESS_TOKEN_RECORD_3X)

    assert access.resource == "https://keystone.example/mcp"
    assert access.subject == "user@example.com"
    assert access.claims["email"] == "user@example.com"
    assert access.claims["auth_method"] == "google"


def test_refresh_token_from_3x_is_readable():
    refresh = RefreshToken.model_validate_json(_REFRESH_TOKEN_RECORD_3X)

    assert refresh.token == "km_rt_spike0000000000000000000000"
    assert refresh.client_id == "spike-client-id"
    assert refresh.subject == "user@example.com"


def test_pending_txn_envelope_from_3x_is_readable():
    pending = _parse_pending_txn_raw(_PENDING_LOGIN_TXN_ENVELOPE_3X)

    assert pending is not None
    assert pending.client_id == "spike-client-id"
    assert isinstance(pending.params, AuthorizationParams)
    assert pending.params.state == "spike-state"
    assert pending.params.resource == "https://keystone.example/mcp"


def test_auth_code_envelope_from_3x_is_readable():
    parsed = _parse_auth_code_envelope(_AUTH_CODE_ENVELOPE_3X)

    assert parsed is not None
    assert parsed.code.code == "km_code_spike0000000000000000000000"
    assert parsed.code.subject == "user@example.com"
    assert parsed.auth_method == "google"
    # The 3x envelope predates the "interactive" field (X05): rebuilt from
    # the sign-in method's own name, same as has_interactive_human_identity's
    # fallback for a pre-0.5.0 token.
    assert parsed.interactive is True


async def test_refresh_meta_marker_from_3x_is_readable():
    pending_store = InMemoryLoginPendingStore()
    await pending_store.put("refresh_auth", "km_rt_marker", _REFRESH_META_MARKER_3X, 3600)
    provider = KeystoneOAuthProvider(
        Settings(base_url="http://localhost:8080"),
        InMemoryOAuthStore(),
        pending_store,
        login_providers=[
            dev_token_login(
                {"valid-test-token"}
                if isinstance({"valid-test-token"}, set)
                else set({"valid-test-token"})
                if False
                else {"valid-test-token"}
            )
        ],
    )

    meta = await provider._read_refresh_meta("km_rt_marker")

    assert meta is not None
    assert meta.auth_method == "google"
    assert meta.resource == "https://keystone.example/mcp"
    # The 3x marker predates "interactive" too; same rebuild rule as above.
    assert meta.interactive is True
