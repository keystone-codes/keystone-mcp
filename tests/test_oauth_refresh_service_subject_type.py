"""Refresh must not rewrite a service session's ``subject_type`` claim."""

from __future__ import annotations

import time
from dataclasses import replace

from conftest import refresh_access_token, register_client
from keystone_mcp.auth.keystone_oauth_provider import RefreshMeta
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore, KeystoneRefreshToken
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from support.admin_harness import build_admin_harness

SERVICE_SUBJECT = "svc:ci"


async def _seed_service_refresh_session(
    oauth,
    store: InMemoryOAuthStore,
    *,
    client_id: str,
) -> str:
    refresh_token = "km_rt_svc_legacy"
    now = int(time.time())
    await store.put_refresh_token(
        KeystoneRefreshToken(
            token=refresh_token,
            client_id=client_id,
            scopes=[],
            expires_at=now + 3600,
            subject=SERVICE_SUBJECT,
            iat=now,
        )
    )
    await oauth._put_refresh_meta(
        refresh_token,
        RefreshMeta(
            auth_method="api_key",
            resource=None,
            interactive=False,
            auth_time=now,
            key_id=None,
            key_id_known=False,
            key_expires_at=None,
        ),
    )
    return refresh_token


def _identity_from_access_record(access) -> VerifiedIdentity:
    claims = access.claims or {}
    return VerifiedIdentity(
        subject=access.subject or SERVICE_SUBJECT,
        claims=claims,
        subject_type=claims.get("subject_type"),
    )


async def test_refresh_keeps_service_subject_type_and_admin_mutation_forbidden(
    harness, tmp_path
) -> None:
    client = harness.client
    oauth = harness.oauth
    store = oauth._store
    settings = harness.settings
    client_id = await register_client(client)
    refresh_token = await _seed_service_refresh_session(oauth, store, client_id=client_id)

    refreshed = await refresh_access_token(client, client_id, refresh_token, settings.resource_url)
    assert refreshed["status"] == 200, refreshed
    access = await store.get_access_token(refreshed["body"]["access_token"])
    assert access is not None
    assert access.subject == SERVICE_SUBJECT
    assert access.claims.get("subject_type") == "service"

    harness = await build_admin_harness(tmp_path)
    users_route = harness.registry.get("users_add")
    assert users_route is not None
    off_engine = RouterEngine(replace(harness.settings, rbac_mode="off"))
    identity = _identity_from_access_record(access)
    result = await off_engine.execute(
        users_route,
        {
            "email": "attacker@evil.example",
            "full_name": "Intruder",
            "roles": ["administrator"],
        },
        identity=identity,
    )
    assert result["code"] == "forbidden"
    resolved = await harness.directory.resolve_user("attacker@evil.example")
    assert resolved.exists is False


async def test_service_subject_login_still_refused(harness) -> None:
    from conftest import VALID_TOKEN, authorize_to_login, make_pkce

    client = harness.client
    settings = harness.settings
    client_id = await register_client(client)
    _verifier, challenge = make_pkce()
    txn = await authorize_to_login(client, client_id, challenge, settings.resource_url)
    response = await client.post(
        "/login",
        data={"txn": txn, "api_token": VALID_TOKEN, "email": SERVICE_SUBJECT},
    )
    assert response.status_code == 401
    assert "code" not in response.text
