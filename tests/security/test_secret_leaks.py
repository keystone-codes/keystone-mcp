"""SEC-10: secrets must not appear in logs or HTTP bodies at DEBUG."""

from __future__ import annotations

import logging
from dataclasses import replace

import pytest

from keystone_mcp.observability.logging import configure_logging
from security.conftest import DEV_TOKEN, REDIRECT_URI
from security.helpers import obtain_bearer_token, pkce_pair

pytestmark = pytest.mark.security


@pytest.fixture
def debug_redacted_logs(attacker_stand, monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("KEYSTONE_MCP_LOG_REDACT", "true")
    settings = replace(attacker_stand.settings, log_level="DEBUG", log_redact=True)
    configure_logging(settings)
    return settings


async def test_oauth_flow_leaves_no_raw_secrets_in_logs_or_bodies(
    attacker_stand, debug_redacted_logs, caplog
) -> None:
    caplog.set_level(logging.DEBUG)
    secrets_to_hunt = {DEV_TOKEN, attacker_stand.dev_token}
    bodies: list[str] = []

    verifier, challenge = pkce_pair()
    async with attacker_stand.raw_client() as client:
        reg = await client.post(
            "/register",
            json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
        )
        bodies.append(reg.text)
        client_id = reg.json()["client_id"]
        auth = await client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "s",
                "resource": attacker_stand.settings.resource_url,
            },
        )
        bodies.append(auth.text)
        from urllib.parse import parse_qs, urlparse

        from security.conftest import parse_csrf

        txn = parse_qs(urlparse(auth.headers["location"]).query)["txn"][0]
        page = await client.get(f"/login?txn={txn}")
        bodies.append(page.text)
        csrf = parse_csrf(page.text)
        bad = await client.post(
            "/login",
            data={"txn": txn, "csrf": csrf, "api_token": "wrong-secret", "email": "member@sec.test"},
        )
        bodies.append(bad.text)

    await obtain_bearer_token(attacker_stand, email="member@sec.test")
    async with attacker_stand.raw_client() as client:
        fail = await client.post(
            "/token",
            data={"grant_type": "refresh_token", "refresh_token": "not-a-real-refresh"},
        )
        bodies.append(fail.text)

    combined_logs = "\n".join(r.getMessage() for r in caplog.records)
    combined_bodies = "\n".join(bodies)
    for secret in secrets_to_hunt:
        if len(secret) < 8:
            continue
        assert secret not in combined_logs, f"secret leaked to logs: {secret[:6]}..."
        assert secret not in combined_bodies, f"secret leaked to response body: {secret[:6]}..."
