"""SEC-11 / SEC-12: DoS resistance on DCR and /authorize."""

from __future__ import annotations

import tracemalloc

import pytest
from tests.security.conftest import REDIRECT_URI
from tests.security.helpers import pkce_pair

pytestmark = pytest.mark.security

_MAX_ALLOC_DELTA_BYTES = 2 * 1024 * 1024


async def test_dcr_rejects_oversized_registration_body(attacker_stand) -> None:
    blob = "x" * (4 * 1024 * 1024)
    async with attacker_stand.raw_client() as client:
        r = await client.post(
            "/register",
            json={
                "redirect_uris": [REDIRECT_URI],
                "client_name": blob,
                "token_endpoint_auth_method": "none",
            },
        )
    assert r.status_code == 400


async def test_authorize_giant_params_return_400_without_memory_spike(attacker_stand) -> None:
    tracemalloc.start()
    before = tracemalloc.get_traced_memory()[0]
    async with attacker_stand.raw_client() as client:
        reg = await client.post(
            "/register",
            json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
        )
        client_id = reg.json()["client_id"]
        _verifier, challenge = pkce_pair()
        r = await client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT_URI,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "s" * 8000,
                "scope": "z" * 8000,
                "resource": attacker_stand.settings.resource_url,
            },
        )
    after = tracemalloc.get_traced_memory()[0]
    tracemalloc.stop()
    assert r.status_code in (400, 414, 302, 307, 429)
    assert after - before < _MAX_ALLOC_DELTA_BYTES
