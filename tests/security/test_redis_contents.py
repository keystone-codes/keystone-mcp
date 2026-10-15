"""SEC-15: Redis must not store raw OAuth tokens."""

from __future__ import annotations

import pytest

from keystone_mcp.auth.oauth_store import RedisOAuthStore
from security.helpers import obtain_bearer_token

pytestmark = pytest.mark.security


async def test_redis_has_no_raw_access_or_refresh_tokens(attacker_stand) -> None:
    token = await obtain_bearer_token(attacker_stand, email="member@sec.test")
    async with attacker_stand.raw_client() as client:
        reg = await client.post(
            "/register",
            json={
                "redirect_uris": ["http://127.0.0.1:9999/callback"],
                "token_endpoint_auth_method": "none",
            },
        )
        _ = reg.json()["client_id"]

    store = attacker_stand.oauth_store
    if not isinstance(store, RedisOAuthStore):
        pytest.skip("Redis OAuth store required")
    cursor = 0
    prefix = store._prefix  # noqa: SLF001
    while True:
        cursor, keys = await store.redis.scan(cursor, match=f"{prefix}*", count=200)
        for key in keys:
            kind = await store.redis.type(key)
            if kind == b"string":
                val = await store.redis.get(key)
                if val is None:
                    continue
                text = val.decode("utf-8", errors="replace")
                assert token not in text
            elif kind == b"hash":
                vals = await store.redis.hgetall(key)
                blob = b"".join(vals.values())
                assert token.encode() not in blob
        if cursor == 0:
            break
