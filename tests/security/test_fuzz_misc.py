"""SEC-54…SEC-56: request_state, env_bool, login form fuzzing."""

from __future__ import annotations

import hypothesis.strategies as st
import pytest
from hypothesis import given
from hypothesis import settings as hypo_settings

from keystone_mcp.config import ConfigError, _env_bool
from keystone_mcp.router.upstream_call import _decode_keystone_request_state

pytestmark = [pytest.mark.security, pytest.mark.fuzz]


@given(raw=st.text(max_size=200))
def test_decode_request_state_never_raises(raw: str) -> None:
    state, declined, rounds = _decode_keystone_request_state(raw)
    assert isinstance(declined, list)
    assert isinstance(rounds, int)
    assert rounds >= 0


@given(
    name=st.sampled_from(["KEYSTONE_MCP_LOG_REDACT"]),
    raw=st.text(min_size=1, max_size=20),
)
def test_env_bool_never_silent_false_for_unknown(monkeypatch, name: str, raw: str) -> None:
    if raw.strip().lower() in {"1", "true", "yes", "on", "0", "false", "no", "off", ""}:
        return
    try:
        monkeypatch.setenv(name, raw)
    except ValueError:
        return
    try:
        value = _env_bool(name, True)
    except ConfigError:
        return
    except Exception as exc:
        raise AssertionError(f"unexpected {exc!r}") from exc
    if value is False:
        raise AssertionError("unknown env string was silently treated as false")


@hypo_settings(deadline=None)
@given(payload=st.dictionaries(st.text(max_size=12), st.text(max_size=200), max_size=8))
@pytest.mark.asyncio
async def test_login_post_random_fields_not_500(attacker_stand, payload):
    import httpx
    from asgi_lifespan import LifespanManager

    from security.conftest import BASE_URL

    async with LifespanManager(attacker_stand.app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=attacker_stand.app),
            base_url=BASE_URL,
        ) as client:
            response = await client.post("/login", data=payload)
            assert response.status_code != 500
