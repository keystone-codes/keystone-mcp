"""SEC-51: redirect URI allowlist properties."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx
import hypothesis.strategies as st
import pytest
from hypothesis import given

from keystone_mcp.auth.keystone_oauth_provider import _redirect_uri_allowed

pytestmark = [pytest.mark.security, pytest.mark.fuzz]

allowed_hosts = ("127.0.0.1", "localhost", "app.example.com")


@st.composite
def redirect_uri(draw):
    scheme = draw(st.sampled_from(["http", "https"]))
    host = draw(
        st.one_of(
            st.sampled_from(["127.0.0.1", "localhost", "[::1]", "app.example.com"]),
            st.from_regex(r"[a-z]{3,12}\.example\.com", fullmatch=True),
        )
    )
    port = draw(
        st.one_of(st.just(""), st.integers(min_value=1, max_value=65535).map(lambda p: f":{p}"))
    )
    path = draw(st.from_regex(r"/[a-z_/]{0,20}", fullmatch=True))
    return f"{scheme}://{host}{port}{path}"


@given(uri=redirect_uri())
def test_redirect_uri_allowed_matches_host_rules(uri: str) -> None:
    allowed = _redirect_uri_allowed(uri, allowed_hosts, ())
    parsed = urlparse(uri)
    httpx_host = httpx.URL(uri).host or ""
    host = (parsed.hostname or "").lower()
    loopback = host in {"127.0.0.1", "localhost", "::1"} or httpx_host in {
        "127.0.0.1",
        "localhost",
        "::1",
    }
    listed = host in {"app.example.com"} or httpx_host == "app.example.com"
    if not loopback and not listed:
        assert allowed is False
