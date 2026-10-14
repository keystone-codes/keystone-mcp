"""hello-upstream verifies X-Keystone-Identity (Y02).

Loads examples/hello-upstream/server.py by path -- the exact file the demo
compose stack runs -- and drives it two ways: through Keystone's own
UpstreamRegistry (what a real deployment does), and directly with a raw
fastmcp.Client standing in for anyone who tries to reach the service
straight, bypassing Keystone, with a missing or forged assertion.

``server.py`` is written against MCP Python SDK 1.x's decorator-based
``Server`` API (the Dockerfile pins that version on purpose -- see the
module's own docstring), but also supports SDK 2.x's constructor-based API
(``on_list_tools``/``on_call_tool``), which is what this project's own test
suite has installed (``mcp>=2,<3``); ``_build_server`` there picks whichever
the installed SDK supports. Either way the tool logic under test is
identical.

The server reads ``HELLO_IDENTITY_SECRET``/``HELLO_IDENTITY_AUDIENCE`` from
the environment once at import time, so each test reloads the module under
its own ``monkeypatch``-ed environment rather than sharing one import.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
import uuid
from pathlib import Path

import jwt
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport

from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry
from support.lowlevel_upstream import UPSTREAM_MCP_URL, asgi_http_client_factory

REPO_ROOT = Path(__file__).resolve().parents[1]
HELLO_UPSTREAM_DIR = REPO_ROOT / "examples" / "hello-upstream"
SERVER_PATH = HELLO_UPSTREAM_DIR / "server.py"

ANN = VerifiedIdentity(email="ann@example.com")
SECRET = "hello-test-identity-secret-" + "x" * 16  # well over MIN_SECRET_BYTES
OTHER_SECRET = "a-completely-different-secret-" + "y" * 10
AUDIENCE = "hello"
#: Env var name Keystone-MCP itself reads the secret from, for the
#: through-Keystone test -- distinct from HELLO_IDENTITY_SECRET, which is
#: hello-upstream's own setting.
KEYSTONE_SECRET_ENV = "KEYSTONE_MCP_UPSTREAM_HELLO_TEST_IDENTITY_SECRET"


def _load_hello_module(
    monkeypatch,
    *,
    secret: str | None,
    audience: str | None = None,
    issuer: str | None = "http://localhost:8080",
):
    """(Re)load examples/hello-upstream/server.py under a fresh environment.

    A new module name each time: the server's identity settings are only
    read once, at import time, into module-level constants.
    """
    if secret is None:
        monkeypatch.delenv("HELLO_IDENTITY_SECRET", raising=False)
    else:
        monkeypatch.setenv("HELLO_IDENTITY_SECRET", secret)
    if audience is None:
        monkeypatch.delenv("HELLO_IDENTITY_AUDIENCE", raising=False)
    else:
        monkeypatch.setenv("HELLO_IDENTITY_AUDIENCE", audience)
    if issuer is None:
        monkeypatch.delenv("HELLO_IDENTITY_ISSUER", raising=False)
    else:
        monkeypatch.setenv("HELLO_IDENTITY_ISSUER", issuer)

    # server.py does `import keystone_identity` as a plain top-level module
    # (it is a sibling file, not a package) -- make that resolvable.
    if str(HELLO_UPSTREAM_DIR) not in sys.path:
        sys.path.insert(0, str(HELLO_UPSTREAM_DIR))

    spec = importlib.util.spec_from_file_location(f"_hello_server_{uuid.uuid4().hex}", SERVER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _make_token(*, secret: str, audience: str, sub: str = "ann@example.com") -> str:
    now = int(time.time())
    claims = {
        "iss": "http://localhost:8080",
        "aud": audience,
        "sub": sub,
        "iat": now,
        "exp": now + 300,
    }
    return jwt.encode(claims, secret, algorithm="HS256", headers={"typ": "keystone-identity+jwt"})


@pytest.fixture(autouse=True)
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ANN)


async def test_call_through_keystone_is_accepted(monkeypatch):
    """The normal path: Keystone signs the assertion, hello-upstream accepts it."""
    hello = _load_hello_module(monkeypatch, secret=SECRET)
    monkeypatch.setenv(KEYSTONE_SECRET_ENV, SECRET)

    async with LifespanManager(hello.app):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(hello.app),
            identity_issuer=settings.base_url.rstrip("/"),
        )
        upstreams.add_upstream(
            AUDIENCE,
            UPSTREAM_MCP_URL,
            namespace="hello",
            identity_secret_env=KEYSTONE_SECRET_ENV,
        )
        await upstreams.discover_all()

        async with Client(main) as client:
            result = await client.call_tool_mcp("hello_whoami", {})

    assert result.is_error is False
    payload = json.loads(result.content[0].text)
    assert payload["verified"] is True
    assert payload["sub"] == "ann@example.com"
    assert payload["mcp_target"] == "whoami"


async def test_forged_author_email_is_rejected(monkeypatch):
    """A client talking straight to hello-upstream, no assertion, forged email."""
    hello = _load_hello_module(monkeypatch, secret=SECRET)

    async with LifespanManager(hello.app):
        http_client_factory = asgi_http_client_factory(hello.app)

        def direct_factory(headers=None, timeout=None, **_kw):
            merged = dict(headers or {})
            merged["X-Author-Email"] = "boss@example.com"
            transport = StreamableHttpTransport(
                UPSTREAM_MCP_URL,
                headers=merged,
                httpx_client_factory=http_client_factory(timeout or 30.0),
            )
            return Client(transport, timeout=timeout)

        async with direct_factory() as direct:
            result = await direct.call_tool_mcp("whoami", {})

    assert result.is_error is True
    assert "identity rejected" in result.content[0].text


async def test_assertion_signed_with_wrong_secret_is_rejected(monkeypatch):
    hello = _load_hello_module(monkeypatch, secret=SECRET)
    forged = _make_token(secret=OTHER_SECRET, audience=AUDIENCE)

    async with LifespanManager(hello.app):
        http_client_factory = asgi_http_client_factory(hello.app)
        transport = StreamableHttpTransport(
            UPSTREAM_MCP_URL,
            headers={"X-Keystone-Identity": forged},
            httpx_client_factory=http_client_factory(30.0),
        )
        async with Client(transport) as direct:
            result = await direct.call_tool_mcp("whoami", {})

    assert result.is_error is True
    assert "identity rejected" in result.content[0].text


async def test_assertion_for_other_service_is_rejected(monkeypatch):
    """Signed with the right secret, but for a different upstream's audience."""
    hello = _load_hello_module(monkeypatch, secret=SECRET)
    forged = _make_token(secret=SECRET, audience="docs")

    async with LifespanManager(hello.app):
        http_client_factory = asgi_http_client_factory(hello.app)
        transport = StreamableHttpTransport(
            UPSTREAM_MCP_URL,
            headers={"X-Keystone-Identity": forged},
            httpx_client_factory=http_client_factory(30.0),
        )
        async with Client(transport) as direct:
            result = await direct.call_tool_mcp("whoami", {})

    assert result.is_error is True
    assert "identity rejected" in result.content[0].text


async def test_list_tools_needs_no_identity(monkeypatch):
    hello = _load_hello_module(monkeypatch, secret=SECRET)

    async with LifespanManager(hello.app):
        http_client_factory = asgi_http_client_factory(hello.app)
        transport = StreamableHttpTransport(
            UPSTREAM_MCP_URL,
            httpx_client_factory=http_client_factory(30.0),
        )
        async with Client(transport) as direct:
            tools = await direct.list_tools()

    assert {t.name for t in tools} == {
        "greet",
        "search",
        "whoami",
        "slow_count",
        "ask_name",
    }


async def test_slow_count_through_keystone(monkeypatch):
    hello = _load_hello_module(monkeypatch, secret=SECRET)
    monkeypatch.setenv(KEYSTONE_SECRET_ENV, SECRET)

    async with LifespanManager(hello.app):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(hello.app),
            identity_issuer=settings.base_url.rstrip("/"),
        )
        upstreams.add_upstream(
            AUDIENCE,
            UPSTREAM_MCP_URL,
            namespace="hello",
            identity_secret_env=KEYSTONE_SECRET_ENV,
        )
        await upstreams.discover_all()

        async with Client(main) as client:
            result = await client.call_tool_mcp("hello_slow_count", {"n": 1})

    assert result.is_error is False
    assert result.content[0].text == "counted to 1"


async def test_ask_name_through_keystone_without_elicitation(monkeypatch):
    """Without a client elicitation handler, ask_name answers no-elicitation."""
    hello = _load_hello_module(monkeypatch, secret=SECRET)
    monkeypatch.setenv(KEYSTONE_SECRET_ENV, SECRET)

    async with LifespanManager(hello.app):
        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-test")
        registry = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry,
            http_client_factory=asgi_http_client_factory(hello.app),
            identity_issuer=settings.base_url.rstrip("/"),
        )
        upstreams.add_upstream(
            AUDIENCE,
            UPSTREAM_MCP_URL,
            namespace="hello",
            identity_secret_env=KEYSTONE_SECRET_ENV,
        )
        await upstreams.discover_all()

        async with Client(main) as client:
            result = await client.call_tool_mcp("hello_ask_name", {})

    assert result.is_error is False
    assert result.content[0].text in {"no-elicitation", "elicitation not available in this SDK"}
