"""End-to-end test: real OAuth bearer token, RBAC ``enforce``, denied ``call_tool``.

Every other RBAC test drives the middleware with a verified identity injected
by ``monkeypatch`` (see ``test_rbac_middleware_mounted_coverage.py``), and every
OAuth connector test (``test_mcp_tool_call.py``) runs with RBAC disabled. This
file is the one place a real token from ``/token`` goes through the full
OAuth -> identity -> RBAC chain in ``rbac_mode="enforce"`` and is denied by a
role's policy, proving the "token -> identity -> role" link end to end.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from httpx import ASGITransport, AsyncClient

from conftest import BASE_URL, mcp_client_session, obtain_access_token
from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import bootstrap_rbac_policy, build_server
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver

VALID_TOKEN = "valid-test-token"
VIEWER_EMAIL = "viewer@example.com"

ENFORCE_POLICY = """\
version: "1.0.0"
default_deny: true
roles:
  administrator:
    allow: ["*"]
  viewer:
    allow: ["e2e_ping"]
requires_human_identity: []
critical_tools: []
"""


class CountingStubAdapter(StubAdapter):
    """A :class:`StubAdapter` that counts how many times it actually ran.

    Used on the forbidden route to prove a denied ``call_tool`` never reaches
    the adapter: the RBAC middleware must short-circuit before the engine
    dispatches to ``execute``.
    """

    def __init__(self) -> None:
        self.calls = 0

    async def execute(self, route, ctx, args, request):  # noqa: ANN001
        self.calls += 1
        return await super().execute(route, ctx, args, request)


class EnforceHarness:
    def __init__(
        self, app, settings: Settings, client: AsyncClient, backend, revision, secret_adapter
    ):
        self.app = app
        self.settings = settings
        self.client = client
        self.backend = backend
        self.revision = revision
        self.secret_adapter = secret_adapter

    def mcp_client_factory(self):
        app = self.app

        def factory(headers=None, timeout=None, auth=None, **_kw):
            return AsyncClient(
                transport=ASGITransport(app=app),
                base_url=BASE_URL,
                headers=headers,
                timeout=timeout or httpx.Timeout(30.0),
                auth=auth,
                follow_redirects=True,
            )

        return factory

    def transport_factory_for(self, token: str):
        """A factory building a fresh transport per connection attempt.

        ``mcp_client_session`` retries brief transport flakes by calling this
        again, so it must not hand back an already-used transport instance.
        """
        client_factory = self.mcp_client_factory()

        def factory():
            return StreamableHttpTransport(
                self.settings.transport_url,
                auth=token,
                httpx_client_factory=client_factory,
            )

        return factory


@pytest_asyncio.fixture
async def enforce_harness(tmp_path: Path):
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(ENFORCE_POLICY, encoding="utf-8")

    settings = Settings(
        base_url=BASE_URL,
        refresh_interval_seconds=0,
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        rbac_audit_subject_salt="e2e-salt",
        redis_url="redis://localhost:6379/0",
    )

    resolver, backend, revision = build_in_memory_user_directory_resolver()
    backend.seed(VIEWER_EMAIL, roles=("viewer",))

    idp = StaticIdentityProvider({VALID_TOKEN})
    store = InMemoryOAuthStore()

    mcp, registry, _oauth, _upstreams, policy_manager, _observability, _reconciler = build_server(
        identity_provider=idp,
        settings=settings,
        oauth_store=store,
        user_resolver=resolver,
        register_builtin_catalog=False,
    )

    secret_adapter = CountingStubAdapter()
    registry.add_route("e2e_ping", StubAdapter(), mode="live", description="Allowed test route.")
    registry.add_route(
        "e2e_secret", secret_adapter, mode="live", description="Forbidden test route."
    )

    bootstrap_rbac_policy(policy_manager, registry)

    app = mcp.http_app(path=settings.http_path)
    async with LifespanManager(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url=BASE_URL) as client:
            yield EnforceHarness(
                app=app,
                settings=settings,
                client=client,
                backend=backend,
                revision=revision,
                secret_adapter=secret_adapter,
            )


async def _viewer_token(harness: EnforceHarness) -> str:
    res = await obtain_access_token(
        harness.client, harness.settings.resource_url, email=VIEWER_EMAIL
    )
    return res["body"]["access_token"]


async def test_viewer_lists_only_allowed_tools(enforce_harness):
    token = await _viewer_token(enforce_harness)
    transport_factory = enforce_harness.transport_factory_for(token)

    async with mcp_client_session(transport_factory=transport_factory) as client:
        tools = await client.list_tools()
        names = {t.name for t in tools}
        assert "e2e_ping" in names
        assert "e2e_secret" not in names


async def test_viewer_call_to_forbidden_tool_is_denied(enforce_harness):
    token = await _viewer_token(enforce_harness)
    transport_factory = enforce_harness.transport_factory_for(token)

    async with mcp_client_session(transport_factory=transport_factory) as client:
        with pytest.raises(ToolError, match="access denied"):
            await client.call_tool("e2e_secret", {})

    assert enforce_harness.secret_adapter.calls == 0


async def test_viewer_call_to_allowed_tool_succeeds(enforce_harness):
    token = await _viewer_token(enforce_harness)
    transport_factory = enforce_harness.transport_factory_for(token)

    async with mcp_client_session(transport_factory=transport_factory) as client:
        result = await client.call_tool("e2e_ping", {})
        assert result.data["state"] == "done"


async def test_blocked_user_is_denied_with_live_token(enforce_harness):
    token = await _viewer_token(enforce_harness)
    transport_factory = enforce_harness.transport_factory_for(token)

    enforce_harness.backend.block(VIEWER_EMAIL)
    enforce_harness.revision.bump()

    async with mcp_client_session(transport_factory=transport_factory) as client:
        with pytest.raises(ToolError):
            await client.call_tool("e2e_ping", {})
