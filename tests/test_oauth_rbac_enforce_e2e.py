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

import httpx2
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import ToolError
from httpx2 import ASGITransport, AsyncClient

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import bootstrap_rbac_policy, build_server
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from support.login import dev_token_login
from support.oauth_harness import BASE_URL, obtain_access_token
from support.test_env import UNUSED_REDIS_URL

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
                timeout=timeout or httpx2.Timeout(30.0),
                auth=auth,
                follow_redirects=True,
            )

        return factory

    def transport_for(self, token: str) -> StreamableHttpTransport:
        return StreamableHttpTransport(
            self.settings.transport_url,
            auth=token,
            httpx_client_factory=self.mcp_client_factory(),
        )


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
        redis_url=UNUSED_REDIS_URL,
    )

    resolver, backend, revision = build_in_memory_user_directory_resolver()
    backend.seed(VIEWER_EMAIL, roles=("viewer",))

    _login = dev_token_login({VALID_TOKEN})
    store = InMemoryOAuthStore()

    mcp, registry, _oauth, _upstreams, policy_manager, _observability, _reconciler = build_server(
        login_providers=[_login],
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
    async with Client(enforce_harness.transport_for(token)) as client:
        tools = await client.list_tools()
        names = {t.name for t in tools}
        assert "e2e_ping" in names
        assert "e2e_secret" not in names


async def test_viewer_call_to_forbidden_tool_is_denied(enforce_harness):
    token = await _viewer_token(enforce_harness)
    async with Client(enforce_harness.transport_for(token)) as client:
        with pytest.raises(ToolError, match="access denied"):
            await client.call_tool("e2e_secret", {})

    assert enforce_harness.secret_adapter.calls == 0


async def test_viewer_call_to_allowed_tool_succeeds(enforce_harness):
    token = await _viewer_token(enforce_harness)
    async with Client(enforce_harness.transport_for(token)) as client:
        result = await client.call_tool("e2e_ping", {})
        assert result.data["state"] == "done"


async def test_blocked_user_is_denied_with_live_token(enforce_harness):
    token = await _viewer_token(enforce_harness)

    enforce_harness.backend.block(VIEWER_EMAIL)
    enforce_harness.revision.bump()

    async with Client(enforce_harness.transport_for(token)) as client:
        with pytest.raises(ToolError):
            await client.call_tool("e2e_ping", {})
