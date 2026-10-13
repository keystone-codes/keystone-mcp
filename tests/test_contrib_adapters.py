"""keystone_mcp.contrib.adapters.webhook: settings read at construction time.

WebhookSettings.from_env() is called from WebhookAdapter.__init__, not from
execute(): a fork that constructs the adapter once at startup must see the
same environment a running server would. Core Settings must carry none of the
fields the webhook adapter used to read from it.
"""

from __future__ import annotations

import pytest

from keystone_mcp.config import Settings
from keystone_mcp.contrib.adapters.webhook import WebhookAdapter, WebhookSettings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import Param, RouterRegistry

ENV_NAMES = (
    "KEYSTONE_MCP_CONTRIB_WEBHOOK_BASE_URL",
    "KEYSTONE_MCP_CONTRIB_WEBHOOK_CLIENT",
    "KEYSTONE_MCP_CONTRIB_WEBHOOK_PROJECT",
    "KEYSTONE_MCP_CONTRIB_WEBHOOK_API_TOKEN",
    "KEYSTONE_MCP_CONTRIB_WEBHOOK_LONG_POLL_SECONDS",
)


def test_webhook_reads_contrib_variables_on_construction(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_CONTRIB_WEBHOOK_BASE_URL", "http://localhost:9000")
    monkeypatch.setenv("KEYSTONE_MCP_CONTRIB_WEBHOOK_CLIENT", "acme")
    monkeypatch.setenv("KEYSTONE_MCP_CONTRIB_WEBHOOK_PROJECT", "demo-project")
    monkeypatch.setenv("KEYSTONE_MCP_CONTRIB_WEBHOOK_API_TOKEN", "secret-token")
    monkeypatch.setenv("KEYSTONE_MCP_CONTRIB_WEBHOOK_LONG_POLL_SECONDS", "7")

    adapter = WebhookAdapter()

    assert adapter._settings == WebhookSettings(
        base_url="http://localhost:9000",
        client="acme",
        project="demo-project",
        api_token="secret-token",
        long_poll_seconds=7,
    )


async def test_webhook_without_base_url_is_unconfigured(monkeypatch):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)

    def _factory():
        raise AssertionError("no network call should be made when unconfigured")

    adapter = WebhookAdapter(client_factory=_factory)

    engine = RouterEngine(Settings(base_url="http://localhost:8080"))
    reg = RouterRegistry(engine)
    route = reg.add_route("submit_task", adapter, mode="live", params=[Param("x", str)])

    out = await engine.execute(route, {"x": "1"}, identity=VerifiedIdentity(email="d@example.com"))
    assert out["state"] == "error"
    assert out["code"] == "webhook_target_unconfigured"


def test_webhook_long_poll_must_be_integer(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_CONTRIB_WEBHOOK_LONG_POLL_SECONDS", "abc")
    with pytest.raises(ValueError, match="KEYSTONE_MCP_CONTRIB_WEBHOOK_LONG_POLL_SECONDS"):
        WebhookSettings.from_env()


def test_core_settings_have_no_webhook_fields():
    settings = Settings(base_url="http://localhost:8080")
    assert not hasattr(settings, "webhook_base_url")
    assert not hasattr(settings, "webhook_client_id")
    assert not hasattr(settings, "webhook_project_id")
    assert not hasattr(settings, "webhook_api_token")
    assert not hasattr(settings, "long_poll_seconds")
