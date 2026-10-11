"""Webhook adapter: identity propagation + peek short-circuit (deliverables 1, 4).

Asserts the verified email reaches downstream as X-Author-Email and that a
previously published result short-circuits the webhook (peek before submit).
A fake K2/webhook is built with httpx.MockTransport capturing request headers.
"""

from __future__ import annotations

import httpx

from keystone_mcp.adapters.webhook import WebhookAdapter
from keystone_mcp.config import Settings
from keystone_mcp.identity import AUTHOR_EMAIL_HEADER, VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import Param, RouterRegistry


def _registry(adapter):
    settings = Settings(
        base_url="http://localhost:8080",
        webhook_client_id="acme",
        webhook_project_id="demo-project",
    )
    engine = RouterEngine(settings)
    reg = RouterRegistry(engine)  # no FastMCP — exercise the engine directly
    return settings, engine, reg


async def test_email_propagated_as_x_author_email():
    captured = {"headers": [], "submitted": False}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"].append(dict(request.headers))
        if request.url.path.endswith("/result"):
            if not captured["submitted"]:
                return httpx.Response(404)
            return httpx.Response(200, json={"state": "done", "result": {"ok": True}})
        captured["submitted"] = True
        return httpx.Response(202, json={"status": "accepted"})

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://localhost:8080"
        )

    adapter = WebhookAdapter(client_factory=factory, poll_interval=0.0)
    settings, engine, reg = _registry(adapter)
    route = reg.add_route(
        "apply_changes",
        adapter,
        mode="live",
        params=[Param("project_id", str), Param("changes", dict)],
    )

    identity = VerifiedIdentity(email="bob@example.com")
    out = await engine.execute(route, {"project_id": "p1", "changes": {"a": 1}}, identity=identity)

    assert out["state"] == "done"
    assert out["result"] == {"ok": True}
    # Every downstream request carried the verified identity.
    assert all(h.get(AUTHOR_EMAIL_HEADER.lower()) == "bob@example.com" for h in captured["headers"])
    assert captured["submitted"] is True


async def test_peek_short_circuits_webhook():
    """A done result on peek must return immediately without POSTing the webhook."""
    posted = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/result"):
            return httpx.Response(200, json={"state": "done", "result": {"cached": True}})
        posted["count"] += 1
        return httpx.Response(202)

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://localhost:8080"
        )

    adapter = WebhookAdapter(client_factory=factory, poll_interval=0.0)
    settings, engine, reg = _registry(adapter)
    route = reg.add_route("get_totals", adapter, mode="live", params=[Param("project_id", str)])

    out = await engine.execute(
        route, {"project_id": "p1"}, identity=VerifiedIdentity(email="c@example.com")
    )
    assert out["state"] == "done"
    assert out["result"] == {"cached": True}
    assert posted["count"] == 0  # webhook never sent


async def test_webhook_refuses_when_client_and_project_are_unset():
    """The webhook route segments have no default; an unset target must not be posted."""
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(404)

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://localhost:8080"
        )

    adapter = WebhookAdapter(client_factory=factory, poll_interval=0.0)
    settings = Settings(base_url="http://localhost:8080")
    assert settings.webhook_client_id == ""
    assert settings.webhook_project_id == ""
    engine = RouterEngine(settings)
    reg = RouterRegistry(engine)
    route = reg.add_route("submit_task", adapter, mode="live", params=[Param("x", str)])

    out = await engine.execute(route, {"x": "1"}, identity=VerifiedIdentity(email="d@example.com"))
    assert out["state"] == "error"
    assert out["code"] == "webhook_target_unconfigured"
    assert calls["count"] == 0
