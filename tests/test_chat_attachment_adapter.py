"""chat_attachment adapter — existence probe + done signal, no session routing."""

from __future__ import annotations

import httpx

from keystone_mcp.adapters.chat_attachment import ChatAttachmentAdapter
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import Param, RouterRegistry

ID = VerifiedIdentity(email="user@example.com")


def _registry(adapter):
    engine = RouterEngine(Settings(base_url="http://localhost:8080"))
    reg = RouterRegistry(engine)
    return engine, reg


async def test_send_chat_attachment_success():
    captured = {"paths": []}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["paths"].append(request.url.path)
        return httpx.Response(
            200, json={"url": "http://files/d/tok", "expires_at": "2026-06-19T00:00:00+00:00"}
        )

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://localhost:8080"
        )

    adapter = ChatAttachmentAdapter("http://localhost:8080", client_factory=factory)
    engine, reg = _registry(adapter)
    route = reg.add_route(
        "send_chat_attachment",
        adapter,
        mode="live",
        params=[Param("file_id", str), Param("caption", str, required=False, default="")],
    )

    out = await engine.execute(
        route,
        {"file_id": "eph:uploads/auto/2026/06/report.pdf", "caption": "Here"},
        identity=ID,
    )

    assert out["state"] == "done"
    assert out["file_id"] == "eph:uploads/auto/2026/06/report.pdf"
    assert out["caption"] == "Here"
    assert captured["paths"][0] == "/api/v1/files/uploads/auto/2026/06/report.pdf/download-link"


async def test_missing_object_returns_file_not_found():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "file_not_found"})

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://localhost:8080"
        )

    adapter = ChatAttachmentAdapter("http://localhost:8080", client_factory=factory)
    engine, reg = _registry(adapter)
    route = reg.add_route(
        "send_chat_attachment",
        adapter,
        mode="live",
        params=[Param("file_id", str)],
    )

    out = await engine.execute(route, {"file_id": "eph:uploads/missing.pdf"}, identity=ID)
    assert out["state"] == "error"
    assert out["code"] == "file_not_found"


async def test_domain_prefix_rejected_without_call():
    called = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["n"] += 1
        return httpx.Response(200, json={})

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://localhost:8080"
        )

    adapter = ChatAttachmentAdapter("http://localhost:8080", client_factory=factory)
    engine, reg = _registry(adapter)
    route = reg.add_route(
        "send_chat_attachment",
        adapter,
        mode="live",
        params=[Param("file_id", str)],
    )

    out = await engine.execute(route, {"file_id": "bvs:p1:v2"}, identity=ID)
    assert out["state"] == "error"
    assert out["code"] == "invalid_file_id"
    assert called["n"] == 0
