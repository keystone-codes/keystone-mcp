"""file_ref adapter — synchronous signed-link mint, no async 425.

A fake generic object-store API is built with httpx.MockTransport: it captures
the verified identity header and returns the minted link, or 404 when missing.
"""

from __future__ import annotations

import httpx

from keystone_mcp.adapters.file_ref import FileRefAdapter
from keystone_mcp.config import Settings
from keystone_mcp.identity import AUTHOR_EMAIL_HEADER, VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import Param, RouterRegistry

ID = VerifiedIdentity(email="user@example.com")


def _registry(adapter):
    engine = RouterEngine(Settings(base_url="http://localhost:8080"))
    reg = RouterRegistry(engine)
    return engine, reg


async def test_mint_link_for_eph_file_id():
    captured = {"headers": [], "paths": []}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"].append(dict(request.headers))
        captured["paths"].append(request.url.path)
        return httpx.Response(
            200, json={"url": "http://files/d/tok", "expires_at": "2026-06-19T00:00:00+00:00"}
        )

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://localhost:8080"
        )

    adapter = FileRefAdapter("http://localhost:8080", client_factory=factory)
    engine, reg = _registry(adapter)
    route = reg.add_route("get_download_link", adapter, mode="live", params=[Param("file_id", str)])

    out = await engine.execute(route, {"file_id": "eph:uploads/auto/2026/06/abc.dat"}, identity=ID)

    assert out["state"] == "done"
    assert out["file_url"] == "http://files/d/tok"
    assert out["expires_at"]
    assert captured["paths"][0] == "/api/v1/files/uploads/auto/2026/06/abc.dat/download-link"
    assert captured["headers"][0].get(AUTHOR_EMAIL_HEADER.lower()) == "user@example.com"


async def test_missing_object_returns_error_not_pending():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "file_not_found"})

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://localhost:8080"
        )

    adapter = FileRefAdapter("http://localhost:8080", client_factory=factory)
    engine, reg = _registry(adapter)
    route = reg.add_route("get_download_link", adapter, mode="live", params=[Param("file_id", str)])

    out = await engine.execute(route, {"file_id": "eph:uploads/missing.dat"}, identity=ID)
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

    adapter = FileRefAdapter("http://localhost:8080", client_factory=factory)
    engine, reg = _registry(adapter)
    route = reg.add_route("get_download_link", adapter, mode="live", params=[Param("file_id", str)])

    out = await engine.execute(route, {"file_id": "bvs:p1:v2"}, identity=ID)
    assert out["state"] == "error"
    assert out["code"] == "invalid_file_id"
    assert called["n"] == 0
