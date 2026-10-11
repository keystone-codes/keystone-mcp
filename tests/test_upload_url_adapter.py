"""upload_url adapter (two-phase upload) — mint a signed PUT link.

A fake generic object-store API is built with httpx.MockTransport: it captures
the verified identity header and the request body, and returns the minted upload
URL + reserved eph: file_id.
"""

from __future__ import annotations

import httpx

from keystone_mcp.adapters.upload_url import UploadUrlAdapter
from keystone_mcp.config import Settings
from keystone_mcp.identity import AUTHOR_EMAIL_HEADER, VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import Param, RouterRegistry

ID = VerifiedIdentity(email="user@example.com")


def _registry():
    engine = RouterEngine(Settings(base_url="http://localhost:8080"))
    return engine, RouterRegistry(engine)


def _params():
    return [
        Param("filename", str, required=False, default=None),
        Param("content_type", str, required=False, default=None),
    ]


async def test_mint_upload_url_returns_link_and_file_id():
    captured = {"headers": [], "paths": [], "bodies": []}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"].append(dict(request.headers))
        captured["paths"].append(request.url.path)
        captured["bodies"].append(request.content)
        return httpx.Response(
            200,
            json={
                "upload_url": "http://files/u/tok",
                "file_id": "eph:uploads/auto/2026/06/abc.dat",
                "key": "uploads/auto/2026/06/abc.dat",
                "expires_at": "2026-06-19T00:10:00+00:00",
                "max_bytes": 52428800,
            },
        )

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://localhost:8080"
        )

    adapter = UploadUrlAdapter("http://localhost:8080", client_factory=factory)
    engine, reg = _registry()
    route = reg.add_route("create_upload_url", adapter, mode="live", params=_params())

    out = await engine.execute(route, {"filename": "report.csv"}, identity=ID)

    assert out["state"] == "done"
    assert out["upload_url"] == "http://files/u/tok"
    assert out["file_id"] == "eph:uploads/auto/2026/06/abc.dat"
    assert out["expires_at"]
    assert out["max_bytes"] == 52428800
    assert captured["paths"][0] == "/api/v1/files/upload-link"
    assert captured["headers"][0].get(AUTHOR_EMAIL_HEADER.lower()) == "user@example.com"
    assert b"report.csv" in captured["bodies"][0]
