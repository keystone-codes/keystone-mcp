"""Router constructor unit tests.

Covers: stub default, stub<->live switch without transport changes,
external_http GET|POST switching, and the unauthorized path. Throttling is
not the engine's job — see tests/test_throttle_middleware.py.
"""

from __future__ import annotations

import httpx
import pytest

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.config import Settings
from keystone_mcp.contrib.adapters.external_http import ExternalHttpAdapter
from keystone_mcp.identity import AUTHOR_EMAIL_HEADER, VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine, UnauthorizedError
from keystone_mcp.router.registry import Param, RouterRegistry

ID = VerifiedIdentity(email="u@example.com")


def _engine():
    return RouterEngine(Settings(base_url="http://localhost:8080"))


async def test_stub_is_default():
    engine = _engine()
    reg = RouterRegistry(engine)
    route = reg.add_route("register_project", StubAdapter())
    assert route.mode == "stub"
    out = await engine.execute(route, {"code": "X"}, identity=ID)
    assert out["stub"] is True
    assert out["state"] == "done"


async def test_mode_switch_changes_dispatch_not_transport():
    captured = {"hit": False}

    def handler(request):
        captured["hit"] = True
        return httpx.Response(200, json={"ok": 1})

    adapter = ExternalHttpAdapter(
        "http://ext",
        method="GET",
        path="/things",
        client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://ext"
        ),
    )
    engine = _engine()
    reg = RouterRegistry(engine)
    route = reg.add_route("project_list", adapter)

    # stub: adapter not touched
    out = await engine.execute(route, {}, identity=ID)
    assert out["stub"] is True
    assert captured["hit"] is False

    # flip to live: same route, adapter now runs
    reg.set_mode("project_list", "live")
    out = await engine.execute(route, {}, identity=ID)
    assert captured["hit"] is True
    assert out["state"] == "done"


async def test_external_http_get_vs_post():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["author"] = request.headers.get(AUTHOR_EMAIL_HEADER.lower())
        return httpx.Response(200, json={"echo": True})

    def make(method):
        return ExternalHttpAdapter(
            "http://ext",
            method=method,
            path="/x",
            client_factory=lambda: httpx.AsyncClient(
                transport=httpx.MockTransport(handler), base_url="http://ext"
            ),
        )

    engine = _engine()
    reg = RouterRegistry(engine)

    rget = reg.add_route("ext_get", make("GET"), mode="live")
    await engine.execute(rget, {"q": "1"}, identity=ID)
    assert seen["method"] == "GET"
    assert seen["author"] == "u@example.com"

    rpost = reg.add_route("ext_post", make("POST"), mode="live")
    await engine.execute(rpost, {"q": "1"}, identity=ID)
    assert seen["method"] == "POST"


async def test_external_http_transform_can_override_method():
    seen = {}

    def handler(request):
        seen["method"] = request.method
        seen["path"] = request.url.path
        return httpx.Response(200, json={})

    adapter = ExternalHttpAdapter(
        "http://ext",
        method="POST",
        path="/default",
        client_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://ext"
        ),
    )
    engine = _engine()
    reg = RouterRegistry(engine)

    def transform(ctx, args):
        return {"method": "GET", "path": "/override", "params": args}

    route = reg.add_route("ext", adapter, mode="live", transform=transform)
    await engine.execute(route, {"a": 1}, identity=ID)
    assert seen["method"] == "GET"
    assert seen["path"] == "/override"


async def test_engine_does_not_throttle():
    """Rate limiting belongs to ThrottleMiddleware; the engine must not count calls."""
    engine = _engine()
    reg = RouterRegistry(engine)
    route = reg.add_route("list_projects", StubAdapter())

    for _ in range(50):
        out = await engine.execute(route, {}, identity=ID)
        assert out["state"] == "done"


async def test_missing_identity_raises_unauthorized():
    engine = _engine()
    reg = RouterRegistry(engine)
    route = reg.add_route("list_projects", StubAdapter())
    with pytest.raises(UnauthorizedError):
        await engine.execute(route, {}, identity=None)


# ── Header precedence: the verified identity is not client-overridable ──────
def _identity_capturing_adapter(captured: dict):
    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json={"ok": True})

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://target.example.com"
        )

    return ExternalHttpAdapter("http://target.example.com", client_factory=factory)


@pytest.mark.parametrize(
    "spoofed",
    [
        {"X-Author-Email": "evil@example.com"},
        {"x-author-email": "evil@example.com"},
        {"X-AUTHOR-EMAIL": "evil@example.com"},
        {"x-Author-eMail": "evil@example.com"},
    ],
)
async def test_transform_headers_cannot_override_the_verified_identity(spoofed: dict):
    """Whatever case it is spelled in, a supplied identity header is discarded."""
    captured: dict = {}
    adapter = _identity_capturing_adapter(captured)
    engine = _engine()
    reg = RouterRegistry(engine)
    route = reg.add_route(
        "call_target",
        adapter,
        mode="live",
        params=[Param("x", str, required=False)],
        transform=lambda ctx, args: {
            "method": "POST",
            "path": "/v1/thing",
            "json": {"x": args.get("x")},
            "headers": spoofed,
        },
    )

    out = await engine.execute(route, {"x": "1"}, identity=ID)
    assert out["state"] == "done"
    assert captured["headers"]["x-author-email"] == ID.email
    assert "evil@example.com" not in captured["headers"].values()


async def test_transform_headers_cannot_inject_authorization():
    """Server-held credentials are not something a caller may supply."""
    captured: dict = {}
    adapter = _identity_capturing_adapter(captured)
    engine = _engine()
    reg = RouterRegistry(engine)
    route = reg.add_route(
        "call_target",
        adapter,
        mode="live",
        transform=lambda ctx, args: {
            "method": "POST",
            "path": "/v1/thing",
            "json": {},
            "headers": {"Authorization": "Bearer stolen", "X-Trace-Id": "abc"},
        },
    )

    await engine.execute(route, {}, identity=ID)
    assert captured["headers"].get("authorization") != "Bearer stolen"
    # Unrelated headers still pass through.
    assert captured["headers"]["x-trace-id"] == "abc"


async def test_benign_transform_headers_are_preserved():
    captured: dict = {}
    adapter = _identity_capturing_adapter(captured)
    engine = _engine()
    reg = RouterRegistry(engine)
    route = reg.add_route(
        "call_target",
        adapter,
        mode="live",
        transform=lambda ctx, args: {
            "method": "GET",
            "path": "/v1/thing",
            "params": {},
            "headers": {"X-Request-Source": "router", "Accept": "application/json"},
        },
    )

    await engine.execute(route, {}, identity=ID)
    assert captured["headers"]["x-request-source"] == "router"
    assert captured["headers"]["accept"] == "application/json"
    assert captured["headers"]["x-author-email"] == ID.email
