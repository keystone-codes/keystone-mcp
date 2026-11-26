"""Webhook adapter: identity propagation + peek short-circuit (deliverables 1, 4).

Asserts the verified email reaches downstream as X-Author-Email and that a
previously published result short-circuits the webhook (peek before submit).
A fake K2/webhook is built with httpx.MockTransport capturing request headers.
"""

from __future__ import annotations

import logging

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keystone_mcp.config import Settings
from keystone_mcp.contrib.adapters.external_http import ExternalHttpAdapter
from keystone_mcp.contrib.adapters.webhook import WebhookAdapter, WebhookSettings
from keystone_mcp.identity import AUTHOR_EMAIL_HEADER, VerifiedIdentity
from keystone_mcp.identity_assertion import IDENTITY_HEADER, IDENTITY_TYP, build_identity_jwks
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import Param, RouterRegistry

WEBHOOK_SETTINGS = WebhookSettings(
    base_url="http://localhost:8080", client="acme", project="demo-project"
)


def _registry(adapter):
    settings = Settings(base_url="http://localhost:8080")
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

    adapter = WebhookAdapter(WEBHOOK_SETTINGS, client_factory=factory, poll_interval=0.0)
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
    # Every downstream request carried the verified identity, and no signed header.
    assert all(h.get(AUTHOR_EMAIL_HEADER.lower()) == "bob@example.com" for h in captured["headers"])
    assert all(IDENTITY_HEADER.lower() not in h for h in captured["headers"])
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

    adapter = WebhookAdapter(WEBHOOK_SETTINGS, client_factory=factory, poll_interval=0.0)
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

    unconfigured = WebhookSettings()
    assert unconfigured.client == ""
    assert unconfigured.project == ""
    adapter = WebhookAdapter(unconfigured, client_factory=factory, poll_interval=0.0)
    settings = Settings(base_url="http://localhost:8080")
    engine = RouterEngine(settings)
    reg = RouterRegistry(engine)
    route = reg.add_route("submit_task", adapter, mode="live", params=[Param("x", str)])

    out = await engine.execute(route, {"x": "1"}, identity=VerifiedIdentity(email="d@example.com"))
    assert out["state"] == "error"
    assert out["code"] == "webhook_target_unconfigured"
    assert calls["count"] == 0


def _signing_material():
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode(
        "utf-8"
    )
    return private_key, pem


async def _exchange(identity: VerifiedIdentity, *, identity_signing_key: str = ""):
    """Peek, submit, then poll. Returns the tool result and each request's headers."""
    captured: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(dict(request.headers))
        if request.method == "GET" and len(captured) == 1:
            return httpx.Response(404)
        if request.method == "POST":
            return httpx.Response(202, json={"status": "accepted"})
        return httpx.Response(200, json={"state": "done", "result": {"ok": True}})

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://localhost:8080"
        )

    adapter = WebhookAdapter(WEBHOOK_SETTINGS, client_factory=factory, poll_interval=0.0)
    settings = Settings(
        base_url="http://localhost:8080",
        identity_signing_key=identity_signing_key,
    )
    engine = RouterEngine(settings)
    reg = RouterRegistry(engine)
    route = reg.add_route(
        "apply_changes",
        adapter,
        mode="live",
        params=[Param("project_id", str)],
    )
    out = await engine.execute(route, {"project_id": "p1"}, identity=identity)
    return out, captured


def _assert_webhook_jwt(headers: dict[str, str], private_key, *, email: str | None) -> None:
    token = headers[IDENTITY_HEADER.lower()]
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "ES256"
    assert header["typ"] == IDENTITY_TYP
    jwks = build_identity_jwks(private_key)
    assert header["kid"] == jwks["keys"][0]["kid"]
    claims = jwt.decode(
        token,
        private_key.public_key(),
        algorithms=["ES256"],
        audience="keystone",
        issuer="http://localhost:8080",
    )
    assert claims["aud"] == "keystone"
    assert claims["iss"] == "http://localhost:8080"
    assert claims["mcp_method"] == "tools/call"
    assert claims["mcp_target"] == "apply_changes"
    if email is None:
        assert "email" not in claims
        assert AUTHOR_EMAIL_HEADER.lower() not in headers
    else:
        assert claims["email"] == email
        assert headers[AUTHOR_EMAIL_HEADER.lower()] == email


async def test_webhook_sends_signed_identity_when_key_set():
    private_key, pem = _signing_material()
    out, captured = await _exchange(
        VerifiedIdentity(email="bob@example.com"),
        identity_signing_key=pem,
    )

    assert out["state"] == "done"
    assert len(captured) == 3
    tokens = [headers[IDENTITY_HEADER.lower()] for headers in captured]
    assert len(set(tokens)) == 1
    for headers in captured:
        _assert_webhook_jwt(headers, private_key, email="bob@example.com")


async def test_webhook_omits_identity_when_key_empty():
    out, captured = await _exchange(
        VerifiedIdentity(email="bob@example.com"),
        identity_signing_key="",
    )

    assert out["state"] == "done"
    assert captured
    assert all(IDENTITY_HEADER.lower() not in headers for headers in captured)
    assert all(
        headers.get(AUTHOR_EMAIL_HEADER.lower()) == "bob@example.com" for headers in captured
    )


async def test_webhook_signs_service_account_without_email_claim():
    private_key, pem = _signing_material()
    out, captured = await _exchange(
        VerifiedIdentity(subject="svc:demo"),
        identity_signing_key=pem,
    )

    assert out["state"] == "done"
    assert len(captured) == 3
    for headers in captured:
        _assert_webhook_jwt(headers, private_key, email=None)


async def test_webhook_omits_identity_when_signing_key_is_unusable(caplog):
    bad_pem = "not-a-pem"
    caplog.set_level(logging.WARNING, logger="keystone_mcp.contrib.adapters.webhook")
    out, captured = await _exchange(
        VerifiedIdentity(email="bob@example.com"),
        identity_signing_key=bad_pem,
    )

    assert out["state"] == "done"
    assert captured
    assert all(IDENTITY_HEADER.lower() not in headers for headers in captured)
    assert all(
        headers.get(AUTHOR_EMAIL_HEADER.lower()) == "bob@example.com" for headers in captured
    )
    warnings = [record.getMessage() for record in caplog.records]
    assert warnings == ["omitting X-Keystone-Identity: signing key is not a usable P-256 PEM"]
    assert bad_pem not in caplog.text


async def test_external_http_does_not_send_signed_identity():
    _private_key, pem = _signing_material()
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(dict(request.headers))
        return httpx.Response(200, json={"ok": True})

    def factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://target.example.com"
        )

    adapter = ExternalHttpAdapter("http://target.example.com", client_factory=factory)
    engine = RouterEngine(Settings(base_url="http://localhost:8080", identity_signing_key=pem))
    reg = RouterRegistry(engine)
    route = reg.add_route("ping", adapter, mode="live", params=[Param("x", str)])
    out = await engine.execute(
        route, {"x": "1"}, identity=VerifiedIdentity(email="bob@example.com")
    )

    assert out["state"] == "done"
    assert captured[AUTHOR_EMAIL_HEADER.lower()] == "bob@example.com"
    assert IDENTITY_HEADER.lower() not in captured
