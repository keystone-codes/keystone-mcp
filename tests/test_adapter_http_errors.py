"""A failed downstream HTTP call returns the Model-M error shape, never an exception.

external_http and webhook both called raise_for_status() without catching it,
so a downstream 500 (or a refused connection, or a timeout) escaped the
adapter and reached the client as an opaque internal tool error rather than
{"state": "error", ...} — the shape every other outcome, and the users_admin
adapter, already uses.
"""

from __future__ import annotations

import httpx
import pytest

from keystone_mcp.config import Settings
from keystone_mcp.contrib.adapters.external_http import ExternalHttpAdapter
from keystone_mcp.contrib.adapters.webhook import WebhookAdapter, WebhookSettings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry

ID = VerifiedIdentity(email="u@example.com")
BASE = "http://localhost:8000"

SETTINGS = Settings(base_url="http://localhost:8080")

WEBHOOK_SETTINGS = WebhookSettings(
    base_url=BASE, client="acme", project="demo-project", long_poll_seconds=0
)


def _factory(handler):
    def factory():
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=BASE)

    return factory


def _status_handler(status: int):
    def handler(request: httpx.Request) -> httpx.Response:
        # A downstream error page may echo the request headers, which carry the
        # service credential; the adapter must not pass any of it back.
        return httpx.Response(
            status,
            json={"detail": "boom", "leaked": request.headers.get("authorization")},
        )

    return handler


def _timeout_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("too slow", request=request)


def _connect_error_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("refused", request=request)


def _run(adapter, tool_name: str, args: dict, params=None):
    engine = RouterEngine(SETTINGS)
    reg = RouterRegistry(engine)
    route = reg.add_route(tool_name, adapter, mode="live", params=params or [])
    return engine.execute(route, args, identity=ID)


ADAPTER_CASES = [
    pytest.param(
        lambda handler: ExternalHttpAdapter(BASE, client_factory=_factory(handler)),
        "call_target",
        {"x": "1"},
        id="external_http",
    ),
    pytest.param(
        lambda handler: WebhookAdapter(
            WEBHOOK_SETTINGS, client_factory=_factory(handler), poll_interval=0.0
        ),
        "submit_task",
        {"x": "1"},
        id="webhook",
    ),
]


@pytest.mark.parametrize(("build", "tool_name", "args"), ADAPTER_CASES)
@pytest.mark.parametrize("status", [400, 404, 500, 503])
async def test_downstream_error_status_becomes_a_model_m_error(
    build, tool_name: str, args: dict, status: int
):
    out = await _run(build(_status_handler(status)), tool_name, args)
    assert out["state"] == "error"
    assert out["code"] == f"downstream_http_{status}"
    assert out["tool"] == tool_name
    assert out["task_id"]
    assert isinstance(out["message"], str)


@pytest.mark.parametrize(("build", "tool_name", "args"), ADAPTER_CASES)
async def test_downstream_timeout_becomes_a_model_m_error(build, tool_name: str, args: dict):
    out = await _run(build(_timeout_handler), tool_name, args)
    assert out["state"] == "error"
    assert out["code"] == "downstream_timeout"


@pytest.mark.parametrize(("build", "tool_name", "args"), ADAPTER_CASES)
async def test_connect_failure_becomes_a_model_m_error(build, tool_name: str, args: dict):
    out = await _run(build(_connect_error_handler), tool_name, args)
    assert out["state"] == "error"
    assert out["code"] == "downstream_unavailable"


@pytest.mark.parametrize(("build", "tool_name", "args"), ADAPTER_CASES)
async def test_error_result_does_not_echo_the_downstream_body(build, tool_name: str, args: dict):
    """The service credential must not come back through a downstream error page."""
    import json as json_module

    out = await _run(build(_status_handler(500)), tool_name, args)
    serialized = json_module.dumps(out)
    assert "boom" not in serialized
    assert "Authorization" not in serialized
