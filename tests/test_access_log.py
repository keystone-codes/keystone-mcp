"""Tests for HTTP access logging middleware."""

from __future__ import annotations

import logging

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from keystone_mcp.config import Settings
from keystone_mcp.http.access_log import AccessLogMiddleware
from keystone_mcp.observability.logging import configure_logging
from keystone_mcp.observability.logging.context import get_request_id


async def _ok(_request):
    return PlainTextResponse("ok")


@pytest.fixture
def access_app():
    settings = Settings(log_access_enabled=True, log_request_id_response=True)
    configure_logging(settings)
    base = Starlette(routes=[Route("/hello", _ok)])
    return AccessLogMiddleware(base, settings=settings)


def test_access_log_emits_structured_fields(access_app, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="keystone_mcp.access")

    from starlette.testclient import TestClient

    with TestClient(access_app) as client:
        response = client.get("/hello?secret=1", headers={"Authorization": "Bearer x"})
    assert response.status_code == 200
    assert "X-Request-ID" in response.headers

    access_records = [r for r in caplog.records if r.name == "keystone_mcp.access"]
    assert len(access_records) == 1
    record = access_records[0]
    assert record.method == "GET"
    assert record.path == "/hello"
    assert record.status == 200
    assert "secret" not in (record.path or "")
    assert get_request_id() is None


def test_access_log_respects_incoming_request_id(
    access_app, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="keystone_mcp.access")
    from starlette.testclient import TestClient

    with TestClient(access_app) as client:
        response = client.get("/hello", headers={"X-Request-ID": "corr-123"})
    assert response.headers.get("X-Request-ID") == "corr-123"
    record = next(r for r in caplog.records if r.name == "keystone_mcp.access")
    assert record.request_id == "corr-123"


def test_access_log_json_line_has_stream(access_app, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="keystone_mcp.access")
    from starlette.testclient import TestClient

    with TestClient(access_app) as client:
        client.get("/hello")
    record = next(r for r in caplog.records if r.name == "keystone_mcp.access")
    assert record.stream == "access"
    assert record.path == "/hello"
