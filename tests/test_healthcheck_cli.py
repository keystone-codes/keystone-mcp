"""Tests for the standalone container healthcheck CLI (keystone_mcp.healthcheck)."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from keystone_mcp.healthcheck import main


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/readyz":
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b"not ready")
        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture
def running_server() -> Iterator[int]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        thread.join()


def test_returns_zero_on_200(running_server: int, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_PORT", str(running_server))
    assert main(["/healthz"]) == 0


def test_returns_one_on_503(running_server: int, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_PORT", str(running_server))
    assert main(["/readyz"]) == 1


def test_returns_one_when_nothing_listens(monkeypatch: pytest.MonkeyPatch) -> None:
    # Bind a socket to claim a free port, then close it so nothing listens there.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    monkeypatch.setenv("KEYSTONE_MCP_PORT", str(closed_port))
    assert main(["/healthz"]) == 1
