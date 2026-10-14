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


def test_reads_port_from_env_file(
    running_server: int, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(f"KEYSTONE_MCP_PORT={running_server}\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("KEYSTONE_MCP_PORT", raising=False)
    monkeypatch.delenv("KEYSTONE_MCP_ENV_FILE", raising=False)
    assert main(["/healthz"]) == 0


def test_uses_configured_host(running_server: int, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_PORT", str(running_server))
    monkeypatch.setenv("KEYSTONE_MCP_HOST", "127.0.0.1")
    assert main(["/healthz"]) == 0

    monkeypatch.setenv("KEYSTONE_MCP_HOST", "0.0.0.0")
    assert main(["/healthz"]) == 0


def test_bad_env_file_exits_one(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    missing = tmp_path / "missing.env"
    monkeypatch.setenv("KEYSTONE_MCP_ENV_FILE", str(missing))
    assert main(["/healthz"]) == 1


def test_returns_one_when_nothing_listens(monkeypatch: pytest.MonkeyPatch) -> None:
    # Bind a socket to claim a free port, then close it so nothing listens there.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    monkeypatch.setenv("KEYSTONE_MCP_PORT", str(closed_port))
    assert main(["/healthz"]) == 1
