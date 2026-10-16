"""Graceful shutdown configuration and SIGTERM behaviour."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import httpx2
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from keystone_mcp import server
from keystone_mcp.config import ConfigError, Settings, validate_settings
from support.test_env import UNUSED_REDIS_URL

STDIO_SERVER = str(Path(__file__).parent / "support" / "stdio_upstream.py")


@pytest.fixture
def redis_url() -> str:
    url = os.environ.get("KEYSTONE_MCP_REDIS_URL", "").strip()
    if not url:
        pytest.skip("KEYSTONE_MCP_REDIS_URL not set")
    return url


def test_shutdown_grace_default_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS", raising=False)
    assert Settings(base_url="http://localhost:8080").shutdown_grace_seconds == 25

    monkeypatch.setenv("KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS", "40")
    assert Settings(base_url="http://localhost:8080").shutdown_grace_seconds == 40

    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "off")
    monkeypatch.setenv("KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS", "-1")
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS"):
        validate_settings(Settings(base_url="http://localhost:8080"))


def test_main_passes_grace_to_uvicorn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS", "40")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "http://localhost:8080")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", UNUSED_REDIS_URL)
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "off")

    fake_mcp = MagicMock()

    def _fake_build_server(*, settings):
        return (fake_mcp, None, None, None, None, None, None)

    async def _fake_bootstrap_platform(*args, **kwargs):
        return None

    monkeypatch.setattr(server, "build_server", _fake_build_server)
    monkeypatch.setattr(server, "bootstrap_platform", _fake_bootstrap_platform)
    monkeypatch.setattr(server, "install_policy_reload_signal", lambda *a, **k: None)

    server.main()

    _, kwargs = fake_mcp.run.call_args
    assert kwargs["uvicorn_config"]["timeout_graceful_shutdown"] == 40


def _free_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


@pytest.mark.integration
@pytest.mark.asyncio
async def test_in_flight_call_survives_sigterm(redis_url: str, tmp_path: Path) -> None:
    if not redis_url:
        pytest.skip("KEYSTONE_MCP_REDIS_URL not set")

    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    users_db = tmp_path / "users.db"
    upstreams = json.dumps(
        [
            {
                "name": "notes",
                "namespace": "notes",
                "transport": "stdio",
                "command": sys.executable,
                "args": [STDIO_SERVER],
            }
        ]
    )
    server_env = {k: v for k, v in os.environ.items() if not k.startswith("KEYSTONE_MCP_")}
    server_env.update(
        {
            "KEYSTONE_MCP_PORT": str(port),
            "KEYSTONE_MCP_HOST": "127.0.0.1",
            "KEYSTONE_MCP_BASE_URL": base_url,
            "KEYSTONE_MCP_REDIS_URL": redis_url,
            "KEYSTONE_MCP_RBAC_MODE": "off",
            "KEYSTONE_MCP_DEPLOYMENT_PROFILE": "local",
            "KEYSTONE_MCP_USERS_DB_URL": f"sqlite:///{users_db}",
            "KEYSTONE_MCP_UPSTREAMS": upstreams,
            "KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS": "0",
            "KEYSTONE_MCP_DEV_TOKENS": "dev",
            "KEYSTONE_MCP_SUPERADMIN_EMAIL": "user@example.com",
            "KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS": "25",
            "KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP": "true",
            "KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE": "true",
        }
    )

    log_path = tmp_path / "server.log"
    log_file = log_path.open("wb")
    proc = subprocess.Popen(
        [sys.executable, "-m", "keystone_mcp.server"],
        env=server_env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    try:
        deadline = time.monotonic() + 45.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                log_file.flush()
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
                pytest.fail(f"server exited early with code {proc.returncode}; log:\n{log_text}")
            try:
                if httpx.get(f"{base_url}/healthz", timeout=1.0).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        else:
            pytest.fail("server never became ready")

        await asyncio.sleep(2.0)

        from support.oauth_harness import obtain_access_token

        resource = Settings(base_url=base_url).resource_url

        async with httpx2.AsyncClient(base_url=base_url, timeout=30.0) as http:
            token_res = await obtain_access_token(http, resource, api_token="dev")
            access_token = token_res["body"]["access_token"]

        def _remote_mcp_client_factory(headers=None, timeout=None, auth=None, **_kw):
            return httpx2.AsyncClient(
                base_url=base_url,
                headers=headers,
                timeout=timeout or httpx2.Timeout(30.0),
                auth=auth,
                follow_redirects=True,
            )

        transport = StreamableHttpTransport(
            url=f"{base_url}/",
            auth=access_token,
            httpx_client_factory=_remote_mcp_client_factory,
        )

        async def call_slow() -> str:
            async with Client(transport) as client:
                tools = {t.name for t in await client.list_tools()}
                assert "notes_slow" in tools, tools
                response = await client.call_tool("notes_slow", {"seconds": 3})
            if not response.content:
                return ""
            return response.content[0].text

        slow_task = asyncio.create_task(call_slow())
        await asyncio.sleep(1.5)
        proc.send_signal(signal.SIGTERM)
        text = await asyncio.wait_for(slow_task, timeout=30.0)
        proc.wait(timeout=35.0)

        assert text == "slow done"
        if proc.returncode not in (0, -signal.SIGTERM):
            log_tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
            pytest.fail(f"server exit code {proc.returncode}; log:\n{log_tail}")
    finally:
        log_file.close()
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)
