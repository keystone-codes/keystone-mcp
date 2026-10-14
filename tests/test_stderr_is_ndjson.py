"""Subprocess smoke: stderr is NDJSON when KEYSTONE_MCP_LOG_FORMAT=json."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

from support.test_env import require_redis_url

REPO_ROOT = Path(__file__).resolve().parents[1]
BOOM_SERVER = REPO_ROOT / "tests" / "support" / "boom_server.py"
SERVER_READY_TIMEOUT_SECONDS = 90
SERVER_READY_POLL_SECONDS = 0.25


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _redis_url() -> str:
    return require_redis_url()


@pytest.mark.integration
def test_every_stderr_line_is_json(tmp_path, monkeypatch) -> None:
    redis_url = _redis_url()
    try:
        import redis

        redis.Redis.from_url(redis_url).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Redis at {redis_url} is not reachable: {exc}")

    monkeypatch.chdir(tmp_path)
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    host_header = f"127.0.0.1:{port}"

    server_env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("KEYSTONE_MCP_") and k != "FORWARDED_ALLOW_IPS"
    }
    server_env.update(
        {
            "KEYSTONE_MCP_ENV_FILE": "",
            "KEYSTONE_MCP_DEPLOYMENT_PROFILE": "local",
            "KEYSTONE_MCP_LOG_FORMAT": "json",
            "KEYSTONE_MCP_HOST": "127.0.0.1",
            "KEYSTONE_MCP_PORT": str(port),
            "KEYSTONE_MCP_BASE_URL": base_url,
            "KEYSTONE_MCP_REDIS_URL": redis_url,
            "KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS": "0",
            "KEYSTONE_MCP_DEV_TOKENS": "stderr-ndjson-test-token",
        }
    )

    proc = subprocess.Popen(
        [sys.executable, str(BOOM_SERVER)],
        cwd=REPO_ROOT,
        env=server_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    stderr_chunks: list[str] = []
    try:
        deadline = time.monotonic() + SERVER_READY_TIMEOUT_SECONDS
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                stderr_chunks.append(proc.stderr.read() if proc.stderr else "")
                pytest.fail(
                    f"server exited early with code {proc.returncode}; stderr:\n{''.join(stderr_chunks)}"
                )
            try:
                r = httpx.get(f"{base_url}/healthz", headers={"Host": host_header}, timeout=1.0)
                if r.status_code == 200:
                    ready = True
                    break
            except httpx.HTTPError:
                pass
            time.sleep(SERVER_READY_POLL_SECONDS)
        if not ready:
            pytest.fail("server never answered /healthz")

        boom = httpx.get(
            f"{base_url}/__boom",
            headers={"Host": host_header},
            timeout=5.0,
        )
        assert boom.status_code >= 500

        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    finally:
        if proc.stderr is not None:
            stderr_chunks.append(proc.stderr.read())

    stderr_text = "".join(stderr_chunks)
    lines = [line for line in stderr_text.splitlines() if line.strip()]
    assert lines, "expected stderr output from server subprocess"

    import json

    saw_exc_info = False
    forbidden_substrings = (
        "Deploy free",
        "Uvicorn running",
        "Started server process",
    )
    for line in lines:
        assert "\x1b[" not in line, f"ANSI escape in stderr: {line!r}"
        for bad in forbidden_substrings:
            assert bad not in line, f"non-JSON noise in stderr: {line!r}"
        payload = json.loads(line)
        if payload.get("exc_info"):
            saw_exc_info = True
    assert saw_exc_info, "expected at least one JSON log line with exc_info after /__boom"
