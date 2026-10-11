"""End-to-end test of a brand-new deployment (A08).

Repeats the exact path a new user takes: run ``setup.sh`` in the ``local``
profile with no terminal attached, start the server the way the script's own
summary tells them to (``python -m keystone_mcp.server``, reading only the
``.env`` the script wrote), wait for ``/healthz``, then sign in as the first
administrator over the real OAuth connector and prove ``users_list`` is
published. A second sign-in attempt, for an email absent from the built-in
users directory, is refused.

Everything after step 1 talks to a real subprocess over a real TCP socket:
no ``ASGITransport``, no app built in-process. This is deliberate -- the
whole point of the card is to catch a ``setup.sh`` output the server itself
refuses to start from, which an in-process harness could never see.

Skipped (not failed) when ``bash`` is unavailable or when
``KEYSTONE_MCP_REDIS_URL`` is unset or unreachable, the same convention
``tests/test_oauth_redis_integration.py`` and ``tests/test_setup_script.py``
use.
"""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastmcp.client.transports import StreamableHttpTransport

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is not available")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SETUP_SCRIPT = PROJECT_ROOT / "setup.sh"
ENV_EXAMPLE = PROJECT_ROOT / ".env.example"
RBAC_POLICY = PROJECT_ROOT / "config" / "rbac-policy.yaml"

REDIRECT_URI = "http://localhost:9999/callback"
ADMIN_EMAIL_MIXED_CASE = "Admin@Example.com"
ADMIN_EMAIL_LOWER = "admin@example.com"
STRANGER_EMAIL = "someone@example.com"

SERVER_READY_TIMEOUT_SECONDS = 30
SERVER_READY_POLL_SECONDS = 0.2


@pytest.fixture
def redis_url() -> str:
    url = os.environ.get("KEYSTONE_MCP_REDIS_URL", "").strip()
    if not url:
        pytest.skip("KEYSTONE_MCP_REDIS_URL not set")
    parsed = urlparse(url)
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 6379), timeout=2):
            pass
    except OSError:
        pytest.skip(f"Redis at {url} is not reachable")
    return url


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _register_client(client: httpx.AsyncClient) -> str:
    r = await client.post(
        "/register",
        json={"redirect_uris": [REDIRECT_URI], "token_endpoint_auth_method": "none"},
    )
    assert r.status_code in (200, 201), r.text
    return r.json()["client_id"]


def _make_pkce() -> tuple[str, str]:
    import base64
    import hashlib

    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


async def _authorize_to_login(
    client: httpx.AsyncClient, client_id: str, challenge: str, resource: str
) -> str:
    r = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "test-state",
            "resource": resource,
        },
    )
    assert r.status_code in (302, 307), r.text
    return parse_qs(urlparse(r.headers["location"]).query)["txn"][0]


async def _sign_in(client: httpx.AsyncClient, base_url: str, *, email: str, token: str) -> dict:
    """Full connector flow (register -> authorize -> login -> token exchange).

    Returns the parsed ``/token`` JSON body plus its HTTP status; never
    raises on a login or exchange failure, since the test needs to assert on
    a rejected sign-in (``someone@example.com``) as well as a successful one.
    """
    resource = base_url
    client_id = await _register_client(client)
    verifier, challenge = _make_pkce()
    txn = await _authorize_to_login(client, client_id, challenge, resource)
    r = await client.post("/login", data={"txn": txn, "api_token": token, "email": email})
    if r.status_code != 302:
        return {"login_status": r.status_code, "status": None, "body": {}}
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    r = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
            "resource": resource,
        },
    )
    return {
        "login_status": 302,
        "status": r.status_code,
        "body": r.json() if r.content else {},
    }


async def _cleanup_redis(redis_url: str, *, prefixes: list[str], exact_keys: list[str]) -> None:
    from redis.asyncio import Redis

    client = Redis.from_url(redis_url, decode_responses=True)
    try:
        for prefix in prefixes:
            keys = [key async for key in client.scan_iter(match=f"{prefix}*")]
            if keys:
                await client.delete(*keys)
        if exact_keys:
            await client.delete(*exact_keys)
    finally:
        await client.aclose()


async def test_setup_local_profile_then_server_starts_and_admin_signs_in(
    tmp_path: Path, redis_url: str
) -> None:
    admin_token = secrets.token_urlsafe(16)

    # ── 1. setup.sh in an isolated sandbox ──────────────────────────────────
    shutil.copy(SETUP_SCRIPT, tmp_path / "setup.sh")
    shutil.copy(ENV_EXAMPLE, tmp_path / ".env.example")
    (tmp_path / "config").mkdir()
    shutil.copy(RBAC_POLICY, tmp_path / "config" / "rbac-policy.yaml")

    env = {k: v for k, v in os.environ.items() if not k.startswith("KEYSTONE_MCP_")}
    env.update(
        {
            "KEYSTONE_SETUP_PROFILE": "local",
            "KEYSTONE_SETUP_ADMIN_EMAIL": ADMIN_EMAIL_MIXED_CASE,
            "KEYSTONE_SETUP_ADMIN_TOKEN": admin_token,
            "KEYSTONE_SETUP_REDIS_URL": redis_url,
        }
    )
    result = subprocess.run(
        ["bash", "setup.sh", "--non-interactive", "--skip-install"],
        cwd=tmp_path,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    env_path = tmp_path / ".env"
    env_text = env_path.read_text(encoding="utf-8")
    assert "KEYSTONE_MCP_DEPLOYMENT_PROFILE=local" in env_text

    # ── 2. start the real server, exactly the way setup.sh's own summary
    #        tells a new user to, reading only the .env it just wrote ───────
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    run_suffix = uuid.uuid4().hex
    redis_key_prefix = f"km:oauth:a08:{run_suffix}:"
    login_pending_key_prefix = f"km:login:a08:{run_suffix}:"
    users_revision_key = f"km:users:revision:a08:{run_suffix}"

    server_env = {k: v for k, v in os.environ.items() if not k.startswith("KEYSTONE_MCP_")}
    server_env.update(
        {
            "KEYSTONE_MCP_PORT": str(port),
            "KEYSTONE_MCP_BASE_URL": base_url,
            "KEYSTONE_MCP_REDIS_KEY_PREFIX": redis_key_prefix,
            "KEYSTONE_MCP_LOGIN_PENDING_KEY_PREFIX": login_pending_key_prefix,
            "KEYSTONE_MCP_USERS_REDIS_REVISION_KEY": users_revision_key,
            "KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS": "0",
        }
    )
    # KEYSTONE_MCP_ENV_FILE is deliberately NOT set: the point of this test is
    # that the server finds .env in its working directory on its own.

    log_path = tmp_path / "server.log"
    log_file = open(log_path, "wb")
    proc: subprocess.Popen | None = None
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "keystone_mcp.server"],
            cwd=tmp_path,
            env=server_env,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )

        def _log_contents() -> str:
            try:
                return log_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return "<server.log unreadable>"

        # ── 3. wait for /healthz ─────────────────────────────────────────
        deadline = time.monotonic() + SERVER_READY_TIMEOUT_SECONDS
        ready = False
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                pytest.fail(
                    f"server process exited early with code {proc.returncode}; "
                    f"server.log:\n{_log_contents()}"
                )
            try:
                r = httpx.get(f"{base_url}/healthz", timeout=1.0)
                if r.status_code == 200:
                    ready = True
                    break
            except httpx.HTTPError as exc:
                last_error = exc
            time.sleep(SERVER_READY_POLL_SECONDS)
        if not ready:
            pytest.fail(
                f"server never answered /healthz within {SERVER_READY_TIMEOUT_SECONDS}s "
                f"(last error: {last_error}); server.log:\n{_log_contents()}"
            )

        # ── 4. the first administrator signs in and sees users_* ──────────
        async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
            result_body = await _sign_in(
                client, base_url, email=ADMIN_EMAIL_LOWER, token=admin_token
            )
            assert result_body["login_status"] == 302, _log_contents()
            assert result_body["status"] == 200, (result_body, _log_contents())
            access_token = result_body["body"]["access_token"]

            # A second sign-in for an email not in the built-in users
            # directory is refused: the server validates every /login
            # attempt against the directory it just seeded.
            stranger_result = await _sign_in(
                client, base_url, email=STRANGER_EMAIL, token=admin_token
            )
            assert stranger_result["login_status"] == 403, (stranger_result, _log_contents())

        transport = StreamableHttpTransport(
            url=f"{base_url}/",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        from fastmcp import Client

        async with Client(transport) as mcp_client:
            tools = await mcp_client.list_tools()
        tool_names = {t.name for t in tools}
        assert "users_list" in tool_names, (tool_names, _log_contents())
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(10)
        log_file.close()
        await _cleanup_redis(
            redis_url,
            prefixes=[redis_key_prefix, login_pending_key_prefix],
            exact_keys=[users_revision_key],
        )
