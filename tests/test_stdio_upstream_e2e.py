"""End-to-end tests for stdio upstream proxying (Y09)."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import jwt
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.exceptions import ToolError
from prometheus_client import REGISTRY

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.identity_assertion import IDENTITY_META_KEY
from keystone_mcp.router.upstream_content import published_uri_for_namespace
from keystone_mcp.server import bootstrap_rbac_policy, bootstrap_upstreams, build_server
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from support.login import dev_token_login

STDIO_SERVER = str(Path(__file__).parent / "support" / "stdio_upstream.py")
STDIO_LAUNCH_COUNTER = str(Path(__file__).parent / "support" / "stdio_launch_counter.py")
FLAKY_STDIO_SERVER = str(Path(__file__).parent / "support" / "flaky_stdio_upstream.py")
ANN = VerifiedIdentity(email="ann@example.com")


def _identity_ann() -> VerifiedIdentity:
    return ANN


@pytest.fixture(autouse=True)
def patch_verified_identity(monkeypatch):
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", _identity_ann)
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity", _identity_ann
    )


NOTES_POLICY = """\
version: "1.0.0"
default_deny: true
roles:
  member:
    allow: ["notes_*"]
requires_human_identity: []
critical_tools: []
"""


def _stdio_upstream_payload(**extra: object) -> list[dict[str, object]]:
    entry: dict[str, object] = {
        "name": "notes",
        "namespace": "notes",
        "transport": "stdio",
        "command": sys.executable,
        "args": [STDIO_SERVER],
    }
    entry.update(extra)
    return [entry]


def _build_stdio_server(
    monkeypatch,
    tmp_path: Path,
    *,
    rbac_mode: str = "off",
    policy: bool = False,
    upstream_payload: list[dict[str, object]] | None = None,
    user_resolver=None,
    **settings_kw,
):
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(upstream_payload or _stdio_upstream_payload()),
    )
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", rbac_mode)
    if policy:
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(NOTES_POLICY, encoding="utf-8")
        monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy_path))
        settings_kw.setdefault("rbac_audit_subject_salt", "test-stdio-e2e-salt")
    settings = Settings(
        base_url="http://127.0.0.1:8080",
        refresh_interval_seconds=settings_kw.pop("refresh_interval_seconds", 0),
        **settings_kw,
    )
    return build_server(
        settings=settings,
        login_providers=[dev_token_login({"dev"})],
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
        user_resolver=user_resolver,
    )


@asynccontextmanager
async def _with_stdio_stack(monkeypatch, tmp_path: Path, **build_kw):
    user_resolver = build_kw.pop("user_resolver", None)
    built = _build_stdio_server(monkeypatch, tmp_path, user_resolver=user_resolver, **build_kw)
    mcp, registry, upstreams = built[0], built[1], built[3]
    policy_manager = built[4]
    settings = Settings(base_url="http://127.0.0.1:8080")
    await upstreams.start_connections()
    discovery = await bootstrap_upstreams(upstreams, settings)
    if build_kw.get("policy"):
        bootstrap_rbac_policy(policy_manager, registry, discovery=discovery)
    reconciler = built[6]
    if reconciler is not None:
        await reconciler.start()
    async with LifespanManager(mcp.http_app(path="/mcp")):
        yield mcp, upstreams, reconciler


@pytest.mark.asyncio
async def test_startup_uses_only_the_persistent_process(monkeypatch, tmp_path):
    marker = tmp_path / "launches.txt"
    payload = _stdio_upstream_payload(args=[STDIO_LAUNCH_COUNTER, str(marker)])
    async with _with_stdio_stack(monkeypatch, tmp_path, upstream_payload=payload) as (
        mcp,
        upstreams,
        _reconciler,
    ):
        conn = upstreams.connection("notes")
        assert conn.process.state == "running"
        launches = marker.read_text(encoding="utf-8").strip().splitlines()
        assert len(launches) == 1
        async with Client(mcp) as client:
            tools = {t.name for t in await client.list_tools()}
        assert "notes_greet" in tools


@pytest.mark.asyncio
async def test_start_connections_runs_in_parallel(monkeypatch, tmp_path):
    delay_args = ["--init-delay", "1"]
    upstreams_payload = [
        {
            "name": "notes",
            "namespace": "notes",
            "transport": "stdio",
            "command": sys.executable,
            "args": [STDIO_SERVER, *delay_args],
        },
        {
            "name": "docs",
            "namespace": "docs",
            "transport": "stdio",
            "command": sys.executable,
            "args": [STDIO_SERVER, *delay_args],
        },
    ]
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS", json.dumps(upstreams_payload))
    settings = Settings(base_url="http://127.0.0.1:8080", refresh_interval_seconds=0)
    _mcp, _reg, _oauth, upstreams, *_ = build_server(
        settings=settings,
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    t0 = time.monotonic()
    await upstreams.start_connections(wait=15)
    elapsed = time.monotonic() - t0
    assert elapsed < 1.8
    for ns in ("notes", "docs"):
        conn = upstreams.connection(ns)
        assert conn.process.state == "running"


@pytest.mark.asyncio
async def test_no_warning_when_process_started(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.WARNING)
    async with _with_stdio_stack(monkeypatch, tmp_path) as (_mcp, _upstreams, _reconciler):
        pass
    assert not any(
        "did not reach running" in r.message for r in caplog.records if r.levelno >= logging.WARNING
    )


@pytest.mark.asyncio
async def test_process_up_after_failed_discovery_publishes_tools_within_seconds(
    monkeypatch, tmp_path
):
    counter = tmp_path / "launch.count"
    monkeypatch.setenv("KEYSTONE_TEST_STDIO_FAIL_UNTIL", "2")
    monkeypatch.setenv("KEYSTONE_MCP_METRICS_ENABLED", "true")
    payload = _stdio_upstream_payload(args=[FLAKY_STDIO_SERVER, str(counter)])
    async with _with_stdio_stack(
        monkeypatch,
        tmp_path,
        upstream_payload=payload,
        metrics_enabled=True,
        refresh_interval_seconds=60,
        upstream_discovery_retries=0,
    ) as (mcp, upstreams, _reconciler):
        assert upstreams._status["notes"].available is False
        conn = upstreams.connection("notes")
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline and (
            conn.process.state != "running" or conn.process.restarts < 2
        ):
            await asyncio.sleep(0.05)
        assert conn.process.state == "running"
        t0 = time.monotonic()
        async with Client(mcp) as client:
            while time.monotonic() - t0 < 5.0:
                tools = {t.name for t in await client.list_tools()}
                if "notes_greet" in tools:
                    break
                await asyncio.sleep(0.1)
            else:
                pytest.fail("tools not published within 5s after process came up")
        assert upstreams._status["notes"].available is True
        sample = REGISTRY.get_sample_value(
            "keystone_mcp_upstream_available", {"namespace": "notes"}
        )
        assert sample is not None and sample >= 1.0


@pytest.mark.asyncio
async def test_process_up_without_reconciler_is_discovered(monkeypatch, tmp_path):
    counter = tmp_path / "launch.count"
    monkeypatch.setenv("KEYSTONE_TEST_STDIO_FAIL_UNTIL", "2")
    payload = _stdio_upstream_payload(args=[FLAKY_STDIO_SERVER, str(counter)])
    async with _with_stdio_stack(
        monkeypatch,
        tmp_path,
        upstream_payload=payload,
        refresh_interval_seconds=0,
    ) as (mcp, upstreams, reconciler):
        assert reconciler is None or reconciler._task is None
        conn = upstreams.connection("notes")
        deadline = time.monotonic() + 15.0
        while conn.process.state != "running" and time.monotonic() < deadline:
            await asyncio.sleep(0.1)
        t0 = time.monotonic()
        async with Client(mcp) as client:
            while time.monotonic() - t0 < 5.0:
                tools = {t.name for t in await client.list_tools()}
                if "notes_greet" in tools:
                    break
                await asyncio.sleep(0.1)
            else:
                pytest.fail("tools not published within 5s without reconciler tick")


@pytest.mark.asyncio
async def test_tools_published_and_called_through_rbac(monkeypatch, tmp_path):
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed("ann@example.com", roles=("member",))
    backend.seed("bob@example.com", roles=())
    async with _with_stdio_stack(
        monkeypatch,
        tmp_path,
        rbac_mode="enforce",
        policy=True,
        user_resolver=resolver,
    ) as (mcp, _upstreams, _reconciler):

        def _ann() -> VerifiedIdentity:
            return VerifiedIdentity(email="ann@example.com")

        monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", _ann)
        monkeypatch.setattr("keystone_mcp.router.rbac_middleware.resolve_verified_identity", _ann)
        async with Client(mcp) as client:
            tools = {t.name for t in await client.list_tools()}
            assert "notes_greet" in tools
            out = await client.call_tool("notes_greet", {"name": "Ada"})
            assert "Ada" in out.content[0].text

        def _bob() -> VerifiedIdentity:
            return VerifiedIdentity(email="bob@example.com")

        monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", _bob)
        monkeypatch.setattr("keystone_mcp.router.rbac_middleware.resolve_verified_identity", _bob)
        async with Client(mcp) as client:
            tools = {t.name for t in await client.list_tools()}
            assert "notes_greet" not in tools
            with pytest.raises(ToolError, match="access denied|denied"):
                await client.call_tool("notes_greet", {"name": "Ada"})


@pytest.mark.asyncio
async def test_identity_assertion_in_meta(monkeypatch, tmp_path):
    secret = "x" * 40
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET", secret)
    payload = _stdio_upstream_payload(
        auth={"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET"}
    )
    async with _with_stdio_stack(monkeypatch, tmp_path, upstream_payload=payload) as (
        mcp,
        _upstreams,
        _reconciler,
    ):
        async with Client(mcp) as client:
            raw = await client.call_tool("notes_meta", {})
            meta = json.loads(raw.content[0].text)
            token = meta[IDENTITY_META_KEY]
            claims = jwt.decode(
                token,
                secret,
                algorithms=["HS256"],
                audience="notes",
                options={"verify_aud": True},
            )
            assert claims["aud"] == "notes"


@pytest.mark.asyncio
async def test_progress_over_stdio(monkeypatch, tmp_path):
    seen: list[tuple[int, int | None, str | None]] = []

    async def on_progress(progress: float, total: float | None, message: str | None) -> None:
        seen.append((int(progress), int(total) if total is not None else None, message))

    async with _with_stdio_stack(monkeypatch, tmp_path) as (mcp, _upstreams, _reconciler):
        async with Client(mcp) as client:
            await client.call_tool("notes_count", {"n": 3}, progress_handler=on_progress)
    assert len(seen) == 3


@pytest.mark.asyncio
async def test_cancel_over_stdio_within_one_second(monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="keystone_mcp.upstream.stderr")
    async with _with_stdio_stack(monkeypatch, tmp_path) as (mcp, _upstreams, _reconciler):
        async with Client(mcp) as client:
            task = asyncio.create_task(client.call_tool("notes_slow", {}))
            t0 = time.monotonic()
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    assert time.monotonic() - t0 < 1.0
    assert any("slow-cancelled" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_crash_marks_unavailable_and_recovers(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYSTONE_MCP_METRICS_ENABLED", "true")
    async with _with_stdio_stack(monkeypatch, tmp_path, metrics_enabled=True) as (
        mcp,
        upstreams,
        _reconciler,
    ):
        async with Client(mcp) as client:
            with pytest.raises(ToolError):
                await client.call_tool("notes_crash", {})
            with pytest.raises(ToolError, match="unavailable"):
                await client.call_tool("notes_greet", {"name": "x"})
            conn = upstreams.connection("notes")
            deadline = time.monotonic() + 5.0
            while conn.process.state != "running" and time.monotonic() < deadline:
                await asyncio.sleep(0.1)
            out = await client.call_tool("notes_greet", {"name": "back"})
            assert "back" in out.content[0].text
    sample = REGISTRY.get_sample_value(
        "keystone_mcp_upstream_process_restarts_total", {"namespace": "notes"}
    )
    assert sample is not None and sample >= 1.0


@pytest.mark.asyncio
async def test_reconciler_tick_reuses_the_process(monkeypatch, tmp_path):
    async with _with_stdio_stack(monkeypatch, tmp_path, refresh_interval_seconds=60) as (
        mcp,
        _upstreams,
        reconciler,
    ):
        assert reconciler is not None
        async with Client(mcp) as client:
            pid1 = (await client.call_tool("notes_pid", {})).content[0].text
            reconciler.seed_snapshots()
            await reconciler.tick()
            pid2 = (await client.call_tool("notes_pid", {})).content[0].text
    assert pid1 == pid2


async def _decode_identity_from_stdio_payload(
    raw_text: str, *, secret: str, audience: str, mcp_method: str, mcp_target: str
) -> dict:
    meta = json.loads(raw_text)
    token = meta[IDENTITY_META_KEY]
    claims = jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        audience=audience,
        options={"verify_aud": True},
    )
    assert claims["aud"] == audience
    assert claims["mcp_method"] == mcp_method
    assert claims["mcp_target"] == mcp_target
    return claims


@pytest.mark.asyncio
async def test_stdio_prompt_get_carries_identity_in_meta(monkeypatch, tmp_path):
    secret = "y" * 40
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET", secret)
    payload = _stdio_upstream_payload(
        auth={"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET"}
    )
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed(ANN.email, roles=("member",))
    async with _with_stdio_stack(
        monkeypatch,
        tmp_path,
        upstream_payload=payload,
        policy=True,
        rbac_mode="enforce",
        user_resolver=resolver,
    ) as (mcp, _upstreams, _reconciler):
        async with Client(mcp) as client:
            result = await client.get_prompt("notes_whoami", {})
            text = result.messages[0].content.text
            await _decode_identity_from_stdio_payload(
                text,
                secret=secret,
                audience="notes",
                mcp_method="prompts/get",
                mcp_target="whoami",
            )


@pytest.mark.asyncio
async def test_stdio_resource_read_carries_identity_in_meta(monkeypatch, tmp_path):
    secret = "z" * 40
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET", secret)
    payload = _stdio_upstream_payload(
        auth={"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET"}
    )
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed(ANN.email, roles=("member",))
    async with _with_stdio_stack(
        monkeypatch,
        tmp_path,
        upstream_payload=payload,
        policy=True,
        rbac_mode="enforce",
        user_resolver=resolver,
    ) as (mcp, _upstreams, _reconciler):
        async with Client(mcp) as client:
            published = published_uri_for_namespace("notes", "meta://whoami")
            blocks = await client.read_resource(published)
            text = blocks[0].text
            await _decode_identity_from_stdio_payload(
                text,
                secret=secret,
                audience="notes",
                mcp_method="resources/read",
                mcp_target="meta://whoami",
            )


@pytest.mark.asyncio
async def test_client_meta_identity_is_not_forwarded_to_stdio(monkeypatch, tmp_path):
    secret = "w" * 40
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET", secret)
    payload = _stdio_upstream_payload(
        auth={"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET"}
    )
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed(ANN.email, roles=("member",))
    async with _with_stdio_stack(
        monkeypatch,
        tmp_path,
        upstream_payload=payload,
        policy=True,
        rbac_mode="enforce",
        user_resolver=resolver,
    ) as (mcp, _upstreams, _reconciler):
        async with Client(mcp) as client:
            result = await client.get_prompt(
                "notes_whoami",
                {},
                meta={"keystone-mcp/identity": "forged"},
            )
            text = result.messages[0].content.text
            meta = json.loads(text)
            token = meta[IDENTITY_META_KEY]
            assert token != "forged"
            jwt.decode(
                token,
                secret,
                algorithms=["HS256"],
                audience="notes",
                options={"verify_aud": True},
            )


@pytest.mark.asyncio
async def test_shutdown_stops_processes(monkeypatch, tmp_path):
    built = _build_stdio_server(monkeypatch, tmp_path)
    conn = built[3].connection("notes")
    async with _with_stdio_stack(monkeypatch, tmp_path) as (mcp, _upstreams, _reconciler):
        async with Client(mcp) as client:
            pid = int((await client.call_tool("notes_pid", {})).content[0].text)
    assert conn.process.state == "stopped"
    assert pid != os.getpid()
