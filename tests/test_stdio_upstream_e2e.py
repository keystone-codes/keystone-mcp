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

from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.identity_assertion import IDENTITY_META_KEY
from keystone_mcp.server import bootstrap_rbac_policy, bootstrap_upstreams, build_server
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver

STDIO_SERVER = str(Path(__file__).parent / "support" / "stdio_upstream.py")
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
        identity_provider=StaticIdentityProvider({"dev"}),
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
    discovery = await bootstrap_upstreams(upstreams, settings)
    if build_kw.get("policy"):
        bootstrap_rbac_policy(policy_manager, registry, discovery=discovery)
    async with LifespanManager(mcp.http_app(path="/mcp")):
        yield mcp, upstreams, built[6]


@pytest.mark.asyncio
async def test_bootstrap_discovers_with_a_temporary_process(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS", json.dumps(_stdio_upstream_payload()))
    settings = Settings(base_url="http://127.0.0.1:8080")
    _mcp, _reg, _oauth, upstreams, *_ = build_server(
        settings=settings,
        register_builtin_catalog=False,
        oauth_store=InMemoryOAuthStore(),
    )
    result = await bootstrap_upstreams(upstreams, settings)
    assert result.counts.get("notes", 0) >= 1
    conn = upstreams.connection("notes")
    assert conn.process.state != "running"


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


@pytest.mark.asyncio
async def test_shutdown_stops_processes(monkeypatch, tmp_path):
    built = _build_stdio_server(monkeypatch, tmp_path)
    conn = built[3].connection("notes")
    async with _with_stdio_stack(monkeypatch, tmp_path) as (mcp, _upstreams, _reconciler):
        async with Client(mcp) as client:
            pid = int((await client.call_tool("notes_pid", {})).content[0].text)
    assert conn.process.state == "stopped"
    assert pid != os.getpid()
