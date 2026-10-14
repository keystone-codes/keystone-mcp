"""F03: hot reload of the upstream registry file and SIGHUP."""

from __future__ import annotations

import asyncio
import os
import signal as signal_mod
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import yaml
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.exceptions import ToolError
from prometheus_client import REGISTRY

from conftest import BASE_URL, VALID_TOKEN
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.server import (
    bootstrap_rbac_policy,
    bootstrap_upstreams,
    build_server,
    install_reload_signal,
)
from support.login import dev_token_login
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)

POLICY = """\
version: "1.0.0"
default_deny: true
roles:
  administrator:
    allow: ["*"]
"""

POLICY_HELLO = """\
version: "1.0.0"
default_deny: true
roles:
  administrator:
    allow: ["hello_*"]
"""


def _metric(name: str, labels: dict[str, str]) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


def _write_registry(path: Path, entries: list[dict[str, Any]]) -> None:
    path.write_text(
        yaml.safe_dump({"schema_version": 1, "entries": entries}, sort_keys=False),
        encoding="utf-8",
    )


def _hello_entry(**overrides: Any) -> dict[str, Any]:
    base = {
        "name": "hello",
        "namespace": "hello",
        "url": UPSTREAM_MCP_URL,
        "transport": "http",
    }
    base.update(overrides)
    return base


async def _stack(
    tmp_path: Path,
    *,
    entries: list[dict[str, Any]],
    policy: str = "",
    observed: dict[str, Any] | None = None,
    app=None,
    settings_overrides: dict[str, Any] | None = None,
) -> tuple[Any, ...]:
    reg_path = tmp_path / "upstreams.yaml"
    _write_registry(reg_path, entries)
    settings_kw: dict[str, Any] = {
        "base_url": BASE_URL,
        "upstreams_path": str(reg_path),
        "refresh_interval_seconds": 300,
        "rbac_mode": "off",
        "metrics_enabled": True,
    }
    if policy:
        policy_path = tmp_path / "policy.yaml"
        policy_path.write_text(policy, encoding="utf-8")
        settings_kw["rbac_policy_path"] = str(policy_path)
    if settings_overrides:
        settings_kw.update(settings_overrides)
    settings = Settings(**settings_kw)
    upstream_app = app or build_lowlevel_upstream_app(
        tools=["greet", "whoami"],
        prompts=True,
        resources=True,
        observed=observed,
    )
    mcp, registry, oauth, upstreams, policy_manager, observability, reconciler = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        login_providers=[dev_token_login({VALID_TOKEN})],
        register_builtin_catalog=False,
    )
    lifespan = LifespanManager(upstream_app)
    await lifespan.__aenter__()
    factory = asgi_http_client_factory(upstream_app)
    upstreams.http_client_factory = factory
    from keystone_mcp.router.upstream_connection import HttpUpstreamConnection

    for conn in upstreams._connections.values():
        if isinstance(conn, HttpUpstreamConnection):
            conn._http_client_factory = factory  # type: ignore[assignment]
    discovery = await bootstrap_upstreams(upstreams, settings)
    if policy_manager is not None and settings.rbac_policy_path.strip():
        bootstrap_rbac_policy(
            policy_manager, registry, discovery=discovery, observability=observability
        )
    assert reconciler is not None
    await reconciler.start()
    return mcp, registry, upstreams, policy_manager, observability, reconciler, reg_path, settings


async def test_added_entry_publishes_tools_after_one_tick(tmp_path: Path):
    mcp, _registry, _upstreams, _pm, _obs, reconciler, reg_path, _settings = await _stack(
        tmp_path,
        entries=[_hello_entry()],
    )
    received: list[Any] = []

    async def handler(message):
        received.append(message)

    async with Client(mcp, mode="legacy", message_handler=handler) as client:
        tools_before = {t.name for t in await client.list_tools()}
        assert "hello_greet" in tools_before
        assert "world_greet" not in tools_before

        entries = [_hello_entry(), _hello_entry(name="world", namespace="world")]
        _write_registry(reg_path, entries)
        await reconciler.tick()
        await asyncio.sleep(0)
        tools_after = {t.name for t in await client.list_tools()}
        assert "world_greet" in tools_after
        assert any(getattr(m, "method", "") == "notifications/tools/list_changed" for m in received)


async def test_removed_entry_unpublishes_tools_prompts_resources(tmp_path: Path):
    mcp, registry, upstreams, _pm, _obs, reconciler, reg_path, _settings = await _stack(
        tmp_path,
        entries=[_hello_entry()],
    )
    async with Client(mcp) as client:
        assert "hello_greet" in {t.name for t in await client.list_tools()}
        _write_registry(reg_path, [])
        await reconciler.tick()
        tools = {t.name for t in await client.list_tools()}
        assert "hello_greet" not in tools
        with pytest.raises(ToolError, match="Unknown tool"):
            await client.call_tool("hello_greet", {"name": "x"})
        assert "hello" not in upstreams.namespaces()


async def test_changed_url_routes_new_calls_to_new_service(tmp_path: Path):
    from keystone_mcp.router.upstream_connection import HttpUpstreamConnection

    mcp, _registry, upstreams, _pm, _obs, reconciler, reg_path, _settings = await _stack(
        tmp_path,
        entries=[_hello_entry()],
    )
    conn = upstreams.connection("hello")
    assert isinstance(conn, HttpUpstreamConnection)
    assert conn._url == UPSTREAM_MCP_URL.rstrip("/")
    _write_registry(reg_path, [_hello_entry(url="http://other.test/mcp")])
    await reconciler.tick()
    conn = upstreams.connection("hello")
    assert isinstance(conn, HttpUpstreamConnection)
    assert conn._url == "http://other.test/mcp"


async def test_changed_filters_and_timeout_apply(tmp_path: Path):
    mcp, _registry, _upstreams, _pm, _obs, reconciler, reg_path, _settings = await _stack(
        tmp_path,
        entries=[_hello_entry(include_prefixes=["greet"])],
    )
    async with Client(mcp) as client:
        names = {t.name for t in await client.list_tools()}
        assert "hello_greet" in names
        assert "hello_whoami" not in names
        _write_registry(
            reg_path,
            [_hello_entry(include_prefixes=["whoami"], tool_timeout_seconds=0.05)],
        )
        await reconciler.tick()
        names = {t.name for t in await client.list_tools()}
        assert "hello_whoami" in names
        assert "hello_greet" not in names


async def test_invalid_file_keeps_previous_registry(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    mcp, _registry, _upstreams, _pm, _obs, reconciler, reg_path, _settings = await _stack(
        tmp_path,
        entries=[_hello_entry()],
    )
    reg_path.write_text("schema_version: 2\nentries: []\n", encoding="utf-8")
    with caplog.at_level("WARNING"):
        await reconciler.tick()
        await reconciler.tick()
    warnings = [r.message for r in caplog.records if "upstream registry reload rejected" in r.message]
    assert len(warnings) == 1
    assert _metric("keystone_mcp_upstream_registry_reload_total", {"outcome": "rejected"}) >= 1
    async with Client(mcp) as client:
        assert "hello_greet" in {t.name for t in await client.list_tools()}
    _write_registry(reg_path, [_hello_entry(), _hello_entry(name="world", namespace="world")])
    await reconciler.tick()
    async with Client(mcp) as client:
        assert "world_greet" in {t.name for t in await client.list_tools()}


async def test_missing_bearer_env_rejects_reload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MISSING_BEARER", raising=False)
    entries = [_hello_entry(auth={"bearer_env": "MISSING_BEARER"})]
    mcp, _registry, _upstreams, _pm, _obs, reconciler, reg_path, _settings = await _stack(
        tmp_path,
        entries=[_hello_entry()],
    )
    _write_registry(reg_path, entries)
    await reconciler.tick()
    async with Client(mcp) as client:
        assert "hello_greet" in {t.name for t in await client.list_tools()}


async def test_stdio_entry_added_and_removed_controls_process(tmp_path: Path):
    script = Path(__file__).resolve().parent / "support" / "stdio_upstream.py"
    entries = [
        {
            "name": "notes",
            "namespace": "notes",
            "url": "",
            "transport": "stdio",
            "command": sys.executable,
            "args": [str(script)],
        }
    ]
    mcp, _registry, upstreams, _pm, _obs, reconciler, reg_path, _settings = await _stack(
        tmp_path,
        entries=[],
        settings_overrides={"refresh_interval_seconds": 300},
    )
    _write_registry(reg_path, entries)
    await reconciler.tick()
    assert "notes" in upstreams.namespaces()
    conn = upstreams.connection("notes")
    async with Client(mcp) as client:
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            tools = {t.name for t in await client.list_tools()}
            if "notes_greet" in tools:
                break
            await asyncio.sleep(0.05)
        else:
            pytest.fail("notes_greet was not published after registry reload")
    _write_registry(reg_path, [])
    await reconciler.tick()
    assert conn.process.state in {"stopped", "stopping"}
    async with Client(mcp) as client:
        assert "notes_greet" not in {t.name for t in await client.list_tools()}


async def test_readd_same_namespace_reuses_mount(tmp_path: Path):
    mount_calls = 0
    mcp, _registry, upstreams, _pm, _obs, reconciler, reg_path, _settings = await _stack(
        tmp_path,
        entries=[_hello_entry()],
    )
    original_mount = upstreams.main_mcp.mount

    def counting_mount(*args, **kwargs):  # noqa: ANN002, ANN003
        nonlocal mount_calls
        mount_calls += 1
        return original_mount(*args, **kwargs)

    upstreams.main_mcp.mount = counting_mount  # type: ignore[method-assign]
    mounts_after_bootstrap = mount_calls
    _write_registry(reg_path, [])
    await reconciler.tick()
    _write_registry(reg_path, [_hello_entry()])
    await reconciler.tick()
    async with Client(mcp) as client:
        assert "hello_greet" in {t.name for t in await client.list_tools()}
    assert mount_calls == mounts_after_bootstrap


async def test_sighup_reloads_registry_immediately(tmp_path: Path):
    mcp, _registry, _upstreams, _pm, _obs, reconciler, reg_path, _settings = await _stack(
        tmp_path,
        entries=[_hello_entry()],
    )
    _write_registry(reg_path, [_hello_entry(), _hello_entry(name="world", namespace="world")])
    await reconciler.reload_registry_once()
    async with Client(mcp) as client:
        assert "world_greet" in {t.name for t in await client.list_tools()}


async def test_sighup_with_env_registry_logs_and_does_nothing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
):
    if not hasattr(signal_mod, "SIGHUP"):
        pytest.skip("SIGHUP not available")
    settings = Settings(
        base_url=BASE_URL,
        upstreams_json='[{"name":"hello","namespace":"hello","url":"http://x/mcp"}]',
        refresh_interval_seconds=300,
    )
    mcp, registry, _oauth, upstreams, policy_manager, _obs, reconciler = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        register_builtin_catalog=False,
    )
    await reconciler.start()
    install_reload_signal(registry, policy_manager, reconciler=reconciler)
    with caplog.at_level("INFO"):
        os.kill(os.getpid(), signal_mod.SIGHUP)
        await asyncio.sleep(0.05)
    assert any("KEYSTONE_MCP_UPSTREAMS" in r.message for r in caplog.records)


async def test_sighup_picks_up_rotated_bearer_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    bearer_var = "KEYSTONE_MCP_UPSTREAM_HELLO_BEARER"
    monkeypatch.setenv(bearer_var, "token-a")
    entries = [_hello_entry(auth={"bearer_env": bearer_var})]
    observed: dict[str, Any] = {}
    app = build_lowlevel_upstream_app(tools=["whoami"], observed=observed, require_bearer="token-a")
    mcp, registry, upstreams, policy_manager, _obs, reconciler, reg_path, settings = await _stack(
        tmp_path,
        entries=entries,
        app=app,
    )
    monkeypatch.setenv(bearer_var, "token-b")
    app2 = build_lowlevel_upstream_app(tools=["whoami"], observed=observed, require_bearer="token-b")
    lifespan_b = LifespanManager(app2)
    await lifespan_b.__aenter__()
    factory_b = asgi_http_client_factory(app2)
    upstreams.http_client_factory = factory_b
    conn = upstreams._connections["hello"]
    conn._http_client_factory = factory_b  # type: ignore[attr-defined]
    await reconciler.reload_registry_once()
    assert "hello" in upstreams.namespaces()
    assert upstreams._auth_headers["hello"]["Authorization"].endswith("token-b")


async def test_policy_drift_logged_for_removed_namespace(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(POLICY_HELLO, encoding="utf-8")
    reg_path = tmp_path / "upstreams.yaml"
    _write_registry(reg_path, [_hello_entry()])
    settings = Settings(
        base_url=BASE_URL,
        upstreams_path=str(reg_path),
        refresh_interval_seconds=300,
        rbac_policy_path=str(policy_path),
        rbac_mode="enforce",
        metrics_enabled=True,
    )
    upstream_app = build_lowlevel_upstream_app(tools=["greet", "whoami"])
    mcp, registry, _oauth, upstreams, policy_manager, observability, reconciler = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        login_providers=[dev_token_login({VALID_TOKEN})],
        register_builtin_catalog=False,
    )
    lifespan = LifespanManager(upstream_app)
    await lifespan.__aenter__()
    factory = asgi_http_client_factory(upstream_app)
    upstreams.http_client_factory = factory
    from keystone_mcp.router.upstream_connection import HttpUpstreamConnection

    for conn in upstreams._connections.values():
        if isinstance(conn, HttpUpstreamConnection):
            conn._http_client_factory = factory  # type: ignore[assignment]
    discovery = await bootstrap_upstreams(upstreams, settings)
    bootstrap_rbac_policy(policy_manager, registry, discovery=discovery, observability=observability)
    assert reconciler is not None
    await reconciler.start()
    _write_registry(reg_path, [])
    with caplog.at_level("WARNING"):
        await reconciler.tick()
    assert any("hello_*" in r.message for r in caplog.records)


async def test_reserved_namespace_in_new_file_rejected(tmp_path: Path):
    mcp, _registry, _upstreams, _pm, _obs, reconciler, reg_path, _settings = await _stack(
        tmp_path,
        entries=[_hello_entry()],
    )
    _write_registry(reg_path, [_hello_entry(name="users", namespace="users", url=UPSTREAM_MCP_URL)])
    await reconciler.tick()
    async with Client(mcp) as client:
        assert "hello_greet" in {t.name for t in await client.list_tools()}


async def test_registry_info_metric_changes_with_file(tmp_path: Path):
    _mcp, _registry, _upstreams, _pm, _obs, reconciler, reg_path, _settings = await _stack(
        tmp_path,
        entries=[_hello_entry()],
    )
    before_hash = reconciler.upstream_registry_hash()
    _write_registry(reg_path, [_hello_entry(tool_timeout_seconds=30)])
    await reconciler.tick()
    after_hash = reconciler.upstream_registry_hash()
    assert after_hash is not None
    assert after_hash != before_hash
    assert _metric("keystone_mcp_upstream_registry_info", {"content_hash": after_hash}) == 1.0


async def test_limits_change_recreates_guard(tmp_path: Path):
    mcp, _registry, upstreams, _pm, _obs, reconciler, reg_path, _settings = await _stack(
        tmp_path,
        entries=[_hello_entry(limits={"rate": 5, "window": 60})],
    )
    first = upstreams.upstream_guard("hello")
    assert first is not None
    _write_registry(
        reg_path,
        [_hello_entry(limits={"rate": 2, "window": 60})],
    )
    await reconciler.tick()
    second = upstreams.upstream_guard("hello")
    assert second is not None
    assert second is not first
