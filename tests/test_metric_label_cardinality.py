"""Prometheus label cardinality for published vs client-supplied names."""

from __future__ import annotations

import json
import secrets
import uuid
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path
from typing import AsyncIterator

import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client
from fastmcp.exceptions import ToolError
from prometheus_client import REGISTRY

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.server import bootstrap_platform, build_server
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver
from support.login import dev_token_login
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)

SUBJECT = "metrics-user@example.com"

ALLOW_ALL_POLICY = """\
version: "metric-labels"
default_deny: true
roles:
  administrator:
    allow: ["*"]
"""


def _counter_snapshot(metric_basename: str) -> dict[frozenset[tuple[str, str]], float]:
    values: dict[frozenset[tuple[str, str]], float] = {}
    for family in REGISTRY.collect():
        if family.name != metric_basename:
            continue
        for sample in family.samples:
            if sample.name != f"{metric_basename}_total":
                continue
            key = frozenset(sample.labels.items())
            values[key] = values.get(key, 0.0) + float(sample.value)
    return values


def _increased_label_sets(
    before: dict[frozenset[tuple[str, str]], float],
    after: dict[frozenset[tuple[str, str]], float],
) -> set[frozenset[tuple[str, str]]]:
    return {key for key, value in after.items() if value > before.get(key, 0.0)}


def _label_value(labels: frozenset[tuple[str, str]], name: str) -> str | None:
    return dict(labels).get(name)


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "rbac-policy.yaml"
    path.write_text(ALLOW_ALL_POLICY, encoding="utf-8")
    return path


@pytest.fixture
def patch_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = VerifiedIdentity(email=SUBJECT)
    for module in (
        "keystone_mcp.identity",
        "keystone_mcp.router.rbac_middleware",
        "keystone_mcp.router.throttle_middleware",
        "keystone_mcp.observability.tool_call_labels",
    ):
        monkeypatch.setattr(f"{module}.resolve_verified_identity", lambda: identity)


def _base_settings(policy_path: Path, *, metrics_tool_name: str = "full") -> Settings:
    return Settings(
        base_url="http://localhost:8080",
        metrics_enabled=True,
        metrics_tool_name=metrics_tool_name,
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        throttle_max_requests=50_000,
        throttle_window_seconds=60,
        redis_url="redis://localhost:6379/13",
        users_service_url="http://users:8000",
        users_service_token="token",
        rbac_audit_subject_salt="metric-label-salt",
    )


@asynccontextmanager
async def _built_client(
    settings: Settings,
    policy_path: Path,
    *,
    register_builtin: bool = True,
    upstreams_json: str | None = None,
) -> AsyncIterator[tuple[Client, object, object]]:
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.seed(SUBJECT, roles=("administrator",))

    if upstreams_json is not None:
        settings = replace(settings, upstreams_json=upstreams_json)

    observed: dict = {}
    upstream_app = None
    if upstreams_json:
        upstream_app = build_lowlevel_upstream_app(
            tools=["greet"],
            prompts=True,
            resources=True,
            observed=observed,
        )

    mcp, registry, oauth, upstreams, policy_manager, observability, reconciler = build_server(
        settings=settings,
        user_resolver=resolver,
        oauth_store=InMemoryOAuthStore(),
        login_providers=[dev_token_login({"dev"})],
        register_builtin_catalog=register_builtin,
    )
    if upstream_app is not None:
        factory = asgi_http_client_factory(upstream_app)
        upstreams.http_client_factory = factory
        for adapter in upstreams._adapters.values():  # noqa: SLF001 — test harness
            adapter._http_client_factory = factory  # noqa: SLF001

    if policy_manager is not None:
        policy_manager.load_initial(registry)

    if upstream_app is not None:
        async with LifespanManager(upstream_app):
            async with LifespanManager(mcp.http_app(path=settings.http_path)):
                await bootstrap_platform(
                    upstreams,
                    registry,
                    settings,
                    policy_manager,
                    observability=observability,
                )
                async with Client(mcp) as client:
                    yield client, registry, observability
    else:
        async with Client(mcp) as client:
            yield client, registry, observability


@pytest.mark.asyncio
@pytest.mark.parametrize("metrics_tool_name", ["full", "coarse"])
async def test_unknown_tool_names_collapse_to_one_series(
    policy_path: Path,
    patch_identity: None,
    metrics_tool_name: str,
) -> None:
    settings = _base_settings(policy_path, metrics_tool_name=metrics_tool_name)
    attempts_before = _counter_snapshot("keystone_mcp_tool_call_attempts")
    decisions_before = _counter_snapshot("keystone_mcp_rbac_decisions")

    async with _built_client(settings, policy_path) as (client, _registry, _obs):
        for _ in range(1000):
            with pytest.raises(ToolError):
                await client.call_tool(f"rand_{secrets.token_hex(8)}", {})

    attempts_after = _counter_snapshot("keystone_mcp_tool_call_attempts")
    decisions_after = _counter_snapshot("keystone_mcp_rbac_decisions")

    new_attempts = _increased_label_sets(attempts_before, attempts_after)
    assert len(new_attempts) <= 1
    if new_attempts:
        labels = next(iter(new_attempts))
        assert _label_value(labels, "tool") == "unknown"
        assert _label_value(labels, "tool_family") == "unknown"
        assert _label_value(labels, "namespace") == "unknown"

    new_decisions = {
        s
        for s in _increased_label_sets(decisions_before, decisions_after)
        if _label_value(s, "operation") == "call_tool"
    }
    assert len(new_decisions) <= 1
    if new_decisions:
        labels = next(iter(new_decisions))
        assert _label_value(labels, "tool_family") == "unknown"


@pytest.mark.asyncio
async def test_known_builtin_tool_keeps_its_labels(
    policy_path: Path,
    patch_identity: None,
) -> None:
    settings = _base_settings(policy_path)
    before = _counter_snapshot("keystone_mcp_tool_call_attempts")

    async with _built_client(settings, policy_path) as (client, _registry, _obs):
        await client.call_tool("users_list", {})

    after = _counter_snapshot("keystone_mcp_tool_call_attempts")
    increased = _increased_label_sets(before, after)
    matching = [
        s
        for s in increased
        if _label_value(s, "tool") == "users_list"
        and _label_value(s, "tool_family") == "users"
        and _label_value(s, "namespace") == "users"
    ]
    assert len(matching) >= 1


@pytest.mark.asyncio
async def test_proxied_tool_keeps_its_labels(
    policy_path: Path,
    patch_identity: None,
) -> None:
    upstreams_json = json.dumps(
        [
            {
                "name": "hello-upstream",
                "url": UPSTREAM_MCP_URL,
                "namespace": "hello",
                "enabled": True,
            }
        ]
    )
    settings = _base_settings(policy_path)
    before = _counter_snapshot("keystone_mcp_tool_call_attempts")

    async with _built_client(settings, policy_path, upstreams_json=upstreams_json) as (
        client,
        _registry,
        _obs,
    ):
        await client.call_tool("hello_greet", {"name": "world"})

    after = _counter_snapshot("keystone_mcp_tool_call_attempts")
    increased = _increased_label_sets(before, after)
    matching = [
        s
        for s in increased
        if _label_value(s, "tool") == "hello_greet"
        and _label_value(s, "tool_family") == "hello"
        and _label_value(s, "namespace") == "hello"
    ]
    assert len(matching) >= 1


@pytest.mark.asyncio
async def test_unknown_prompt_and_resource_uri_are_unknown(
    policy_path: Path,
    patch_identity: None,
) -> None:
    upstreams_json = json.dumps(
        [
            {
                "name": "hello-upstream",
                "url": UPSTREAM_MCP_URL,
                "namespace": "hello",
                "enabled": True,
            }
        ]
    )
    settings = _base_settings(policy_path)
    before = _counter_snapshot("keystone_mcp_rbac_decisions")

    async with _built_client(settings, policy_path, upstreams_json=upstreams_json) as (
        client,
        _registry,
        _obs,
    ):
        for _ in range(200):
            with pytest.raises(Exception):
                await client.get_prompt(f"rand_{secrets.token_hex(6)}", {})
        for _ in range(200):
            with pytest.raises(Exception):
                await client.read_resource(f"file:///rand-{uuid.uuid4().hex}.md")

    after = _counter_snapshot("keystone_mcp_rbac_decisions")
    for operation in ("get_prompt", "read_resource"):
        increased = {
            s
            for s in _increased_label_sets(before, after)
            if _label_value(s, "operation") == operation
        }
        assert len(increased) <= 1
        if increased:
            assert _label_value(next(iter(increased)), "tool_family") == "unknown"


@pytest.mark.asyncio
async def test_tool_added_by_reconciler_gets_its_own_label(
    policy_path: Path,
    patch_identity: None,
) -> None:
    settings = _base_settings(policy_path)
    suffix = uuid.uuid4().hex[:8]

    async with _built_client(settings, policy_path, register_builtin=False) as (
        client,
        registry,
        _obs,
    ):
        published = f"probe_{suffix}"
        registry.add_route(published, StubAdapter(), mode="live")
        before = _counter_snapshot("keystone_mcp_tool_call_attempts")
        await client.call_tool(published, {})
        after = _counter_snapshot("keystone_mcp_tool_call_attempts")
        increased = _increased_label_sets(before, after)
        matching = [
            s
            for s in increased
            if _label_value(s, "tool") == published and _label_value(s, "tool_family") == "probe"
        ]
        assert len(matching) >= 1
