"""Cross-process policy file locking (requires fcntl)."""

from __future__ import annotations

import asyncio
import multiprocessing as mp
from pathlib import Path

import pytest
from fastmcp import FastMCP

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.config import Settings
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.rbac.policy_document import AllowAdd
from keystone_mcp.rbac.policy_store import PolicyStore
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry

pytest.importorskip("fcntl")

MP_POLICY = """\
version: "1.0.0"
default_deny: true
roles:
  administrator:
    description: admin
    allow: ["*"]
  role_a:
    description: a
    allow: [docs_search]
  role_b:
    description: b
    allow: [docs_search]
"""


def _worker(
    policy_path: str,
    redis_url: str,
    role: str,
    patterns: tuple[str, ...],
    catalog_names: tuple[str, ...],
) -> None:
    asyncio.run(_worker_async(policy_path, redis_url, role, patterns, catalog_names))


async def _worker_async(
    policy_path: str,
    redis_url: str,
    role: str,
    patterns: tuple[str, ...],
    catalog_names: tuple[str, ...],
) -> None:
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=policy_path,
        rbac_audit_subject_salt="mp",
        policy_tools="full",
        redis_url=redis_url,
    )
    routes = ("users_list", "policy_read", "policy_role_set", "docs_search", "docs_read")
    routes += catalog_names
    mcp = FastMCP("mp-policy")
    registry = RouterRegistry(RouterEngine(settings), mcp)
    for name in routes:
        registry.add_route(name, StubAdapter(), mode="live")
    manager = RbacPolicyManager(settings)
    manager.load_initial(registry)
    store = PolicyStore(
        settings=settings,
        policy_manager=manager,
        registry=registry,
    )
    for pattern in patterns:
        await store.change(
            changes=[AllowAdd(role, [pattern])],
            actor="admin@example.com",
            actor_roles=frozenset({"administrator"}),
            expected_hash=None,
            operation="policy_allow_add",
            task_id=f"{role}-{pattern}",
        )


def test_two_processes_on_one_file_lose_no_change(tmp_path: Path) -> None:
    from support.test_env import require_redis_url

    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(MP_POLICY, encoding="utf-8")
    redis_url = require_redis_url()
    ctx = mp.get_context("spawn")
    patterns_a = tuple(f"docs_a{i}" for i in range(10))
    patterns_b = tuple(f"docs_b{i}" for i in range(10))
    catalog_names = patterns_a + patterns_b

    p_a = ctx.Process(
        target=_worker,
        args=(str(policy_path), redis_url, "role_a", patterns_a, catalog_names),
    )
    p_b = ctx.Process(
        target=_worker,
        args=(str(policy_path), redis_url, "role_b", patterns_b, catalog_names),
    )
    p_a.start()
    p_b.start()
    p_a.join(timeout=120)
    p_b.join(timeout=120)
    assert p_a.exitcode == 0
    assert p_b.exitcode == 0

    text = policy_path.read_text(encoding="utf-8")
    for pattern in patterns_a:
        assert pattern in text
    for pattern in patterns_b:
        assert pattern in text
