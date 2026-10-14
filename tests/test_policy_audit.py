"""Tests for the rbac_policy_mutation audit event and its Prometheus metric."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from fastmcp import FastMCP
from prometheus_client import REGISTRY

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.config import Settings
from keystone_mcp.observability.service import RbacObservability
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.rbac.policy_document import AllowAdd, PolicyChangeError
from keystone_mcp.rbac.policy_store import PolicyStore
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from support.test_env import UNUSED_REDIS_URL

TEST_POLICY = """\
version: "1.0.0"
default_deny: true
roles:
  administrator:
    description: admin
    allow: ["*"]
  editor:
    description: editor
    allow:
      - docs_search
      - docs_read
      - policy_read
"""

ADMIN_ROLES = frozenset({"administrator"})


def _parse_audit_records(caplog: pytest.LogCaptureFixture) -> list[dict]:
    records: list[dict] = []
    for record in caplog.records:
        if not record.message.startswith("rbac audit "):
            continue
        records.append(json.loads(record.message.removeprefix("rbac audit ")))
    return records


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "rbac-policy.yaml"
    path.write_text(TEST_POLICY, encoding="utf-8")
    return path


@pytest.fixture
def settings(policy_path: Path) -> Settings:
    return Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        rbac_audit_enabled=True,
        rbac_audit_subject_salt="salt",
        policy_tools="full",
        redis_url=UNUSED_REDIS_URL,
        metrics_enabled=True,
    )


@pytest.fixture
def directory() -> InMemoryUserDirectory:
    users = InMemoryUserDirectory()
    users.seed("admin@example.com", roles=("administrator",))
    return users


@pytest.fixture
def store_and_manager(settings: Settings, directory: InMemoryUserDirectory):
    mcp = FastMCP("policy-audit-tests")
    registry = RouterRegistry(RouterEngine(settings), mcp)
    adapter = StubAdapter()
    for name in ("users_list", "policy_read", "policy_role_set", "docs_search", "docs_read"):
        registry.add_route(name, adapter, mode="live")
    manager = RbacPolicyManager(settings)
    manager.load_initial(registry)
    observability = RbacObservability(settings, policy_manager=manager)
    store = PolicyStore(
        settings=settings,
        policy_manager=manager,
        registry=registry,
        observability=observability,
        directory=directory,
    )
    return store, manager, observability


@pytest.mark.asyncio
async def test_successful_change_is_audited(
    caplog: pytest.LogCaptureFixture, store_and_manager
) -> None:
    caplog.set_level(logging.INFO)
    store, _manager, _observability = store_and_manager

    await store.change(
        changes=[AllowAdd("editor", ["users_list", "policy_role_set"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="task-1",
    )

    events = [e for e in _parse_audit_records(caplog) if e["event"] == "rbac_policy_mutation"]
    assert len(events) == 1
    event = events[0]

    assert event["operation"] == "policy_allow_add"
    assert event["outcome"] == "applied"
    assert event["code"] is None
    assert event["task_id"] == "task-1"
    assert event["policy_version_before"] == "1.0.0"
    assert event["policy_version_after"] == "1.0.0"
    assert event["content_hash_before"] is not None
    assert event["content_hash_after"] is not None
    assert event["content_hash_before"] != event["content_hash_after"]
    assert event["changes"] == ["allow_add:editor:+2"]
    assert event["warnings_count"] == 0

    # Never the raw email, in either the actor field or anywhere in the event.
    assert event["actor"] != "admin@example.com"
    assert "admin@example.com" not in json.dumps(event)
    # Never the pattern text either.
    assert "users_list" not in json.dumps(event["changes"])


@pytest.mark.asyncio
async def test_noop_change_is_audited_with_noop_outcome(
    caplog: pytest.LogCaptureFixture, store_and_manager
) -> None:
    caplog.set_level(logging.INFO)
    store, _manager, _observability = store_and_manager

    await store.change(
        changes=[AllowAdd("editor", ["docs_search"])],  # already present
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="task-2",
    )

    events = [e for e in _parse_audit_records(caplog) if e["event"] == "rbac_policy_mutation"]
    assert len(events) == 1
    assert events[0]["outcome"] == "noop"


@pytest.mark.asyncio
async def test_refused_change_is_audited_with_refused_outcome_and_code(
    caplog: pytest.LogCaptureFixture, store_and_manager
) -> None:
    caplog.set_level(logging.INFO)
    store, _manager, _observability = store_and_manager

    with pytest.raises(PolicyChangeError):
        await store.change(
            changes=[AllowAdd("editor", ["users_list"])],
            actor="admin@example.com",
            actor_roles=ADMIN_ROLES,
            expected_hash="stale-hash",
            operation="policy_allow_add",
            task_id="task-3",
        )

    events = [e for e in _parse_audit_records(caplog) if e["event"] == "rbac_policy_mutation"]
    assert len(events) == 1
    assert events[0]["outcome"] == "refused"
    assert events[0]["code"] == "policy_conflict"


@pytest.mark.asyncio
async def test_observability_failure_never_breaks_a_mutation(
    monkeypatch: pytest.MonkeyPatch, store_and_manager
) -> None:
    store, _manager, observability = store_and_manager

    def _boom(*_args, **_kwargs):
        raise RuntimeError("observability backend is down")

    monkeypatch.setattr(observability, "record_policy_mutation", _boom)

    result = await store.change(
        changes=[AllowAdd("editor", ["users_list"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="task-4",
    )

    assert result.changed is True


@pytest.mark.asyncio
async def test_metric_increments_on_applied_and_refused(store_and_manager) -> None:
    store, _manager, _observability = store_and_manager

    before_applied = REGISTRY.get_sample_value(
        "keystone_mcp_policy_mutation_total",
        {"operation": "policy_allow_add", "outcome": "applied"},
    )
    before_refused = REGISTRY.get_sample_value(
        "keystone_mcp_policy_mutation_total",
        {"operation": "policy_allow_add", "outcome": "refused"},
    )

    await store.change(
        changes=[AllowAdd("editor", ["users_list"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="task-5",
    )
    with pytest.raises(PolicyChangeError):
        await store.change(
            changes=[AllowAdd("editor", ["policy_role_set"])],
            actor="admin@example.com",
            actor_roles=ADMIN_ROLES,
            expected_hash="stale",
            operation="policy_allow_add",
            task_id="task-6",
        )

    after_applied = REGISTRY.get_sample_value(
        "keystone_mcp_policy_mutation_total",
        {"operation": "policy_allow_add", "outcome": "applied"},
    )
    after_refused = REGISTRY.get_sample_value(
        "keystone_mcp_policy_mutation_total",
        {"operation": "policy_allow_add", "outcome": "refused"},
    )

    assert (after_applied or 0) > (before_applied or 0)
    assert (after_refused or 0) > (before_refused or 0)
