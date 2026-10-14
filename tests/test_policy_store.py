"""Tests for PolicyStore: atomic write, optimistic lock, catalog gate, reload, rollback."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastmcp import FastMCP

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.config import Settings
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.rbac.policy_document import (
    AllowAdd,
    PolicyChangeError,
    PolicyDocument,
    RoleBody,
    RoleDelete,
    RoleSet,
)
from keystone_mcp.rbac.policy_store import PolicyStore
from keystone_mcp.rbac.upstream_state import UpstreamCatalogState
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from support.test_env import require_redis_url

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

#: The live catalog every test's registry publishes: the platform's own
#: users_list, two stand-in policy_* tools (V02 has not shipped any yet), and
#: two tools from an unrelated namespace.
LIVE_ROUTE_NAMES = ("users_list", "policy_read", "policy_role_set", "docs_search", "docs_read")

ADMIN_ROLES = frozenset({"administrator"})


def _build_registry(settings: Settings) -> RouterRegistry:
    mcp = FastMCP("policy-store-tests")
    registry = RouterRegistry(RouterEngine(settings), mcp)
    adapter = StubAdapter()
    for name in LIVE_ROUTE_NAMES:
        registry.add_route(name, adapter, mode="live")
    return registry


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
        rbac_audit_subject_salt="salt",
        policy_tools="full",
        redis_url=require_redis_url(),
    )


@pytest.fixture
def directory() -> InMemoryUserDirectory:
    users = InMemoryUserDirectory()
    users.seed("admin@example.com", roles=("administrator",))
    return users


def _build_store(
    settings: Settings,
    *,
    directory: InMemoryUserDirectory | None = None,
    upstream_state=None,
) -> tuple[PolicyStore, RouterRegistry, RbacPolicyManager]:
    registry = _build_registry(settings)
    manager = RbacPolicyManager(settings, upstream_catalog_state=upstream_state)
    manager.load_initial(registry)
    store = PolicyStore(
        settings=settings,
        policy_manager=manager,
        registry=registry,
        observability=None,
        directory=directory,
    )
    return store, registry, manager


# ── change(): atomic write ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_change_writes_atomically(settings: Settings, policy_path: Path, directory) -> None:
    store, _registry, manager = _build_store(settings, directory=directory)

    result = await store.change(
        changes=[AllowAdd("editor", ["users_list"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="task-1",
    )

    assert result.changed is True
    assert policy_path.is_file()
    bak_path = policy_path.with_suffix(policy_path.suffix + ".bak")
    tmp_path = policy_path.with_suffix(policy_path.suffix + ".tmp")
    assert bak_path.is_file()
    assert not tmp_path.exists()
    assert bak_path.read_text(encoding="utf-8") == TEST_POLICY
    assert "users_list" in policy_path.read_text(encoding="utf-8")
    assert manager.identity is not None
    assert manager.identity.content_hash == result.content_hash_after


@pytest.mark.asyncio
async def test_change_preserves_file_permissions(
    settings: Settings, policy_path: Path, directory
) -> None:
    os.chmod(policy_path, 0o640)
    store, _registry, _manager = _build_store(settings, directory=directory)

    await store.change(
        changes=[AllowAdd("editor", ["users_list"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="task-1",
    )

    assert oct(policy_path.stat().st_mode & 0o777) == oct(0o640)


# ── change(): nothing to apply ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_change_with_no_effect_is_a_noop(
    settings: Settings, policy_path: Path, directory
) -> None:
    before = policy_path.read_text(encoding="utf-8")
    store, _registry, _manager = _build_store(settings, directory=directory)

    result = await store.change(
        changes=[AllowAdd("editor", ["docs_search"])],  # already present
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="task-1",
    )

    assert result.changed is False
    assert policy_path.read_text(encoding="utf-8") == before
    assert not policy_path.with_suffix(policy_path.suffix + ".bak").exists()


# ── change(): optimistic lock ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_change_refuses_stale_expected_hash(
    settings: Settings, policy_path: Path, directory
) -> None:
    before = policy_path.read_text(encoding="utf-8")
    store, _registry, _manager = _build_store(settings, directory=directory)

    with pytest.raises(PolicyChangeError) as exc_info:
        await store.change(
            changes=[AllowAdd("editor", ["users_list"])],
            actor="admin@example.com",
            actor_roles=ADMIN_ROLES,
            expected_hash="not-the-real-hash",
            operation="policy_allow_add",
            task_id="task-1",
        )

    assert exc_info.value.code == "policy_conflict"
    assert policy_path.read_text(encoding="utf-8") == before


# ── change(): catalog gate ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_change_refuses_pattern_with_no_catalog_owner(
    settings: Settings, policy_path: Path, directory
) -> None:
    before = policy_path.read_text(encoding="utf-8")
    store, _registry, _manager = _build_store(settings, directory=directory)

    with pytest.raises(PolicyChangeError) as exc_info:
        await store.change(
            changes=[AllowAdd("editor", ["nope_*"])],
            actor="admin@example.com",
            actor_roles=ADMIN_ROLES,
            expected_hash=None,
            operation="policy_allow_add",
            task_id="task-1",
        )

    assert exc_info.value.code == "unmatched_pattern"
    assert policy_path.read_text(encoding="utf-8") == before


@pytest.mark.asyncio
async def test_change_applies_pattern_for_unavailable_namespace_with_warning(
    settings: Settings, policy_path: Path, directory
) -> None:
    upstream_state = lambda: UpstreamCatalogState(  # noqa: E731
        namespaces=frozenset({"future"}), unavailable=frozenset({"future"})
    )
    store, _registry, _manager = _build_store(
        settings, directory=directory, upstream_state=upstream_state
    )

    result = await store.change(
        changes=[AllowAdd("editor", ["future_tool"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="task-1",
    )

    assert result.changed is True
    assert any("future" in warning for warning in result.warnings)


# ── change(): invariants ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_change_refuses_deleting_a_role_in_use(
    settings: Settings, policy_path: Path, directory
) -> None:
    directory.seed("editor@example.com", roles=("editor",))
    before = policy_path.read_text(encoding="utf-8")
    store, _registry, _manager = _build_store(settings, directory=directory)

    with pytest.raises(PolicyChangeError) as exc_info:
        await store.change(
            changes=[RoleDelete("editor")],
            actor="admin@example.com",
            actor_roles=ADMIN_ROLES,
            expected_hash=None,
            operation="policy_role_delete",
            task_id="task-1",
        )

    assert exc_info.value.code == "role_in_use"
    assert policy_path.read_text(encoding="utf-8") == before


@pytest.mark.asyncio
async def test_change_allows_deleting_an_unassigned_role(
    settings: Settings, policy_path: Path, directory
) -> None:
    store, _registry, _manager = _build_store(settings, directory=directory)

    result = await store.change(
        changes=[RoleDelete("editor")],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_role_delete",
        task_id="task-1",
    )

    assert result.changed is True
    assert "editor" not in result.document.roles


@pytest.mark.asyncio
async def test_change_refuses_self_lockout(
    settings: Settings, policy_path: Path, directory
) -> None:
    # "administrator" is untouched and keeps "*", so check_no_role_can_administer
    # passes; "editor" (the acting role here) has never held policy_role_set,
    # so any change still leaves it unable to call that tool.
    before = policy_path.read_text(encoding="utf-8")
    store, _registry, _manager = _build_store(settings, directory=directory)

    with pytest.raises(PolicyChangeError) as exc_info:
        await store.change(
            changes=[AllowAdd("editor", ["users_list"])],
            actor="editor@example.com",
            actor_roles=frozenset({"editor"}),
            expected_hash=None,
            operation="policy_allow_add",
            task_id="task-1",
        )

    assert exc_info.value.code == "self_lockout_forbidden"
    assert policy_path.read_text(encoding="utf-8") == before


@pytest.mark.asyncio
async def test_change_refuses_leaving_no_administering_role(
    settings: Settings, policy_path: Path, directory
) -> None:
    store, _registry, _manager = _build_store(settings, directory=directory)

    with pytest.raises(PolicyChangeError) as exc_info:
        await store.change(
            changes=[
                RoleSet("administrator", ["docs_search"]),
                RoleSet("editor", ["docs_search"]),
            ],
            actor="admin@example.com",
            actor_roles=ADMIN_ROLES,
            expected_hash=None,
            operation="policy_role_set",
            task_id="task-1",
        )

    # No role at all would keep users_list/policy_* reachable, so this is
    # caught by check_no_role_can_administer (checked before self-lockout).
    assert exc_info.value.code == "policy_invariant"


# ── change(): read-only ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_change_refuses_when_policy_tools_is_read_only(
    settings: Settings, policy_path: Path, directory
) -> None:
    from dataclasses import replace

    read_only_settings = replace(settings, policy_tools="read-only")
    store, _registry, _manager = _build_store(read_only_settings, directory=directory)

    with pytest.raises(PolicyChangeError) as exc_info:
        await store.change(
            changes=[AllowAdd("editor", ["users_list"])],
            actor="admin@example.com",
            actor_roles=ADMIN_ROLES,
            expected_hash=None,
            operation="policy_allow_add",
            task_id="task-1",
        )

    assert exc_info.value.code == "policy_readonly"
    assert store.writable is False


@pytest.mark.asyncio
async def test_change_refuses_when_file_is_not_writable(
    settings: Settings, policy_path: Path, directory
) -> None:
    if os.geteuid() == 0:
        pytest.skip("root can write a 0o444 file")
    os.chmod(policy_path, 0o444)
    try:
        store, _registry, _manager = _build_store(settings, directory=directory)
        with pytest.raises(PolicyChangeError) as exc_info:
            await store.change(
                changes=[AllowAdd("editor", ["users_list"])],
                actor="admin@example.com",
                actor_roles=ADMIN_ROLES,
                expected_hash=None,
                operation="policy_allow_add",
                task_id="task-1",
            )
        assert exc_info.value.code == "policy_readonly"
    finally:
        os.chmod(policy_path, 0o644)


# ── rollback() ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rollback_restores_the_previous_file(
    settings: Settings, policy_path: Path, directory
) -> None:
    store, _registry, manager = _build_store(settings, directory=directory)
    changed = await store.change(
        changes=[AllowAdd("editor", ["users_list"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="task-1",
    )
    assert "users_list" in policy_path.read_text(encoding="utf-8")

    result = await store.rollback(
        actor="admin@example.com", actor_roles=ADMIN_ROLES, task_id="task-2"
    )

    assert result.changed is True
    assert "users_list" not in policy_path.read_text(encoding="utf-8")
    assert result.content_hash_before == changed.content_hash_after
    assert manager.identity is not None
    assert manager.identity.content_hash == result.content_hash_after


@pytest.mark.asyncio
async def test_rollback_without_a_backup_is_nothing_to_rollback(
    settings: Settings, policy_path: Path, directory
) -> None:
    store, _registry, _manager = _build_store(settings, directory=directory)

    with pytest.raises(PolicyChangeError) as exc_info:
        await store.rollback(actor="admin@example.com", actor_roles=ADMIN_ROLES, task_id="task-1")

    assert exc_info.value.code == "nothing_to_rollback"


# ── read() ───────────────────────────────────────────────────────────────────


def test_read_reports_file_and_active_hash(
    settings: Settings, policy_path: Path, directory
) -> None:
    store, _registry, manager = _build_store(settings, directory=directory)

    result = store.read()

    assert result.content_hash == manager.identity.content_hash
    assert result.file_hash == result.content_hash
    assert result.writable is True
    assert result.path == policy_path


def test_read_detects_drift_from_an_out_of_band_edit(
    settings: Settings, policy_path: Path, directory
) -> None:
    store, _registry, manager = _build_store(settings, directory=directory)
    active_hash_before = manager.identity.content_hash

    # Edited directly on disk, bypassing PolicyStore entirely (another
    # replica on a shared volume, or an operator's hand edit).
    policy_path.write_text(TEST_POLICY + "\n# a trailing comment\n", encoding="utf-8")

    result = store.read()

    assert result.content_hash == active_hash_before
    assert result.file_hash != active_hash_before


# ── validate() ───────────────────────────────────────────────────────────────


def test_validate_does_not_write(settings: Settings, policy_path: Path, directory) -> None:
    before = policy_path.read_text(encoding="utf-8")
    store, _registry, _manager = _build_store(settings, directory=directory)
    document = store.read().document.apply(AllowAdd("editor", ["nope_*"]))

    result = store.validate(document)

    assert result.ok is False
    assert result.errors
    assert policy_path.read_text(encoding="utf-8") == before


def test_validate_reports_unreachable_tools_without_failing(
    settings: Settings, policy_path: Path, directory
) -> None:
    store, _registry, _manager = _build_store(settings, directory=directory)
    document = PolicyDocument(
        version="1.0.0", roles={"viewer": RoleBody(description="", allow=["docs_read"])}
    )

    result = store.validate(document)

    assert result.ok is True
    assert "users_list" in result.unreachable_tools
