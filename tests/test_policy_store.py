"""Tests for PolicyStore: atomic write, optimistic lock, catalog gate, reload, rollback."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import FastMCP

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.config import Settings
from keystone_mcp.rbac.loader import PolicyReloadResult, RbacPolicyManager
from keystone_mcp.rbac.policy import hash_policy_bytes
from keystone_mcp.rbac.policy_document import (
    AllowAdd,
    AllowRemove,
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
    assert bak_path.is_file()
    assert not list(policy_path.parent.glob(f".{policy_path.name}.*.tmp"))
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


CONCURRENT_POLICY = """\
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
  temp:
    description: unused
    allow:
      - docs_search
"""


class SlowDirectoryGate(InMemoryUserDirectory):
    gate: asyncio.Event

    async def list_users(self, *args, **kwargs):
        await self.gate.wait()
        return await super().list_users(*args, **kwargs)


class SlowDirectorySleep(InMemoryUserDirectory):
    async def list_users(self, **kwargs):
        await asyncio.sleep(0.2)
        return await super().list_users(**kwargs)


@pytest.fixture
def concurrent_policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "rbac-policy.yaml"
    path.write_text(CONCURRENT_POLICY, encoding="utf-8")
    return path


@pytest.fixture
def concurrent_settings(concurrent_policy_path: Path) -> Settings:
    return Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(concurrent_policy_path),
        rbac_audit_subject_salt="salt",
        policy_tools="full",
        redis_url=require_redis_url(),
    )


def _build_store_on_policy(
    settings: Settings,
    policy_path: Path,
    *,
    directory: InMemoryUserDirectory | None = None,
    file_lock_timeout_seconds: float = 10.0,
    observability: object | None = None,
) -> tuple[PolicyStore, RouterRegistry, RbacPolicyManager]:
    registry = _build_registry(settings)
    manager = RbacPolicyManager(settings)
    manager.load_initial(registry)
    store = PolicyStore(
        settings=settings,
        policy_manager=manager,
        registry=registry,
        observability=observability,
        directory=directory,
        file_lock_timeout_seconds=file_lock_timeout_seconds,
    )
    return store, registry, manager


@pytest.mark.asyncio
async def test_concurrent_changes_lose_nothing(
    concurrent_settings: Settings, concurrent_policy_path: Path
) -> None:
    directory = SlowDirectoryGate()
    directory.gate = asyncio.Event()
    directory.seed("admin@example.com", roles=("administrator",))
    store, _registry, manager = _build_store_on_policy(
        concurrent_settings, concurrent_policy_path, directory=directory
    )
    admin = ADMIN_ROLES
    delete_task = asyncio.create_task(
        store.change(
            changes=[RoleDelete("temp")],
            actor="admin@example.com",
            actor_roles=admin,
            expected_hash=None,
            operation="policy_role_delete",
            task_id="a",
        )
    )
    remove_task = asyncio.create_task(
        store.change(
            changes=[AllowRemove("editor", ["docs_read"])],
            actor="admin@example.com",
            actor_roles=admin,
            expected_hash=None,
            operation="policy_allow_remove",
            task_id="b",
        )
    )
    await asyncio.sleep(0.05)
    directory.gate.set()
    delete_result = await delete_task
    remove_result = await remove_task
    assert delete_result.changed is True
    assert remove_result.changed is True
    assert "temp" not in store.read().document.roles
    assert "docs_read" not in store.read().document.roles["editor"].allow
    assert not manager.policy.allows(frozenset({"editor"}), "docs_read")


@pytest.mark.asyncio
async def test_concurrent_changes_with_same_expected_hash_second_gets_conflict(
    concurrent_settings: Settings, concurrent_policy_path: Path
) -> None:
    race_policy = """\
version: "1.0.0"
default_deny: true
roles:
  administrator: {description: admin, allow: ["*"]}
  editor: {description: editor, allow: [docs_search]}
  legacy: {description: old, allow: [docs_read]}
"""
    concurrent_policy_path.write_text(race_policy, encoding="utf-8")
    directory = SlowDirectorySleep()
    directory.seed("admin@example.com", roles=("administrator",))
    store, _registry, _manager = _build_store_on_policy(
        concurrent_settings, concurrent_policy_path, directory=directory
    )
    file_hash = hash_policy_bytes(concurrent_policy_path.read_bytes())
    kw = dict(
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=file_hash,
    )
    delete_task = asyncio.create_task(
        store.change(
            changes=[RoleDelete("legacy")],
            operation="policy_role_delete",
            task_id="a",
            **kw,
        )
    )
    allow_task = asyncio.create_task(
        store.change(
            changes=[AllowAdd("editor", ["docs_read"])],
            operation="policy_allow_add",
            task_id="b",
            **kw,
        )
    )
    await asyncio.sleep(0.05)
    delete_result = await delete_task
    assert delete_result.changed is True
    with pytest.raises(PolicyChangeError) as exc_info:
        await allow_task
    assert exc_info.value.code == "policy_conflict"
    doc = store.read().document
    assert "legacy" not in doc.roles
    assert "docs_read" not in doc.roles["editor"].allow


@pytest.mark.asyncio
async def test_lock_timeout_is_policy_conflict(
    concurrent_settings: Settings, concurrent_policy_path: Path, directory
) -> None:
    fcntl = pytest.importorskip("fcntl")
    store, _registry, _manager = _build_store_on_policy(
        concurrent_settings,
        concurrent_policy_path,
        directory=directory,
        file_lock_timeout_seconds=0.2,
    )
    lock_path = concurrent_policy_path.with_suffix(concurrent_policy_path.suffix + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        with pytest.raises(PolicyChangeError) as exc_info:
            await store.change(
                changes=[AllowAdd("editor", ["users_list"])],
                actor="admin@example.com",
                actor_roles=ADMIN_ROLES,
                expected_hash=None,
                operation="policy_allow_add",
                task_id="t",
            )
        assert exc_info.value.code == "policy_conflict"
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


@pytest.mark.asyncio
async def test_file_changed_behind_the_lock_is_conflict(
    concurrent_settings: Settings, concurrent_policy_path: Path, directory
) -> None:
    store, _registry, _manager = _build_store_on_policy(
        concurrent_settings, concurrent_policy_path, directory=directory
    )
    outsider = concurrent_policy_path.read_text(encoding="utf-8") + "\n# touched\n"

    async def slow_check_role_in_use(change, directory_arg):
        concurrent_policy_path.write_text(outsider, encoding="utf-8")
        await asyncio.sleep(0)

    with patch(
        "keystone_mcp.rbac.policy_store.check_role_in_use",
        side_effect=slow_check_role_in_use,
    ):
        with pytest.raises(PolicyChangeError) as exc_info:
            await store.change(
                changes=[RoleDelete("editor")],
                actor="admin@example.com",
                actor_roles=ADMIN_ROLES,
                expected_hash=None,
                operation="policy_role_delete",
                task_id="t",
            )
    assert exc_info.value.code == "policy_conflict"
    assert concurrent_policy_path.read_text(encoding="utf-8") == outsider


@pytest.mark.asyncio
async def test_temp_files_are_unique_and_cleaned_up(
    concurrent_settings: Settings, concurrent_policy_path: Path, directory
) -> None:
    store, _registry, _manager = _build_store_on_policy(
        concurrent_settings, concurrent_policy_path, directory=directory
    )
    await store.change(
        changes=[AllowAdd("editor", ["users_list"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="ok",
    )
    assert not list(concurrent_policy_path.parent.glob(f".{concurrent_policy_path.name}.*.tmp"))

    observability = MagicMock()
    store_fail, _r, _m = _build_store_on_policy(
        concurrent_settings,
        concurrent_policy_path,
        directory=directory,
        observability=observability,
    )
    real_replace = os.replace

    def boom_replace(src, dst):
        if str(dst).endswith("rbac-policy.yaml"):
            raise OSError("disk full")
        return real_replace(src, dst)

    with patch("keystone_mcp.rbac.policy_store.os.replace", side_effect=boom_replace):
        with pytest.raises(PolicyChangeError) as exc_info:
            await store_fail.change(
                changes=[AllowAdd("editor", ["policy_role_set"])],
                actor="admin@example.com",
                actor_roles=ADMIN_ROLES,
                expected_hash=None,
                operation="policy_allow_add",
                task_id="fail",
            )
    assert exc_info.value.code == "service_unavailable"
    assert not list(concurrent_policy_path.parent.glob(f".{concurrent_policy_path.name}.*.tmp"))
    observability.record_policy_mutation.assert_called()
    assert observability.record_policy_mutation.call_args.kwargs["outcome"] == "error"


@pytest.mark.asyncio
async def test_backup_keeps_policy_file_mode(
    concurrent_settings: Settings, concurrent_policy_path: Path, directory
) -> None:
    os.chmod(concurrent_policy_path, 0o640)
    store, _registry, _manager = _build_store_on_policy(
        concurrent_settings, concurrent_policy_path, directory=directory
    )
    await store.change(
        changes=[AllowAdd("editor", ["users_list"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="t",
    )
    bak = concurrent_policy_path.with_suffix(concurrent_policy_path.suffix + ".bak")
    assert oct(bak.stat().st_mode & 0o777) == oct(0o640)


@pytest.mark.asyncio
async def test_directory_is_fsynced_after_replace(
    concurrent_settings: Settings, concurrent_policy_path: Path, directory, monkeypatch
) -> None:
    store, _registry, _manager = _build_store_on_policy(
        concurrent_settings, concurrent_policy_path, directory=directory
    )
    dir_fsynced = False
    real_fsync = os.fsync

    def track_fsync(fd: int) -> None:
        nonlocal dir_fsynced
        if not dir_fsynced:
            try:
                import stat

                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    dir_fsynced = True
            except OSError:
                pass
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", track_fsync)
    await store.change(
        changes=[AllowAdd("editor", ["users_list"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="t",
    )
    assert dir_fsynced


@pytest.mark.asyncio
async def test_rollback_refuses_stale_expected_hash(
    concurrent_settings: Settings, concurrent_policy_path: Path, directory
) -> None:
    store, _registry, _manager = _build_store_on_policy(
        concurrent_settings, concurrent_policy_path, directory=directory
    )
    before = concurrent_policy_path.read_text(encoding="utf-8")
    await store.change(
        changes=[AllowAdd("editor", ["users_list"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="w",
    )
    with pytest.raises(PolicyChangeError) as exc_info:
        await store.rollback(
            actor="admin@example.com",
            actor_roles=ADMIN_ROLES,
            task_id="r",
            expected_hash="0" * 64,
        )
    assert exc_info.value.code == "policy_conflict"
    assert concurrent_policy_path.read_text(encoding="utf-8") != before


@pytest.mark.asyncio
async def test_rollback_refuses_dropping_an_assigned_role(
    concurrent_settings: Settings, concurrent_policy_path: Path, directory
) -> None:
    minimal = 'version: "1"\ndefault_deny: true\nroles:\n  administrator: {allow: ["*"]}\n'
    concurrent_policy_path.write_text(minimal, encoding="utf-8")
    store, _registry, _manager = _build_store_on_policy(
        concurrent_settings, concurrent_policy_path, directory=directory
    )
    kw = dict(
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        task_id="t",
    )
    await store.change(
        changes=[RoleSet("reader", ["docs_read"])],
        operation="policy_role_set",
        **kw,
    )
    directory.seed("bob@example.com", roles=("reader",))
    with pytest.raises(PolicyChangeError) as exc_info:
        await store.rollback(
            actor="admin@example.com",
            actor_roles=ADMIN_ROLES,
            task_id="rb",
        )
    assert exc_info.value.code == "role_in_use"
    assert "reader" in store.read().document.roles


@pytest.mark.asyncio
async def test_rollback_reload_failure_keeps_both_generations(
    concurrent_settings: Settings, concurrent_policy_path: Path, directory
) -> None:
    store, _registry, manager = _build_store_on_policy(
        concurrent_settings, concurrent_policy_path, directory=directory
    )
    await store.change(
        changes=[AllowAdd("editor", ["users_list"])],
        actor="admin@example.com",
        actor_roles=ADMIN_ROLES,
        expected_hash=None,
        operation="policy_allow_add",
        task_id="w",
    )
    path = concurrent_policy_path
    bak = path.with_suffix(path.suffix + ".bak")
    current_before = path.read_bytes()
    bak_before = bak.read_bytes()
    previous = manager.snapshot

    call_count = {"n": 0}

    def reload_side_effect(registry):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return PolicyReloadResult(success=False, active=previous, error="boom")
        return PolicyReloadResult(success=True, active=manager.snapshot)

    with patch.object(manager, "reload", side_effect=reload_side_effect):
        with pytest.raises(PolicyChangeError) as exc_info:
            await store.rollback(
                actor="admin@example.com",
                actor_roles=ADMIN_ROLES,
                task_id="rb",
            )
    assert exc_info.value.code == "policy_invalid"
    assert path.read_bytes() == current_before
    assert bak.read_bytes() == bak_before


@pytest.mark.asyncio
async def test_change_reload_failure_keeps_backup(
    settings: Settings, policy_path: Path, directory
) -> None:
    store, _registry, manager = _build_store(settings, directory=directory)
    original = policy_path.read_bytes()
    previous = manager.snapshot

    call_count = {"n": 0}

    def reload_side_effect(registry):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return PolicyReloadResult(success=False, active=previous, error="boom")
        return PolicyReloadResult(success=True, active=manager.snapshot)

    with patch.object(manager, "reload", side_effect=reload_side_effect):
        with pytest.raises(PolicyChangeError) as exc_info:
            await store.change(
                changes=[AllowAdd("editor", ["users_list"])],
                actor="admin@example.com",
                actor_roles=ADMIN_ROLES,
                expected_hash=None,
                operation="policy_allow_add",
                task_id="t",
            )
    assert exc_info.value.code == "policy_invalid"
    assert policy_path.read_bytes() == original
    assert policy_path.with_suffix(policy_path.suffix + ".bak").is_file()
