"""users_* builtin admin tools — local branch, writing straight to UsersStore.

Mirrors ``tests/test_users_admin_adapter.py`` (the HTTP branch) but exercises
``UsersAdminAdapter`` with ``settings.users_backend == "local"``: no mock
HTTP transport, a real (SQLite-backed) ``UsersStore``, and the RBAC-policy
role check described in the users admin local-backend acceptance notes (private task archive).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from keystone_mcp.adapters.users_admin import UsersAdminAdapter
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import PolicyLoadError
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory.factory import build_user_directory_resolver
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.users.db import create_users_engine
from keystone_mcp.users.revision import NullRevisionWriter
from keystone_mcp.users.store import UsersStore
from support.users_store import make_users_store
from test_users_admin_adapter import USER_SUMMARY

ADMIN = VerifiedIdentity(email="admin@example.com")
ADMIN_B = VerifiedIdentity(email="admin-b@example.com")
ADMIN_C = VerifiedIdentity(email="admin-c@example.com")

DEFAULT_ROLES = frozenset({"administrator", "member"})


def _default_role_source() -> frozenset[str]:
    return DEFAULT_ROLES


def _settings() -> Settings:
    return Settings(base_url="http://localhost:8080", users_backend="local", rbac_mode="off")


def _registry(adapter: UsersAdminAdapter) -> tuple[RouterEngine, RouterRegistry]:
    engine = RouterEngine(_settings())
    registry = RouterRegistry(engine)
    return engine, registry


async def _seed(
    store: UsersStore,
    *,
    email: str,
    full_name: str = "Seed User",
    roles: list[str] | None = None,
    blocked: bool = False,
) -> None:
    await store.create_user(
        email=email,
        full_name=full_name,
        roles=roles or [],
        note=None,
        created_by="system@example.com",
        allowed_roles=None,
    )
    if blocked:
        await store.set_blocked(email=email, blocked=True, actor_email="system@example.com")


_MUTATION_CASES: dict[str, dict] = {
    "users_add": {
        "args": {"email": "new-user@example.com", "full_name": "New User", "roles": ["member"]},
    },
    "users_update": {
        "seed": {"email": "update-user@example.com", "full_name": "Old Name"},
        "args": {"email": "update-user@example.com", "full_name": "New Name"},
    },
    "users_block": {
        "seed": {"email": "block-user@example.com"},
        "args": {"email": "block-user@example.com"},
    },
    "users_unblock": {
        "seed": {"email": "unblock-user@example.com", "blocked": True},
        "args": {"email": "unblock-user@example.com"},
    },
    "users_set_roles": {
        "seed": {"email": "setroles-user@example.com", "roles": ["member"]},
        "args": {"email": "setroles-user@example.com", "roles": ["administrator"]},
    },
    "users_grant_role": {
        "seed": {"email": "grant-user@example.com"},
        "args": {"email": "grant-user@example.com", "role": "member"},
    },
    "users_revoke_role": {
        "seed": {"email": "revoke-user@example.com", "roles": ["member"]},
        "args": {"email": "revoke-user@example.com", "role": "member"},
    },
}

_USER_RESPONSE_KEYS = {
    "email",
    "full_name",
    "roles",
    "is_blocked",
    "created_at",
    "updated_at",
    "created_by",
    "note",
}


@pytest.mark.parametrize(
    "tool_name",
    [
        "users_list",
        "users_add",
        "users_update",
        "users_block",
        "users_unblock",
        "users_set_roles",
        "users_grant_role",
        "users_revoke_role",
    ],
)
async def test_each_tool_runs_against_local_store(tool_name: str, tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=_default_role_source
    )
    engine, registry = _registry(adapter)
    route = registry.add_route(tool_name, adapter, mode="live")

    if tool_name == "users_list":
        args: dict = {}
    else:
        case = _MUTATION_CASES[tool_name]
        if "seed" in case:
            await _seed(store, **case["seed"])
        args = case["args"]

    result = await engine.execute(route, args, identity=ADMIN)

    assert result["state"] == "done"
    if tool_name == "users_list":
        assert "users" in result
        assert "total" in result
    else:
        assert set(result["user"].keys()) == _USER_RESPONSE_KEYS


async def test_users_add_unknown_role_is_validation_error(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=_default_role_source
    )
    engine, registry = _registry(adapter)
    route = registry.add_route("users_add", adapter, mode="live")

    result = await engine.execute(
        route,
        {"email": "ghost-user@example.com", "full_name": "Ghost", "roles": ["ghost"]},
        identity=ADMIN,
    )

    assert result["state"] == "error"
    assert result["code"] == "validation_error"
    assert "unknown role" in result["message"]

    listed = await store.list_users(is_blocked=None)
    assert all(row.email != "ghost-user@example.com" for row in listed)


async def test_grant_and_set_roles_check_policy(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    await _seed(store, email="target@example.com", roles=["member"])
    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=_default_role_source
    )
    engine, registry = _registry(adapter)
    grant_route = registry.add_route("users_grant_role", adapter, mode="live")
    set_roles_route = registry.add_route("users_set_roles", adapter, mode="live")

    granted = await engine.execute(
        grant_route, {"email": "target@example.com", "role": "ghost"}, identity=ADMIN
    )
    assert granted["state"] == "error"
    assert granted["code"] == "validation_error"

    replaced = await engine.execute(
        set_roles_route,
        {"email": "target@example.com", "roles": ["ghost"]},
        identity=ADMIN,
    )
    assert replaced["state"] == "error"
    assert replaced["code"] == "validation_error"


async def test_administrator_accepted_even_if_policy_lacks_it(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    await _seed(store, email="promote-me@example.com", roles=["member"])
    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=lambda: frozenset({"member"})
    )
    engine, registry = _registry(adapter)
    route = registry.add_route("users_grant_role", adapter, mode="live")

    result = await engine.execute(
        route, {"email": "promote-me@example.com", "role": "administrator"}, identity=ADMIN
    )

    assert result["state"] == "done"
    assert "administrator" in result["user"]["roles"]


async def test_no_policy_skips_role_check(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    adapter = UsersAdminAdapter(directory=LocalUserDirectory(store), role_source=None)
    engine, registry = _registry(adapter)
    route = registry.add_route("users_add", adapter, mode="live")

    result = await engine.execute(
        route,
        {"email": "anyone@example.com", "full_name": "Anyone", "roles": ["anything"]},
        identity=ADMIN,
    )

    assert result["state"] == "done"
    assert result["user"]["roles"] == ["anything"]


async def test_policy_not_loaded_is_service_unavailable(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)

    def _raising_source() -> frozenset[str]:
        raise PolicyLoadError("RBAC policy has not been loaded")

    adapter = UsersAdminAdapter(directory=LocalUserDirectory(store), role_source=_raising_source)
    engine, registry = _registry(adapter)
    route = registry.add_route("users_add", adapter, mode="live")

    result = await engine.execute(
        route,
        {"email": "blocked-by-policy@example.com", "full_name": "Nope", "roles": ["member"]},
        identity=ADMIN,
    )

    assert result["state"] == "error"
    assert result["code"] == "service_unavailable"

    listed = await store.list_users(is_blocked=None)
    assert all(row.email != "blocked-by-policy@example.com" for row in listed)


async def test_revoke_role_missing_from_policy_is_allowed(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    # Bypasses the policy check entirely (allowed_roles=None), same as a role
    # that used to be in the policy and was since removed.
    await _seed(store, email="legacy-user@example.com", roles=["legacy"])
    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=_default_role_source
    )
    engine, registry = _registry(adapter)
    route = registry.add_route("users_revoke_role", adapter, mode="live")

    result = await engine.execute(
        route, {"email": "legacy-user@example.com", "role": "legacy"}, identity=ADMIN
    )

    assert result["state"] == "done"
    assert "legacy" not in result["user"]["roles"]


async def test_duplicate_add_is_conflict(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=_default_role_source
    )
    engine, registry = _registry(adapter)
    route = registry.add_route("users_add", adapter, mode="live")
    args = {"email": "dup@example.com", "full_name": "Dup", "roles": []}

    first = await engine.execute(route, args, identity=ADMIN)
    assert first["state"] == "done"

    second = await engine.execute(route, args, identity=ADMIN)
    assert second["state"] == "error"
    assert second["code"] == "conflict"


async def test_unknown_email_is_user_not_found(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=_default_role_source
    )
    engine, registry = _registry(adapter)
    route = registry.add_route("users_block", adapter, mode="live")

    result = await engine.execute(route, {"email": "nobody@example.com"}, identity=ADMIN)

    assert result["state"] == "error"
    assert result["code"] == "user_not_found"


async def test_self_mutation_code(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    await _seed(store, email=ADMIN.email, full_name="Admin A", roles=["administrator"])
    await _seed(store, email=ADMIN_B.email, full_name="Admin B", roles=["administrator"])
    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=_default_role_source
    )
    engine, registry = _registry(adapter)
    block_route = registry.add_route("users_block", adapter, mode="live")
    revoke_route = registry.add_route("users_revoke_role", adapter, mode="live")

    blocked = await engine.execute(block_route, {"email": ADMIN.email}, identity=ADMIN)
    assert blocked["state"] == "error"
    assert blocked["code"] == "self_admin_mutation_forbidden"

    revoked = await engine.execute(
        revoke_route, {"email": ADMIN.email, "role": "administrator"}, identity=ADMIN
    )
    assert revoked["state"] == "error"
    assert revoked["code"] == "self_admin_mutation_forbidden"


async def test_last_administrator_code(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    await _seed(store, email=ADMIN.email, full_name="Only Admin", roles=["administrator"])
    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=_default_role_source
    )
    engine, registry = _registry(adapter)
    block_route = registry.add_route("users_block", adapter, mode="live")
    revoke_route = registry.add_route("users_revoke_role", adapter, mode="live")
    set_roles_route = registry.add_route("users_set_roles", adapter, mode="live")

    # ADMIN_C is not itself an administrator in this store; the adapter never
    # checks that (RBAC middleware is the layer that would), so this exercises
    # the "last administrator" guard independent of the caller's own roles.
    blocked = await engine.execute(block_route, {"email": ADMIN.email}, identity=ADMIN_C)
    assert blocked["code"] == "last_administrator"

    revoked = await engine.execute(
        revoke_route, {"email": ADMIN.email, "role": "administrator"}, identity=ADMIN_C
    )
    assert revoked["code"] == "last_administrator"

    replaced = await engine.execute(
        set_roles_route, {"email": ADMIN.email, "roles": ["member"]}, identity=ADMIN_C
    )
    assert replaced["code"] == "last_administrator"


async def test_actor_is_taken_from_identity_not_arguments(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=_default_role_source
    )
    engine, registry = _registry(adapter)
    route = registry.add_route("users_add", adapter, mode="live")

    result = await engine.execute(
        route,
        {
            "email": "whoami@example.com",
            "full_name": "Who Am I",
            "roles": [],
            "actor_email": "evil@example.com",
        },
        identity=ADMIN,
    )

    assert result["state"] == "done"
    assert result["user"]["created_by"] == ADMIN.email


async def test_grant_existing_role_is_done_without_revision_bump(tmp_path: Path) -> None:
    store, revision = await make_users_store(tmp_path)
    await _seed(store, email="already-member@example.com", roles=["member"])
    after_seed = await revision.current()

    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=_default_role_source
    )
    engine, registry = _registry(adapter)
    route = registry.add_route("users_grant_role", adapter, mode="live")

    result = await engine.execute(
        route, {"email": "already-member@example.com", "role": "member"}, identity=ADMIN
    )

    assert result["state"] == "done"
    assert await revision.current() == after_seed


async def test_mutation_bumps_revision_and_resolver_sees_it(tmp_path: Path) -> None:
    store, reader = await make_users_store(tmp_path)
    await _seed(store, email="watched@example.com")

    resolver = build_user_directory_resolver(_settings(), users_store=store, revision_reader=reader)
    before = await resolver.resolve("watched@example.com")
    assert before.is_blocked is False

    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=_default_role_source
    )
    engine, registry = _registry(adapter)
    route = registry.add_route("users_block", adapter, mode="live")
    result = await engine.execute(route, {"email": "watched@example.com"}, identity=ADMIN)
    assert result["state"] == "done"

    after = await resolver.resolve("watched@example.com")
    assert after.is_blocked is True


class _RecordingObservability:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def record_users_mutation(self, **kwargs) -> None:
        self.calls.append(kwargs)


async def test_audit_receives_before_state(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    # Two separate targets: promoting "roles-audit" to administrator would
    # make the later block of "block-audit" trip the last-administrator guard
    # if they were the same user, which is not what this test is about.
    await _seed(store, email="roles-audit@example.com", roles=["member"])
    await _seed(store, email="block-audit@example.com", roles=["member"])
    observability = _RecordingObservability()
    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store),
        role_source=_default_role_source,
        observability=observability,
    )
    engine, registry = _registry(adapter)
    set_roles_route = registry.add_route("users_set_roles", adapter, mode="live")
    block_route = registry.add_route("users_block", adapter, mode="live")

    await engine.execute(
        set_roles_route,
        {"email": "roles-audit@example.com", "roles": ["administrator"]},
        identity=ADMIN,
    )
    set_roles_call = observability.calls[-1]
    assert set_roles_call["before_roles"] == ("member",)

    await engine.execute(block_route, {"email": "block-audit@example.com"}, identity=ADMIN)
    block_call = observability.calls[-1]
    assert block_call["blocked_before"] is False
    assert block_call["blocked_after"] is True


async def test_store_missing_is_service_unconfigured() -> None:
    adapter = UsersAdminAdapter(directory=None, role_source=_default_role_source)
    engine, registry = _registry(adapter)
    route = registry.add_route("users_list", adapter, mode="live")

    result = await engine.execute(route, {}, identity=ADMIN)

    assert result["state"] == "error"
    assert result["code"] == "service_unconfigured"


async def test_database_down_is_service_unavailable() -> None:
    engine_obj = create_users_engine(
        "postgresql+psycopg://keystone:s3cr3t@127.0.0.1:1/keystone_users"
    )
    store = UsersStore(engine_obj, revision=NullRevisionWriter())
    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=_default_role_source
    )
    engine, registry = _registry(adapter)
    route = registry.add_route("users_list", adapter, mode="live")

    try:
        result = await engine.execute(route, {}, identity=ADMIN)
    finally:
        store.dispose()

    assert result["state"] == "error"
    assert result["code"] == "service_unavailable"
    assert result["message"] == "users directory is unavailable"
    assert "s3cr3t" not in str(result)


async def test_response_shape_matches_http_branch(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    adapter = UsersAdminAdapter(
        directory=LocalUserDirectory(store), role_source=_default_role_source
    )
    engine, registry = _registry(adapter)
    route = registry.add_route("users_add", adapter, mode="live")

    result = await engine.execute(
        route,
        {"email": "shape@example.com", "full_name": "Shape", "roles": ["member"]},
        identity=ADMIN,
    )

    assert result["state"] == "done"
    assert set(result["user"].keys()) == set(USER_SUMMARY.keys())
