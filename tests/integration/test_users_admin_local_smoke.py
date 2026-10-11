"""End-to-end smoke test for the users_* tools against the built-in directory.

Replaces the old ``test_users_admin_mcp_users_smoke.py``, which drove a live
external ``mcp-users`` service that is no longer published. This test wires
``register_catalog`` the way ``keystone_mcp.server.build_server`` does —
against a real (migrated) ``UsersStore`` — and drives the ``users_*`` tools
through ``RouterEngine.execute`` directly, the same way the legacy
standalone directory's ``tests/integration/test_api_lifecycle.py::
test_full_user_lifecycle_and_revision_bumps`` exercised its own HTTP API.

Parametrized over SQLite (always) and PostgreSQL (when
``KEYSTONE_TEST_POSTGRES_URL`` is set) via the shared ``users_engine``
fixture.
"""

from __future__ import annotations

from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory.revision import InMemoryRevisionReader
from keystone_mcp.users.revision import InProcessRevisionWriter
from keystone_mcp.users.store import UsersStore
from support.users_db import users_engine  # noqa: F401 -- fixture import

ADMIN = VerifiedIdentity(email="admin@example.com")

ROLES = frozenset({"administrator", "member"})


def _role_source() -> frozenset[str]:
    return ROLES


def _build_stack(
    users_engine,  # noqa: ANN001, F811
) -> tuple[RouterEngine, RouterRegistry, UsersStore, InMemoryRevisionReader]:
    settings = Settings(
        base_url="http://localhost:8080", users_backend="local", rbac_mode="enforce"
    )
    revision = InMemoryRevisionReader()
    store = UsersStore(users_engine, revision=InProcessRevisionWriter(revision.bump))
    engine = RouterEngine(settings)
    registry = RouterRegistry(engine)
    register_catalog(registry, settings, users_store=store, role_source=_role_source)
    return engine, registry, store, revision


async def test_full_user_lifecycle_and_revision_bumps(users_engine) -> None:  # noqa: ANN001, F811
    engine, registry, store, revision = _build_stack(users_engine)

    add_route = registry.get("users_add")
    update_route = registry.get("users_update")
    grant_route = registry.get("users_grant_role")
    set_roles_route = registry.get("users_set_roles")
    revoke_route = registry.get("users_revoke_role")
    block_route = registry.get("users_block")
    unblock_route = registry.get("users_unblock")
    resolve_route = registry.get("users_list")
    assert all(
        route is not None
        for route in (
            add_route,
            update_route,
            grant_route,
            set_roles_route,
            revoke_route,
            block_route,
            unblock_route,
            resolve_route,
        )
    )

    # An anchor administrator distinct from the lifecycle user: granting and
    # then revoking "administrator" on the lifecycle user below would
    # otherwise make it the directory's sole administrator and trip the
    # last-administrator guard on revoke/set_roles (U01/U02 invariant).
    await store.create_user(
        email="anchor-admin@example.com",
        full_name="Anchor Admin",
        roles=["administrator"],
        note=None,
        created_by=None,
        allowed_roles=None,
    )

    before = await revision.current()

    created = await engine.execute(
        add_route,
        {"email": "lifecycle@example.com", "full_name": "Lifecycle", "roles": ["member"]},
        identity=ADMIN,
    )
    assert created["state"] == "done"
    assert created["user"]["roles"] == ["member"]
    after_create = await revision.current()
    assert after_create > before

    updated = await engine.execute(
        update_route,
        {"email": "lifecycle@example.com", "full_name": "Lifecycle Renamed"},
        identity=ADMIN,
    )
    assert updated["state"] == "done"
    assert updated["user"]["full_name"] == "Lifecycle Renamed"
    after_update = await revision.current()
    assert after_update > after_create

    granted = await engine.execute(
        grant_route,
        {"email": "lifecycle@example.com", "role": "administrator"},
        identity=ADMIN,
    )
    assert granted["state"] == "done"
    assert set(granted["user"]["roles"]) == {"administrator", "member"}

    replaced = await engine.execute(
        set_roles_route,
        {"email": "lifecycle@example.com", "roles": ["member"]},
        identity=ADMIN,
    )
    assert replaced["state"] == "done"
    assert replaced["user"]["roles"] == ["member"]

    revoked = await engine.execute(
        revoke_route,
        {"email": "lifecycle@example.com", "role": "member"},
        identity=ADMIN,
    )
    assert revoked["state"] == "done"
    assert revoked["user"]["roles"] == []

    blocked = await engine.execute(block_route, {"email": "lifecycle@example.com"}, identity=ADMIN)
    assert blocked["state"] == "done"
    assert blocked["user"]["is_blocked"] is True

    resolved = await store.resolve("lifecycle@example.com")
    assert resolved.is_blocked is True

    unblocked = await engine.execute(
        unblock_route, {"email": "lifecycle@example.com"}, identity=ADMIN
    )
    assert unblocked["state"] == "done"
    assert unblocked["user"]["is_blocked"] is False


async def test_blocking_the_sole_administrator_is_last_administrator(users_engine) -> None:  # noqa: ANN001, F811
    engine, registry, _store, _revision = _build_stack(users_engine)
    add_route = registry.get("users_add")
    block_route = registry.get("users_block")

    created = await engine.execute(
        add_route,
        {
            "email": "sole-admin@example.com",
            "full_name": "Sole Admin",
            "roles": ["administrator"],
        },
        identity=ADMIN,
    )
    assert created["state"] == "done"

    result = await engine.execute(block_route, {"email": "sole-admin@example.com"}, identity=ADMIN)
    assert result["state"] == "error"
    assert result["code"] == "last_administrator"


async def test_list_defaults_to_non_blocked(users_engine) -> None:  # noqa: ANN001, F811
    engine, registry, _store, _revision = _build_stack(users_engine)
    add_route = registry.get("users_add")
    block_route = registry.get("users_block")
    list_route = registry.get("users_list")

    await engine.execute(
        add_route,
        {"email": "active@example.com", "full_name": "Active", "roles": []},
        identity=ADMIN,
    )
    await engine.execute(
        add_route,
        {
            "email": "other-admin@example.com",
            "full_name": "Other Admin",
            "roles": ["administrator"],
        },
        identity=ADMIN,
    )
    await engine.execute(
        add_route,
        {"email": "to-block@example.com", "full_name": "To Block", "roles": []},
        identity=ADMIN,
    )
    await engine.execute(block_route, {"email": "to-block@example.com"}, identity=ADMIN)

    default_listing = await engine.execute(list_route, {}, identity=ADMIN)
    assert default_listing["state"] == "done"
    default_emails = {u["email"] for u in default_listing["users"]}
    assert "active@example.com" in default_emails
    assert "to-block@example.com" not in default_emails

    blocked_listing = await engine.execute(list_route, {"is_blocked": True}, identity=ADMIN)
    assert blocked_listing["state"] == "done"
    blocked_emails = {u["email"] for u in blocked_listing["users"]}
    assert blocked_emails == {"to-block@example.com"}
