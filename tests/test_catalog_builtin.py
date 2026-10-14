"""The built-in catalog registers the live admin tools."""

from __future__ import annotations

from pathlib import Path

from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from support.test_env import UNUSED_REDIS_URL


def _registry(settings: Settings | None = None) -> RouterRegistry:
    settings = settings or Settings(base_url="http://localhost:8080", rbac_mode="off")
    engine = RouterEngine(settings)
    return RouterRegistry(engine)


def _enforce_settings(tmp_path: Path) -> Settings:
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text(
        'version: "1"\ndefault_deny: true\nroles:\n  administrator:\n    allow: ["*"]\n',
        encoding="utf-8",
    )
    return Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy),
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url=UNUSED_REDIS_URL,
        rbac_audit_subject_salt="test-salt",
    )


def test_file_tools_are_gone(tmp_path: Path):
    """The file API was removed in 0.5.0: no mode publishes it, and the
    adapters that used to back it no longer exist on keystone_mcp.adapters.
    """
    import keystone_mcp.adapters as adapters_module

    for rbac_mode, settings in (
        ("off", Settings(base_url="http://localhost:8080", rbac_mode="off")),
        ("enforce", _enforce_settings(tmp_path)),
    ):
        reg = _registry(settings)
        register_catalog(reg, settings)
        assert reg.get("create_upload_url") is None, rbac_mode
        assert reg.get("get_download_link") is None, rbac_mode

    assert not hasattr(adapters_module, "UploadUrlAdapter")
    assert not hasattr(adapters_module, "FileRefAdapter")


def test_catalog_registers_users_tools_only_in_enforce(tmp_path):
    settings = _enforce_settings(tmp_path)
    reg = _registry(settings)
    register_catalog(reg, settings, directory=InMemoryUserDirectory())

    for name in (
        "users_list",
        "users_add",
    ):
        assert reg.get(name) is not None, f"{name} not registered"


def test_catalog_drops_base64_upload_file():
    """The inline-base64 upload_file tool is retired."""
    reg = _registry()
    register_catalog(reg, Settings(base_url="http://localhost:8080", rbac_mode="off"))

    assert reg.get("upload_file") is None


def test_builtin_tool_names_constant_covers_registered_tools(tmp_path: Path):
    """BUILTIN_TOOL_NAMES (used by P09 namespace validation) matches reality."""
    from keystone_mcp.catalog.builtin import BUILTIN_TOOL_NAMES
    from keystone_mcp.rbac.loader import RbacPolicyManager
    from keystone_mcp.rbac.policy_store import PolicyStore
    from keystone_mcp.server import policy_role_source
    from keystone_mcp.user_directory.local import LocalUserDirectory
    from keystone_mcp.users.factory import build_users_store

    settings = Settings(
        **_enforce_settings(tmp_path).__dict__
        | {"deployment_profile": "local", "users_backend": "local", "policy_tools": "full"},
    )
    store = build_users_store(settings)
    reg = _registry(settings)
    manager = RbacPolicyManager(settings)
    manager.load_initial(reg)
    policy_store = PolicyStore(
        settings=settings,
        policy_manager=manager,
        registry=reg,
        directory=LocalUserDirectory(store),
    )
    register_catalog(
        reg,
        settings,
        directory=LocalUserDirectory(store),
        role_source=policy_role_source(manager),
        policy_store=policy_store,
    )
    manager.reload(reg)

    registered = {route.name for route in reg.routes.values() if route.namespace is None}
    assert registered == BUILTIN_TOOL_NAMES
    store.dispose()


def test_policy_tools_registered_by_mode(tmp_path: Path):
    from keystone_mcp.rbac.loader import RbacPolicyManager
    from keystone_mcp.rbac.policy_store import PolicyStore

    settings = _enforce_settings(tmp_path)
    reg = _registry(settings)
    manager = RbacPolicyManager(settings)
    manager.load_initial(reg)
    policy_store = PolicyStore(
        settings=settings,
        policy_manager=manager,
        registry=reg,
        directory=InMemoryUserDirectory(),
    )
    register_catalog(reg, settings, directory=InMemoryUserDirectory(), policy_store=policy_store)
    full_names = {route.name for route in reg.routes.values() if route.name.startswith("policy_")}
    assert full_names == {
        "policy_read",
        "policy_catalog",
        "policy_validate",
        "policy_role_set",
        "policy_role_delete",
        "policy_allow_add",
        "policy_allow_remove",
        "policy_list_set",
        "policy_rollback",
    }

    read_only_settings = Settings(**{**settings.__dict__, "policy_tools": "read-only"})
    reg_ro = _registry(read_only_settings)
    manager_ro = RbacPolicyManager(read_only_settings)
    manager_ro.load_initial(reg_ro)
    store_ro = PolicyStore(
        settings=read_only_settings,
        policy_manager=manager_ro,
        registry=reg_ro,
        directory=InMemoryUserDirectory(),
    )
    register_catalog(
        reg_ro,
        read_only_settings,
        directory=InMemoryUserDirectory(),
        policy_store=store_ro,
    )
    ro_names = {route.name for route in reg_ro.routes.values() if route.name.startswith("policy_")}
    assert ro_names == {"policy_read", "policy_catalog", "policy_validate"}


class _ReadOnlyDirectory:
    """A directory that declares no capabilities: ``users_list`` only."""

    name = "read-only-fake"
    capabilities: frozenset[str] = frozenset()

    async def resolve_user(self, subject):  # pragma: no cover - not exercised
        raise NotImplementedError

    async def list_users(self, *, is_blocked=False, role=None, email_contains=None):
        return []

    async def ping(self) -> None:
        return None

    async def aclose(self) -> None:
        return None


def test_read_only_directory_publishes_only_users_list(tmp_path, caplog):
    settings = _enforce_settings(tmp_path)
    reg = _registry(settings)
    with caplog.at_level("WARNING", logger="keystone_mcp.catalog.builtin"):
        register_catalog(reg, settings, directory=_ReadOnlyDirectory())

    assert reg.get("users_list") is not None
    assert reg.get("users_export") is not None
    for name in (
        "users_add",
        "users_update",
        "users_block",
        "users_unblock",
        "users_set_roles",
        "users_grant_role",
        "users_revoke_role",
        "users_delete",
    ):
        assert reg.get(name) is None, name
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert any("read-only" in message for message in warnings)


def test_admin_directory_publishes_all_users_tools(tmp_path):
    settings = _enforce_settings(tmp_path)
    reg = _registry(settings)
    register_catalog(reg, settings, directory=InMemoryUserDirectory())

    for name in (
        "users_list",
        "users_export",
        "users_add",
        "users_update",
        "users_block",
        "users_unblock",
        "users_set_roles",
        "users_grant_role",
        "users_revoke_role",
        "users_delete",
    ):
        route = reg.get(name)
        assert route is not None, name
        assert route.mode == "live"
        assert route.admin is True


def test_users_delete_not_published_without_delete_capability(tmp_path):
    settings = _enforce_settings(tmp_path)

    class _AdminOnly:
        name = "admin-only"
        capabilities = frozenset({"admin"})

        async def resolve_user(self, subject):  # pragma: no cover
            raise NotImplementedError

        async def list_users(self, *, is_blocked=False, role=None, email_contains=None):
            return []

        async def ping(self) -> None:
            return None

        async def aclose(self) -> None:
            return None

    reg = _registry(settings)
    register_catalog(reg, settings, directory=_AdminOnly())
    assert reg.get("users_delete") is None
