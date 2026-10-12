"""The built-in catalog registers the live admin tools."""

from __future__ import annotations

from pathlib import Path

from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory.memory import InMemoryUserDirectory


def _registry(settings: Settings | None = None) -> RouterRegistry:
    settings = settings or Settings(base_url="http://localhost:8080", rbac_mode="off")
    engine = RouterEngine(settings)
    return RouterRegistry(engine)


def _enforce_settings(tmp_path: Path) -> Settings:
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    return Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy),
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url="redis://localhost:6379/0",
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

    settings = _enforce_settings(tmp_path)
    reg = _registry(settings)
    register_catalog(reg, settings, directory=InMemoryUserDirectory())

    registered = {route.name for route in reg.routes.values() if route.namespace is None}
    assert registered == BUILTIN_TOOL_NAMES


class _ReadOnlyDirectory:
    """A directory that declares no capabilities (X06): ``users_list`` only."""

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
    for name in (
        "users_add",
        "users_update",
        "users_block",
        "users_unblock",
        "users_set_roles",
        "users_grant_role",
        "users_revoke_role",
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
        "users_add",
        "users_update",
        "users_block",
        "users_unblock",
        "users_set_roles",
        "users_grant_role",
        "users_revoke_role",
    ):
        route = reg.get(name)
        assert route is not None, name
        assert route.mode == "live"
        assert route.admin is True
