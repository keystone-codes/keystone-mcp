"""The built-in catalog registers the live admin tools."""

from __future__ import annotations

from pathlib import Path

from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry


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


def test_builtin_descriptions_have_no_legacy_terms(tmp_path: Path):
    """Tool descriptions and parameter names carry no internal platform labels."""
    settings = _enforce_settings(tmp_path)
    reg = _registry(settings)
    register_catalog(reg, settings)

    forbidden = (
        "K3",
        "K4",
        "Excel",
        "xlsx",
        "intended_project_id",
        "S2S",
        "mcp-users",
    )
    for route in reg.routes.values():
        haystack = " ".join([route.description or "", *(p.name for p in route.params)])
        for term in forbidden:
            assert term not in haystack, f"{route.name!r} description/params contain {term!r}"


def test_catalog_registers_users_tools_only_in_enforce(tmp_path):
    settings = _enforce_settings(tmp_path)
    reg = _registry(settings)
    register_catalog(reg, settings)

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
    register_catalog(reg, settings)

    registered = {route.name for route in reg.routes.values() if route.namespace is None}
    assert registered == BUILTIN_TOOL_NAMES
