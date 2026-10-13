"""service_accounts_* tools wiring and audit."""

from __future__ import annotations

from pathlib import Path

from keystone_mcp.adapters.service_accounts_admin import ServiceAccountsAdminAdapter
from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory.http import HttpUserDirectory
from keystone_mcp.users.revision import NullRevisionWriter
from support.users_store import make_users_store

ADMIN = VerifiedIdentity(email="admin@example.com")


def _settings(tmp_path: Path) -> Settings:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        'default_deny: true\nroles:\n  member: {allow: ["*"]}\n  robot: {allow: ["*"]}\n',
        encoding="utf-8",
    )
    return Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy),
        rbac_audit_enabled=True,
        users_backend="local",
        users_db_url=f"sqlite:///{tmp_path}/keystone-users.db",
    )


async def test_tools_registered_with_service_accounts_capability(tmp_path: Path, caplog):
    settings = _settings(tmp_path)
    store, _ = await make_users_store(tmp_path, revision=NullRevisionWriter())
    from keystone_mcp.user_directory.local import LocalUserDirectory

    directory = LocalUserDirectory(store)
    reg = RouterRegistry(RouterEngine(settings))
    register_catalog(reg, settings, directory=directory)
    names = {route.name for route in reg.routes.values()}
    assert {"service_accounts_list", "service_accounts_add", "service_accounts_update"} <= names


async def test_http_directory_does_not_publish_service_tools(tmp_path: Path):
    settings = _settings(tmp_path)
    directory = HttpUserDirectory(
        base_url="http://users:8000",
        service_token="token",
        timeout_seconds=1.0,
    )
    reg = RouterRegistry(RouterEngine(settings))
    register_catalog(reg, settings, directory=directory)
    assert reg.get("service_accounts_list") is None


async def test_unknown_role_is_validation_error(tmp_path: Path):
    settings = _settings(tmp_path)
    store, _ = await make_users_store(tmp_path, revision=NullRevisionWriter())
    from keystone_mcp.user_directory.local import LocalUserDirectory

    directory = LocalUserDirectory(store)
    adapter = ServiceAccountsAdminAdapter(
        directory=directory,
        role_source=lambda: frozenset({"member"}),
    )
    reg = RouterRegistry(RouterEngine(settings))
    route = reg.add_route("service_accounts_add", adapter, mode="live", params=[])
    ctx = type("Ctx", (), {"verified_identity": ADMIN, "task_id": "t1"})()
    out = await adapter.execute(route, ctx, {"name": "ci", "roles": ["nope"]})
    assert out["code"] == "validation_error"
