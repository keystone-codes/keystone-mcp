"""Built-in api_keys_* admin tools."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from keystone_mcp.users import service
from keystone_mcp.users.db import make_session_factory, session_scope
from support.test_env import require_redis_url
from support.users_store import make_users_store

ADMIN = VerifiedIdentity(email="admin@example.com")


def _enforce_settings(tmp_path: Path) -> Settings:
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text(
        'version: "api-keys-tools"\ndefault_deny: true\nroles:\n  administrator:\n    allow: ["*"]\n',
        encoding="utf-8",
    )
    return Settings(
        base_url="http://localhost:8080",
        deployment_profile="local",
        rbac_mode="enforce",
        rbac_policy_path=str(policy),
        redis_url=require_redis_url(),
        rbac_audit_subject_salt="tools-test",
        users_backend="local",
    )


@pytest.mark.asyncio
async def test_api_keys_tools_registered_for_capable_directory(tmp_path: Path) -> None:
    settings = _enforce_settings(tmp_path)
    store, _ = await make_users_store(tmp_path)
    directory = LocalUserDirectory(store)
    reg = RouterRegistry(RouterEngine(settings))
    register_catalog(reg, settings, directory=directory)
    for name in ("api_keys_issue", "api_keys_list", "api_keys_revoke"):
        assert reg.get(name) is not None
    store.dispose()


def test_api_keys_tools_omitted_without_capability(tmp_path: Path) -> None:
    settings = _enforce_settings(tmp_path)
    reg = RouterRegistry(RouterEngine(settings))
    register_catalog(reg, settings, directory=InMemoryUserDirectory())
    assert reg.get("api_keys_issue") is None
    assert reg.get("api_keys_list") is None
    assert reg.get("api_keys_revoke") is None


@pytest.mark.asyncio
async def test_issue_response_includes_notice_and_audit_has_no_secret(tmp_path: Path) -> None:
    settings = _enforce_settings(tmp_path)
    store, _ = await make_users_store(tmp_path)
    await store.create_user(
        email="admin@example.com",
        full_name="Admin",
        roles=["administrator"],
        note=None,
        created_by="system:test",
        allowed_roles=None,
    )
    directory = LocalUserDirectory(store)
    factory = make_session_factory(store._engine)  # noqa: SLF001
    with session_scope(factory) as session:
        service.create_service_account(
            session,
            name="bot",
            description=None,
            roles=["member"],
            created_by="test",
        )

    observability = MagicMock()
    reg = RouterRegistry(RouterEngine(settings))
    register_catalog(reg, settings, directory=directory, observability=observability)
    route = reg.get("api_keys_issue")
    assert route is not None
    engine = RouterEngine(settings)
    result = await engine.execute(
        route,
        {"subject": "svc:bot", "expires_in_days": 30},
        identity=ADMIN,
    )
    assert result["state"] == "done"
    assert result["notice"] == "Store this key now; it cannot be shown again."
    secret = result["api_key"]["key"]
    observability.record_users_mutation.assert_called()
    audit_kwargs = observability.record_users_mutation.call_args.kwargs
    assert secret not in json.dumps(audit_kwargs)
    store.dispose()
