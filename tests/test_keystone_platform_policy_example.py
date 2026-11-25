"""The keystone example policy loads against the live built-in catalog."""

from __future__ import annotations

import logging
from pathlib import Path

from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.rbac.policy_document import _ROLE_NAME_PATTERN
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from support.test_env import UNUSED_REDIS_URL

_EXAMPLE = (
    Path(__file__).resolve().parents[1] / "examples" / "keystone-platform" / "rbac-policy.yaml"
)


def test_keystone_platform_policy_example_loads(caplog) -> None:
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(_EXAMPLE),
        redis_url=UNUSED_REDIS_URL,
        rbac_audit_subject_salt="example-salt",
    )
    registry = RouterRegistry(RouterEngine(settings))
    register_catalog(registry, settings, directory=InMemoryUserDirectory())
    manager = RbacPolicyManager(settings)
    with caplog.at_level(logging.WARNING):
        manager.load_initial(registry)

    warnings = " ".join(record.message for record in caplog.records)
    assert "unmatched allow" not in warnings
    assert "empty allow" not in warnings
    assert "matched no tools" not in warnings

    policy = manager.policy
    for name in policy.role_names:
        assert _ROLE_NAME_PATTERN.fullmatch(name), name

    sign_in = ("keystone-superadmin", "keystone-manager", "keystone-member")
    for name in sign_in:
        role = policy.role(name)
        assert role is not None
        assert role.allow_patterns == ("whoami",)
    platform = policy.role("keystone-platform")
    assert platform is not None
    assert set(platform.allow_patterns) == {"whoami", "users_list"}
