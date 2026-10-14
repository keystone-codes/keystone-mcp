"""Guardrails for test isolation from developer shell env and hardcoded Redis."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from keystone_mcp.config import Settings
from support.test_env import ALLOWED_SHELL_KEYSTONE_MCP_VARS, RUN_KEY_ROOT, real_redis_url


def test_redis_is_configured_in_ci() -> None:
    if os.environ.get("CI") == "true" and not real_redis_url():
        pytest.fail("Redis tests must run in CI")
    if not real_redis_url():
        pytest.skip("KEYSTONE_MCP_REDIS_URL is not set outside CI")


def test_shell_environment_does_not_leak() -> None:
    present = {k for k in os.environ if k.startswith("KEYSTONE_MCP_")}
    assert present <= ALLOWED_SHELL_KEYSTONE_MCP_VARS, (
        f"unexpected KEYSTONE_MCP_* in test env: {sorted(present - ALLOWED_SHELL_KEYSTONE_MCP_VARS)}"
    )
    assert Settings().rbac_mode == "off"


_HARDCODED_REDIS = re.compile(r"redis://(localhost|127\.0\.0\.1)")


def test_no_hardcoded_redis_urls_in_tests() -> None:
    tests_root = Path(__file__).resolve().parent
    hits: list[str] = []
    for path in sorted(tests_root.rglob("*.py")):
        if path.name == "test_test_isolation.py":
            continue
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if _HARDCODED_REDIS.search(line):
                hits.append(f"{path.relative_to(tests_root.parent)}:{lineno}")
    assert not hits, "hardcoded redis URLs in tests:\n" + "\n".join(hits)


def test_run_prefix_is_applied() -> None:
    settings = Settings()
    assert settings.redis_key_prefix.startswith("km:test:")
    assert settings.login_pending_key_prefix.startswith("km:test:")
    assert settings.users_redis_revision_key.startswith("km:test:")
    assert settings.redis_key_prefix.startswith(RUN_KEY_ROOT)
