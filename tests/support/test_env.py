"""Test-run isolation: Redis key prefixes, env scrubbing helpers, and guards."""

from __future__ import annotations

import os
import uuid

import pytest

_worker = os.environ.get("PYTEST_XDIST_WORKER", "")
_worker_suffix = f"-{_worker}" if _worker else ""
RUN_ID: str = f"{uuid.uuid4().hex[:12]}{_worker_suffix}"
RUN_KEY_ROOT: str = f"km:test:{RUN_ID}:"

_SESSION_REDIS_URL: str = os.environ.get("KEYSTONE_MCP_REDIS_URL", "")

UNUSED_REDIS_URL = "redis://redis-not-used.invalid:6379/0"

# ``KEYSTONE_MCP_*`` names that may remain in ``os.environ`` during a test after
# ``_isolated_keystone_env`` (plus ``KEYSTONE_MCP_REDIS_URL``, which is kept
# from the developer shell / CI and is not set by the autouse fixture).
ALLOWED_SHELL_KEYSTONE_MCP_VARS: frozenset[str] = frozenset(
    {
        "KEYSTONE_MCP_REDIS_URL",
        "KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP",
        "KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE",
        "KEYSTONE_MCP_DEPLOYMENT_PROFILE",
        "KEYSTONE_MCP_USERS_DB_URL",
        "KEYSTONE_MCP_ENV_FILE",
        "KEYSTONE_MCP_REDIS_KEY_PREFIX",
        "KEYSTONE_MCP_LOGIN_PENDING_KEY_PREFIX",
        "KEYSTONE_MCP_USERS_REDIS_REVISION_KEY",
    }
)


def redis_key_prefix(kind: str) -> str:
    return f"{RUN_KEY_ROOT}{kind}:"


def users_revision_key(kind: str = "users") -> str:
    return f"{RUN_KEY_ROOT}{kind}:revision"


def real_redis_url() -> str | None:
    url = _SESSION_REDIS_URL.strip()
    return url or None


def require_redis_url() -> str:
    url = real_redis_url()
    if url:
        return url
    if os.environ.get("CI") == "true":
        pytest.fail(
            "KEYSTONE_MCP_REDIS_URL must be set in CI; Redis-backed tests must not be skipped"
        )
    pytest.skip("KEYSTONE_MCP_REDIS_URL is not set")


@pytest.fixture
def redis_url() -> str:
    return require_redis_url()
