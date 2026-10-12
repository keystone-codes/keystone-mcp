"""Contract tests for the ``UserDirectory`` protocol itself (X06).

These are not about any one implementation's behavior (``local`` and
``http`` have their own test files) -- they check the shape of the protocol:
that it is dependency-free, that the built-in implementations satisfy
``UserDirectoryAdmin``, that a misdeclared directory is refused at build
time, and that the deprecated 0.4.0 ``UserDirectoryBackend`` still works
through its compatibility wrapper.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from keystone_mcp.auth.identity_provider import StaticIdentityProvider
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import ConfigError, Settings
from keystone_mcp.server import build_server
from keystone_mcp.user_directory.factory import (
    build_user_directory_resolver,
    validate_directory_capabilities,
)
from keystone_mcp.user_directory.http import HttpUserDirectory
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectoryAdmin
from keystone_mcp.user_directory.types import UserResolveResult
from support.users_store import make_users_store


class _AdminlessDirectory:
    """A directory that lies about declaring ``"admin"`` (see below)."""

    name = "fake-admin"
    capabilities = frozenset({"admin"})

    async def resolve_user(self, subject: str) -> UserResolveResult:
        return UserResolveResult(exists=False, roles=(), is_blocked=False)

    async def list_users(self, *, is_blocked=False, role=None, email_contains=None):
        return []

    async def ping(self) -> None:
        return None

    async def aclose(self) -> None:
        return None


def test_protocol_and_types_are_dependency_free() -> None:
    """``import keystone_mcp.user_directory.protocol`` alone stays light.

    Run in a fresh subprocess with ``-I`` (isolated mode): the protocol and
    its types module are meant to be implementable by a plugin that has none
    of fastmcp, the MCP SDK, Starlette, httpx(2), SQLAlchemy, or redis
    installed at all.
    """
    code = (
        "import keystone_mcp.user_directory.protocol, "
        "keystone_mcp.user_directory.types, "
        "keystone_mcp.user_directory.errors, sys; "
        "bad=[m for m in sys.modules if m.split('.')[0] in "
        "{'fastmcp','mcp','starlette','httpx','httpx2','sqlalchemy','redis'}]; "
        "assert not bad, bad"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.asyncio
async def test_local_and_http_satisfy_admin_protocol(tmp_path: Path) -> None:
    store, _revision = await make_users_store(tmp_path)
    local = LocalUserDirectory(store)
    http = HttpUserDirectory(
        base_url="http://users.test", service_token="token", timeout_seconds=1.0
    )
    try:
        assert isinstance(local, UserDirectoryAdmin)
        assert isinstance(http, UserDirectoryAdmin)
        assert "admin" in local.capabilities
        assert "admin" in http.capabilities
    finally:
        await local.aclose()
        await http.aclose()
        store.dispose()


def test_declared_admin_without_methods_is_refused() -> None:
    with pytest.raises(ConfigError, match="declares 'admin'"):
        validate_directory_capabilities(_AdminlessDirectory())


def test_build_server_validates_an_injected_user_directory() -> None:
    """``build_server(user_directory=...)`` gets the same refusal as a

    directory ``build_user_directory`` constructs itself: an embedding
    process, a test, or a plugin that hands in a misdeclared directory does
    not silently publish broken admin tools (X06 review finding).
    """
    settings = Settings(base_url="http://localhost:8080", rbac_mode="off")
    with pytest.raises(ConfigError, match="declares 'admin'"):
        build_server(
            identity_provider=StaticIdentityProvider({"token"}),
            settings=settings,
            oauth_store=InMemoryOAuthStore(),
            user_directory=_AdminlessDirectory(),
        )


@pytest.mark.asyncio
async def test_legacy_backend_is_wrapped_with_deprecation_warning() -> None:
    class _LegacyBackend:
        """A 0.4.0-style ``UserDirectoryBackend``: one method, no admin."""

        async def resolve_user(self, email: str) -> UserResolveResult:
            return UserResolveResult(exists=True, roles=("operator",), is_blocked=False)

        async def aclose(self) -> None:
            return None

    settings = Settings(base_url="http://localhost:8080")
    with pytest.warns(DeprecationWarning, match="UserDirectoryBackend is deprecated"):
        resolver = build_user_directory_resolver(settings, backend=_LegacyBackend())

    result = await resolver.resolve("user@example.com")
    assert result.exists is True
    assert result.roles == ("operator",)
    assert resolver.backend.capabilities == frozenset()

    await resolver.aclose()


@pytest.mark.asyncio
async def test_in_memory_directory_create_user_conflicts_on_existing_email() -> None:
    """``create_user`` for an email that already exists must raise ``conflict``,

    not silently overwrite the existing entry -- matching ``LocalUserDirectory``
    and the HTTP contract's own ``user_already_exists`` normalization (X06
    review finding).
    """
    from keystone_mcp.user_directory.errors import UsersError
    from keystone_mcp.user_directory.memory import InMemoryUserDirectory

    directory = InMemoryUserDirectory()
    await directory.create_user(
        email="dup@example.com", full_name="First", roles=[], note=None, actor="admin@example.com"
    )

    with pytest.raises(UsersError) as exc_info:
        await directory.create_user(
            email="dup@example.com",
            full_name="Second",
            roles=["member"],
            note=None,
            actor="admin@example.com",
        )
    assert exc_info.value.code == "conflict"

    # The original entry is untouched.
    rows = await directory.list_users(is_blocked=None)
    assert len(rows) == 1
    assert rows[0].full_name == "First"
