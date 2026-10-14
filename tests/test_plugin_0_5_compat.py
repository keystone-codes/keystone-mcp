"""The frozen 0.5 plugin must keep working until Keystone 2.0."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import ModuleType

import pytest

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.catalog.builtin import BUILTIN_TOOL_NAMES
from keystone_mcp.config import Settings
from keystone_mcp.contract_tests import (
    AdminDirectoryContract,
    ApiKeyDirectoryContract,
    FormLoginProviderContract,
    FormProviderCase,
    ServiceAccountDirectoryContract,
    seed_contract_dataset,
)
from keystone_mcp.login.factory import validate_login_providers
from keystone_mcp.login.protocol import FormLoginProvider
from keystone_mcp.server import bootstrap_rbac_policy, build_server
from keystone_mcp.user_directory.protocol import UserDirectory
from support.test_env import UNUSED_REDIS_URL

pytest_plugins = ["keystone_mcp.contract_tests"]

_PLUGIN_PATH = Path(__file__).resolve().parent / "data" / "plugin_0_5" / "keystone_plugin_0_5.py"
_PLUGIN_SHA256 = "ee360408e92ed54b8f41b9db1d1f6944bdd10dfe2f21c40707e025b4014b21e3"


def _load_plugin() -> ModuleType:
    spec = importlib.util.spec_from_file_location("keystone_plugin_0_5", _PLUGIN_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


POLICY_YAML = """\
version: "plugin-0-5"
default_deny: true
roles:
  administrator:
    description: admin
    allow: ["*"]
"""


def test_plugin_0_5_file_is_unchanged() -> None:
    digest = hashlib.sha256(_PLUGIN_PATH.read_bytes()).hexdigest()
    assert digest == _PLUGIN_SHA256


@pytest.mark.asyncio
async def test_plugin_0_5_directory_is_accepted_and_publishes_all_admin_tools(
    tmp_path: Path,
) -> None:
    plugin = _load_plugin()

    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(POLICY_YAML, encoding="utf-8")
    directory = plugin.create_directory(None, {})  # type: ignore[arg-type]
    await seed_contract_dataset(directory)

    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        deployment_profile="local",
        users_backend="memory",
        redis_url=UNUSED_REDIS_URL,
        rbac_audit_subject_salt="plugin-0-5-salt",
        policy_tools="full",
    )

    _mcp, registry, _oauth, _upstreams, policy_manager, _observability, _reconciler = build_server(
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        user_directory=directory,
    )
    bootstrap_rbac_policy(policy_manager, registry)

    published = {
        route.published_name
        for route in registry.routes.values()
        if route.namespace is None and route.admin
    }
    assert published == BUILTIN_TOOL_NAMES


def test_plugin_0_5_login_providers_are_accepted() -> None:
    plugin = _load_plugin()

    form = plugin.create_form_provider(None, None)  # type: ignore[arg-type]
    redirect = plugin.create_redirect_provider(None, None)  # type: ignore[arg-type]
    validate_login_providers([form, redirect])


@pytest.fixture
def keystone_directory_factory() -> Callable[[], Awaitable[UserDirectory]]:
    plugin = _load_plugin()

    async def factory() -> UserDirectory:
        directory = plugin.create_directory(None, {})  # type: ignore[arg-type]
        await seed_contract_dataset(directory)
        return directory

    return factory


@pytest.fixture
def keystone_unavailable_directory_factory() -> Callable[[], Awaitable[UserDirectory]]:
    plugin = _load_plugin()

    async def factory() -> UserDirectory:
        directory = plugin.create_directory(None, {})  # type: ignore[arg-type]
        directory.unavailable = True
        return directory

    return factory


class TestPlugin05DirectoryContract(
    AdminDirectoryContract, ServiceAccountDirectoryContract, ApiKeyDirectoryContract
):
    pass


@pytest.fixture
def keystone_form_provider_case() -> FormProviderCase:
    plugin = _load_plugin()

    async def factory() -> FormLoginProvider:
        return plugin.create_form_provider(None, None)  # type: ignore[arg-type]

    return FormProviderCase(
        factory=factory,
        valid_form={"email": "bob@example.com"},
        expected_email="bob@example.com",
        invalid_forms=({"email": ""},),
    )


class TestPlugin05FormContract(FormLoginProviderContract):
    pass
