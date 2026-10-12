"""Entry-point plugin discovery and wiring."""

from __future__ import annotations

import importlib.metadata
import importlib.util
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from keystone_mcp.config import ConfigError, Settings
from keystone_mcp.login.factory import build_login_providers
from keystone_mcp.plugins import (
    LOGIN_PROVIDERS_GROUP,
    USER_DIRECTORIES_GROUP,
    PluginConflictError,
    PluginContext,
    _reset_cache,
    discover,
    keystone_distribution,
    load_factory,
)
from keystone_mcp.user_directory.factory import build_user_directory

_SUPPORT = Path(__file__).resolve().parent / "support"


def _load_support_module(filename: str, module_name: str):
    path = _SUPPORT / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _clear_plugin_cache() -> None:
    _reset_cache()
    yield
    _reset_cache()


def test_builtin_entry_points_are_registered() -> None:
    ks = keystone_distribution()
    login = discover(LOGIN_PROVIDERS_GROUP)
    directories = discover(USER_DIRECTORIES_GROUP)
    for name in ("oidc", "google", "api_key"):
        assert name in login, "run `uv sync`"
        assert login[name].dist is not None
        assert login[name].dist.metadata["Name"] == ks
    for name in ("local", "http"):
        assert name in directories, "run `uv sync`"
        assert directories[name].dist.metadata["Name"] == ks


def test_two_distributions_providing_module_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(
        importlib.metadata,
        "packages_distributions",
        lambda: {"keystone_mcp": ["keystone-mcp-gateway", "other-pkg"]},
    )
    with pytest.raises(ConfigError, match="several distributions"):
        keystone_distribution()


def test_unknown_login_type_lists_available() -> None:
    with pytest.raises(ConfigError, match="available:") as exc:
        load_factory(LOGIN_PROVIDERS_GROUP, "no-such-login")
    assert "uv sync" in str(exc.value)


def test_unknown_users_backend_lists_available() -> None:
    with pytest.raises(ConfigError, match="available:") as exc:
        load_factory(USER_DIRECTORIES_GROUP, "no-such-backend")
    assert "uv sync" in str(exc.value)


def _fake_dist(name: str, version: str = "1.0.0") -> SimpleNamespace:
    return SimpleNamespace(metadata={"Name": name, "Version": version}, version=version)


class _FakeEntryPoint:
    def __init__(self, name: str, value: str, group: str, dist: SimpleNamespace) -> None:
        self.name = name
        self.value = value
        self.group = group
        self.dist = dist

    def load(self) -> object:
        raise ImportError("simulated import failure")


def test_conflicting_names_are_refused(monkeypatch) -> None:
    ep_a = _FakeEntryPoint("acme", "mod:a", LOGIN_PROVIDERS_GROUP, _fake_dist("pkg-a"))
    ep_b = _FakeEntryPoint("acme", "mod:b", LOGIN_PROVIDERS_GROUP, _fake_dist("pkg-b"))

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda *, group: [ep_a, ep_b] if group == LOGIN_PROVIDERS_GROUP else [],
    )
    monkeypatch.setattr(
        "keystone_mcp.plugins.keystone_distribution",
        lambda: "keystone-mcp-gateway",
    )
    with pytest.raises(PluginConflictError, match="pkg-a"):
        discover(LOGIN_PROVIDERS_GROUP)


def test_builtin_name_from_foreign_distribution_is_refused(monkeypatch) -> None:
    ep = _FakeEntryPoint("oidc", "evil:factory", LOGIN_PROVIDERS_GROUP, _fake_dist("evil-pkg"))

    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda *, group: [ep] if group == LOGIN_PROVIDERS_GROUP else [],
    )
    monkeypatch.setattr(
        "keystone_mcp.plugins.keystone_distribution",
        lambda: "keystone-mcp-gateway",
    )
    with pytest.raises(PluginConflictError, match="reserved"):
        discover(LOGIN_PROVIDERS_GROUP)


def test_import_error_is_reported_with_distribution(monkeypatch) -> None:
    ep = _FakeEntryPoint(
        "broken",
        "definitely_missing_module_xyz:factory",
        LOGIN_PROVIDERS_GROUP,
        _fake_dist("broken-pkg", "9.9.9"),
    )

    monkeypatch.setattr(
        "keystone_mcp.plugins.discover",
        lambda group: {"broken": ep},
    )
    with pytest.raises(ConfigError, match="broken-pkg") as exc:
        load_factory(LOGIN_PROVIDERS_GROUP, "broken")
    assert "failed to import" in str(exc.value)


def test_plugin_login_provider_from_file(tmp_path, monkeypatch) -> None:
    create_acme_login_provider = _load_support_module(
        "fake_login.py", "keystone_test_fake_login"
    ).create_acme_login_provider

    real_load = load_factory

    def patched_load(group: str, name: str):
        if group == LOGIN_PROVIDERS_GROUP and name == "acme":
            return create_acme_login_provider
        return real_load(group, name)

    bare_discover = discover.__wrapped__

    def patched_discover(group: str):
        if group == LOGIN_PROVIDERS_GROUP:
            merged = dict(bare_discover(group))
            merged["acme"] = SimpleNamespace(name="acme", value="tests:acme", dist=None)
            return merged
        return bare_discover(group)

    monkeypatch.setattr("keystone_mcp.login.factory.load_factory", patched_load)
    monkeypatch.setattr("keystone_mcp.login.factory.discover", patched_discover)
    path = tmp_path / "providers.yaml"
    path.write_text(
        textwrap.dedent(
            """
            version: 1
            providers:
              - name: acme
                type: acme
                title: Acme SSO
            """
        ),
        encoding="utf-8",
    )
    settings = Settings(login_providers_path=str(path))
    providers = build_login_providers(settings, resolver=None)
    assert providers[0].name == "acme"
    assert providers[0].title == "Acme SSO"


@pytest.mark.asyncio
async def test_plugin_directory_receives_options(tmp_path, monkeypatch) -> None:
    create_memory_test_directory = _load_support_module(
        "plugin_directory.py", "keystone_test_plugin_directory"
    ).create_memory_test_directory

    real_load = load_factory

    def patched_load(group: str, name: str):
        if group == USER_DIRECTORIES_GROUP and name == "memory-test":
            return create_memory_test_directory
        return real_load(group, name)

    bare_discover = discover.__wrapped__

    def patched_discover(group: str):
        if group == USER_DIRECTORIES_GROUP:
            merged = dict(bare_discover(group))
            merged["memory-test"] = SimpleNamespace(
                name="memory-test", value="tests:memory", dist=None
            )
            return merged
        return bare_discover(group)

    monkeypatch.setattr("keystone_mcp.user_directory.factory.load_factory", patched_load)
    monkeypatch.setattr("keystone_mcp.user_directory.factory.discover", patched_discover)
    config_path = tmp_path / "backend.yaml"
    config_path.write_text(
        "seed:\n  - email: user@example.com\n    roles: [viewer]\n",
        encoding="utf-8",
    )
    settings = Settings(
        users_backend="memory-test",
        users_backend_config=str(config_path),
    )
    directory = build_user_directory(settings)
    result = await directory.resolve_user("user@example.com")
    assert result.exists
    assert "viewer" in result.roles


def test_backend_config_with_secret_key_is_refused(tmp_path) -> None:
    from keystone_mcp.user_directory.backend_config import load_users_backend_config

    path = tmp_path / "backend.yaml"
    path.write_text("token: embedded\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="context.secret"):
        load_users_backend_config(str(path))


def test_context_secret_names_missing_variable_without_value() -> None:
    ctx = PluginContext(
        base_url="http://localhost:8080",
        deployment_profile="local",
        http_timeout_seconds=10.0,
        settings=Settings(),
    )
    with pytest.raises(ConfigError, match="KEYSTONE_MCP_MISSING_FOR_TEST"):
        ctx.secret("KEYSTONE_MCP_MISSING_FOR_TEST")
