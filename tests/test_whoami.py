"""Built-in whoami: the caller, never an administration tool."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext

from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.catalog.names import BUILTIN_TOOL_NAMES
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.rbac.management import ADMIN_TOOL_NAMES, is_full_administrator
from keystone_mcp.rbac.policy import parse_policy_yaml
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.rbac_middleware import RbacMiddleware
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory import is_critical_tool
from keystone_mcp.user_directory.errors import UsersStoreUnavailableError
from keystone_mcp.user_directory.factory import build_in_memory_user_directory_resolver
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from support.test_env import UNUSED_REDIS_URL


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {"base_url": "http://localhost:8080", "rbac_mode": "off"}
    base.update(overrides)
    return Settings(**base)


def _registry(settings: Settings) -> tuple[RouterEngine, RouterRegistry]:
    engine = RouterEngine(settings)
    return engine, RouterRegistry(engine)


async def _person(directory: InMemoryUserDirectory) -> None:
    await directory.create_user(
        email="anna@example.com",
        full_name="Anna Ivanova",
        roles=["keystone-member", "mcp-analyst"],
        note=None,
        actor="ops@example.com",
    )


async def _call(directory: InMemoryUserDirectory, identity: VerifiedIdentity) -> dict:
    settings = _settings()
    engine, registry = _registry(settings)
    register_catalog(registry, settings, directory=directory)
    result = await engine.execute(registry.get("whoami"), {}, identity)
    assert isinstance(result, dict)
    return result


async def test_whoami_returns_person() -> None:
    directory = InMemoryUserDirectory()
    await _person(directory)
    result = await _call(
        directory,
        VerifiedIdentity(email="anna@example.com", client_id="keystone-web"),
    )
    assert result["state"] == "done"
    assert result["tool"] == "whoami"
    assert result["sub"] == "anna@example.com"
    assert result["subject_type"] == "human"
    assert result["email"] == "anna@example.com"
    assert result["full_name"] == "Anna Ivanova"
    assert result["roles"] == ["keystone-member", "mcp-analyst"]
    assert result["client_id"] == "keystone-web"
    assert result["task_id"]


async def test_whoami_returns_service_account() -> None:
    directory = InMemoryUserDirectory()
    await directory.create_service_account(
        name="keystone",
        description="platform",
        roles=["keystone-platform"],
        actor="ops@example.com",
    )
    result = await _call(
        directory,
        VerifiedIdentity(subject="svc:keystone", client_id="keystone-web"),
    )
    assert result["state"] == "done"
    assert result["sub"] == "svc:keystone"
    assert result["subject_type"] == "service"
    assert result["email"] is None
    assert result["full_name"] is None
    assert result["roles"] == ["keystone-platform"]
    assert result["client_id"] == "keystone-web"


async def test_whoami_refuses_blocked_user() -> None:
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    await _person(backend)
    cached = await resolver.resolve("anna@example.com")
    assert cached.is_allow_decision
    backend.block("anna@example.com")
    still_cached = await resolver.resolve("anna@example.com")
    assert still_cached.from_cache is True
    assert still_cached.is_blocked is False

    result = await _call(
        backend,
        VerifiedIdentity(email="anna@example.com", client_id="keystone-web"),
    )
    assert result["state"] == "error"
    assert result["code"] == "forbidden"
    assert result["message"] == "account is blocked"


async def test_whoami_unknown_subject() -> None:
    result = await _call(
        InMemoryUserDirectory(),
        VerifiedIdentity(email="missing@example.com", client_id="keystone-web"),
    )
    assert result["state"] == "error"
    assert result["code"] == "user_not_found"


async def test_whoami_directory_down() -> None:
    class _Down:
        name = "down"
        capabilities = frozenset()

        async def resolve_user(self, subject: str):
            raise UsersStoreUnavailableError("password=secret host=10.1.2.3")

        async def list_users(self, **kwargs):
            return []

        async def ping(self) -> None:
            return None

        async def aclose(self) -> None:
            return None

    result = await _call(
        _Down(),  # type: ignore[arg-type]
        VerifiedIdentity(email="anna@example.com", client_id="keystone-web"),
    )
    assert result["code"] == "service_unavailable"
    assert result["message"] == "users directory is unavailable"
    assert "secret" not in result["message"]
    assert "10.1.2.3" not in result["message"]


@pytest.mark.parametrize("mode", ["off", "observe", "enforce"])
def test_whoami_published_in_every_rbac_mode(mode: str) -> None:
    settings = _settings(rbac_mode=mode, redis_url=UNUSED_REDIS_URL)
    _engine, registry = _registry(settings)
    register_catalog(registry, settings, directory=InMemoryUserDirectory())
    route = registry.get("whoami")
    assert route is not None

    _engine_without, without = _registry(settings)
    register_catalog(without, settings, directory=None)
    assert without.get("whoami") is None


def test_whoami_is_not_critical() -> None:
    assert is_critical_tool("whoami") is False


def test_whoami_is_not_admin() -> None:
    assert "whoami" not in BUILTIN_TOOL_NAMES
    assert "whoami" not in ADMIN_TOOL_NAMES

    settings = _settings(rbac_mode="enforce", redis_url=UNUSED_REDIS_URL)
    _engine, registry = _registry(settings)
    register_catalog(registry, settings, directory=InMemoryUserDirectory())
    route = registry.get("whoami")
    assert route is not None
    assert route.admin is False

    listed = "\n".join(f"      - {name}" for name in sorted(BUILTIN_TOOL_NAMES))
    policy = parse_policy_yaml(
        f'version: "1"\ndefault_deny: true\nroles:\n  operator:\n    allow:\n{listed}\n'
    )
    assert is_full_administrator(policy, ["operator"]) is True


async def test_role_with_only_whoami_cannot_call_other_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_path = tmp_path / "rbac-policy.yaml"
    policy_path.write_text(
        'version: "2.0.0"\ndefault_deny: true\nroles:\n  keystone-member:\n    allow: [whoami]\n',
        encoding="utf-8",
    )
    settings = _settings(
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path),
        redis_url=UNUSED_REDIS_URL,
        rbac_audit_subject_salt="whoami-salt",
    )
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    await backend.create_user(
        email="anna@example.com",
        full_name="Anna Ivanova",
        roles=["keystone-member"],
        note=None,
        actor="ops@example.com",
    )
    identity = VerifiedIdentity(email="anna@example.com", client_id="keystone-web")
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: identity,
    )
    engine, registry = _registry(settings)
    register_catalog(registry, settings, directory=backend)
    manager = RbacPolicyManager(settings)
    manager.load_initial(registry)
    middleware = RbacMiddleware(manager, resolver, enforce=True)

    async def _call_whoami(_context):
        return await engine.execute(registry.get("whoami"), {}, identity)

    allowed = await middleware.on_call_tool(
        MiddlewareContext(message=type("Msg", (), {"name": "whoami"})()),
        _call_whoami,
    )
    assert allowed["state"] == "done"
    assert allowed["sub"] == "anna@example.com"

    async def _call_users(_context):
        raise AssertionError("users_list must not run")

    with pytest.raises(ToolError, match="access denied"):
        await middleware.on_call_tool(
            MiddlewareContext(message=type("Msg", (), {"name": "users_list"})()),
            _call_users,
        )
