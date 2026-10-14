"""Built-in policy_* admin tools (V02 acceptance)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastmcp import FastMCP

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.rbac.policy_store import PolicyStore
from keystone_mcp.rbac.upstream_state import UpstreamCatalogState
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.server import policy_role_source
from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy
from keystone_mcp.upstream_registry.validate import ValidationError, assert_valid_upstream_registry
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from support.test_env import UNUSED_REDIS_URL

ADMIN = VerifiedIdentity(email="admin@example.com")
EDITOR = VerifiedIdentity(email="editor@example.com")
SERVICE = VerifiedIdentity(subject="svc:bot", subject_type="service")

POLICY_YAML = """\
version: "2.0.0"
default_deny: true
roles:
  administrator:
    description: admin
    allow: ["*"]
  viewer:
    description: viewer
    allow:
      - docs_read
  editor:
    description: editor
    allow:
      - docs_search
      - docs_read
"""

DOCS_ROUTES = ("docs_search", "docs_read")


def _settings(
    tmp_path: Path,
    *,
    rbac_mode: str = "enforce",
    policy_tools: str = "full",
) -> Settings:
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text(POLICY_YAML, encoding="utf-8")
    return Settings(
        base_url="http://localhost:8080",
        deployment_profile="local",
        rbac_mode=rbac_mode,
        rbac_policy_path=str(policy),
        policy_tools=policy_tools,
        redis_url=UNUSED_REDIS_URL,
        rbac_audit_subject_salt="policy-tools-test",
        users_backend="local",
    )


def _build_harness(
    tmp_path: Path,
    *,
    rbac_mode: str = "enforce",
    policy_tools: str = "full",
    observability: object | None = None,
    upstream_catalog_state: object | None = None,
    extra_catalog_names: object | None = None,
) -> tuple[
    RouterRegistry, PolicyStore | None, RbacPolicyManager | None, InMemoryUserDirectory, Settings
]:
    settings = _settings(tmp_path, rbac_mode=rbac_mode, policy_tools=policy_tools)
    mcp = FastMCP("policy-tools")
    registry = RouterRegistry(RouterEngine(settings), mcp)
    stub = StubAdapter()
    for name in DOCS_ROUTES:
        registry.add_route(name, stub, mode="live")

    directory = InMemoryUserDirectory()
    directory.seed("admin@example.com", roles=("administrator",))
    directory.seed("editor@example.com", roles=("editor",))

    if not settings.rbac_enforcing or settings.policy_tools == "off":
        register_catalog(registry, settings, directory=directory, observability=observability)
        return registry, None, None, directory, settings

    manager = RbacPolicyManager(
        settings,
        upstream_catalog_state=upstream_catalog_state,
        extra_catalog_names=extra_catalog_names,
    )
    manager.load_initial(registry)
    store = PolicyStore(
        settings=settings,
        policy_manager=manager,
        registry=registry,
        observability=observability,
        directory=directory,
    )
    register_catalog(
        registry,
        settings,
        directory=directory,
        observability=observability,
        role_source=policy_role_source(manager),
        policy_store=store,
    )
    manager.reload(registry)
    return registry, store, manager, directory, settings


async def _call(
    registry: RouterRegistry,
    settings: Settings,
    tool: str,
    args: dict | None = None,
    *,
    identity: VerifiedIdentity = ADMIN,
) -> dict:
    route = registry.get(tool)
    assert route is not None, tool
    engine = RouterEngine(settings)
    return await engine.execute(route, args or {}, identity=identity)


POLICY_READ_ONLY = ("policy_read", "policy_catalog", "policy_validate")
POLICY_ALL = POLICY_READ_ONLY + (
    "policy_role_set",
    "policy_role_delete",
    "policy_allow_add",
    "policy_allow_remove",
    "policy_list_set",
    "policy_rollback",
)


@pytest.mark.parametrize(
    ("rbac_mode", "policy_tools", "expected"),
    [
        ("off", "full", ()),
        ("enforce", "off", ()),
        ("enforce", "read-only", POLICY_READ_ONLY),
        ("enforce", "full", POLICY_ALL),
    ],
)
def test_policy_tools_registered_by_mode(
    tmp_path: Path, rbac_mode: str, policy_tools: str, expected: tuple[str, ...]
) -> None:
    registry, _store, _manager, directory, settings = _build_harness(
        tmp_path, rbac_mode=rbac_mode, policy_tools=policy_tools
    )
    names = {route.name for route in registry.routes.values() if route.name.startswith("policy_")}
    assert names == set(expected)


@pytest.mark.asyncio
async def test_policy_read_returns_document_hashes_and_writable(tmp_path: Path) -> None:
    registry, _store, _manager, _directory, settings = _build_harness(tmp_path)
    result = await _call(registry, settings, "policy_read")
    assert result["state"] == "done"
    assert result["policy"]["version"] == "2.0.0"
    assert "administrator" in result["policy"]["roles"]
    assert len(result["content_hash"]) == 64
    assert len(result["file_hash"]) == 64
    assert result["writable"] is True
    assert result["mode"] == "full"


@pytest.mark.asyncio
async def test_policy_catalog_filters_and_critical_flags(tmp_path: Path) -> None:
    registry, _store, _manager, _directory, settings = _build_harness(tmp_path)
    all_tools = await _call(registry, settings, "policy_catalog")
    assert all_tools["state"] == "done"
    assert all_tools["total"] >= len(DOCS_ROUTES)
    names = {row["name"] for row in all_tools["tools"]}
    assert "docs_search" in names
    assert "users_list" in names
    users_row = next(row for row in all_tools["tools"] if row["name"] == "users_list")
    policy_row = next(row for row in all_tools["tools"] if row["name"] == "policy_read")
    assert users_row["critical"] is True
    assert policy_row["critical"] is True

    docs_only = await _call(registry, settings, "policy_catalog", {"namespace": "docs"})
    assert all(row["namespace"] == "docs" for row in docs_only["tools"])

    viewer_only = await _call(registry, settings, "policy_catalog", {"role": "viewer"})
    viewer_names = {row["name"] for row in viewer_only["tools"]}
    assert viewer_names <= {"docs_read"}


@pytest.mark.asyncio
async def test_policy_role_set_creates_role_and_reloads_policy(tmp_path: Path) -> None:
    registry, _store, manager, _directory, settings = _build_harness(tmp_path)
    assert manager is not None
    result = await _call(
        registry,
        settings,
        "policy_role_set",
        {"role": "viewer", "allow": ["users_list"]},
    )
    assert result["state"] == "done"
    assert result["changed"] is True
    assert result["role"]["name"] == "viewer"
    assert manager.policy is not None
    assert manager.policy.allows_role("viewer", "users_list")


@pytest.mark.asyncio
async def test_policy_allow_add_typo_does_not_change_file(tmp_path: Path) -> None:
    registry, _store, _manager, _directory, settings = _build_harness(tmp_path)
    before = (tmp_path / "rbac-policy.yaml").read_text(encoding="utf-8")

    typo = await _call(
        registry,
        settings,
        "policy_allow_add",
        {"role": "editor", "patterns": ["fils_*"]},
    )
    assert typo["code"] == "unmatched_pattern"
    assert (tmp_path / "rbac-policy.yaml").read_text(encoding="utf-8") == before


@pytest.mark.asyncio
async def test_policy_allow_add_unverified_namespace_warns(tmp_path: Path) -> None:
    upstream_state = lambda: UpstreamCatalogState(  # noqa: E731
        namespaces=frozenset({"future"}), unavailable=frozenset({"future"})
    )
    registry, _store, _manager, _directory, settings = _build_harness(
        tmp_path, upstream_catalog_state=upstream_state
    )
    unverified = await _call(
        registry,
        settings,
        "policy_allow_add",
        {"role": "editor", "patterns": ["future_tool"]},
    )
    assert unverified["state"] == "done"
    assert unverified["changed"] is True
    assert any("future" in warning for warning in unverified["warnings"])


@pytest.mark.asyncio
async def test_policy_allow_remove_last_pattern_is_validation_error(tmp_path: Path) -> None:
    registry, _store, _manager, _directory, settings = _build_harness(tmp_path)
    result = await _call(
        registry,
        settings,
        "policy_allow_remove",
        {"role": "viewer", "patterns": ["users_list", "docs_read"]},
    )
    assert result["code"] == "validation_error"
    assert "delete the role instead" in result["message"]


@pytest.mark.asyncio
async def test_policy_role_delete_in_use_then_after_block(tmp_path: Path) -> None:
    registry, _store, _manager, directory, settings = _build_harness(tmp_path)
    in_use = await _call(registry, settings, "policy_role_delete", {"role": "editor"})
    assert in_use["code"] == "role_in_use"

    directory.block("editor@example.com")
    deleted = await _call(registry, settings, "policy_role_delete", {"role": "editor"})
    assert deleted["state"] == "done"
    assert deleted["changed"] is True


@pytest.mark.asyncio
async def test_policy_list_set_unknown_list_and_critical_tools(tmp_path: Path, monkeypatch) -> None:
    registry, _store, manager, _directory, settings = _build_harness(tmp_path)
    assert manager is not None

    bad = await _call(
        registry,
        settings,
        "policy_list_set",
        {"list": "nope", "patterns": ["docs_search"]},
    )
    assert bad["code"] == "validation_error"
    assert "deny, requires_human_identity" in bad["message"]

    applied = await _call(
        registry,
        settings,
        "policy_list_set",
        {"list": "critical_tools", "patterns": ["docs_search"]},
    )
    assert applied["state"] == "done"
    manager.reload(registry)
    assert manager.policy is not None
    assert "docs_search" in manager.policy.critical_tool_patterns

    from keystone_mcp.router.rbac_middleware import RbacMiddleware
    from keystone_mcp.user_directory import build_in_memory_user_directory_resolver

    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: ADMIN,
    )
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed("admin@example.com", roles=("administrator",))
    middleware = RbacMiddleware(manager, resolver, settings=settings)
    seen: list[bool] = []

    async def fake_resolve(email: str, *, critical: bool = False):
        seen.append(critical)
        return type(
            "R",
            (),
            {"exists": True, "roles": ("administrator",), "is_blocked": False},
        )()

    monkeypatch.setattr(middleware._user_resolver, "resolve", fake_resolve)
    ctx = type("Ctx", (), {"message": type("Msg", (), {"name": "docs_search"})()})()

    async def call_next(_context):
        return {"ok": True}

    await middleware.on_call_tool(ctx, call_next)
    assert seen == [True]


@pytest.mark.asyncio
async def test_policy_invariant_and_self_lockout(tmp_path: Path) -> None:
    registry, _store, _manager, _directory, settings = _build_harness(tmp_path)

    invariant = await _call(
        registry,
        settings,
        "policy_role_set",
        {"role": "administrator", "allow": ["docs_search"]},
    )
    assert invariant["code"] == "policy_invariant"

    await _call(
        registry,
        settings,
        "policy_allow_add",
        {"role": "editor", "patterns": ["policy_read"]},
    )
    lockout = await _call(
        registry,
        settings,
        "policy_allow_remove",
        {"role": "editor", "patterns": ["policy_read"]},
        identity=EDITOR,
    )
    assert lockout["code"] == "self_lockout_forbidden"


@pytest.mark.asyncio
async def test_expected_hash_conflict(tmp_path: Path) -> None:
    registry, _store, _manager, _directory, settings = _build_harness(tmp_path)
    conflict = await _call(
        registry,
        settings,
        "policy_allow_add",
        {"role": "editor", "patterns": ["users_list"], "expected_hash": "0" * 64},
    )
    assert conflict["code"] == "policy_conflict"


@pytest.mark.asyncio
async def test_policy_rollback_toggles_one_generation(tmp_path: Path) -> None:
    registry, _store, _manager, _directory, settings = _build_harness(tmp_path)
    read_before = await _call(registry, settings, "policy_read")
    hash_before = read_before["file_hash"]
    await _call(
        registry, settings, "policy_allow_add", {"role": "editor", "patterns": ["users_list"]}
    )
    rolled = await _call(registry, settings, "policy_rollback")
    assert rolled["state"] == "done"
    assert rolled["content_hash"] == hash_before
    rolled_again = await _call(registry, settings, "policy_rollback")
    assert rolled_again["state"] == "done"
    assert rolled_again["content_hash"] != hash_before


@pytest.mark.asyncio
async def test_service_account_forbidden_on_mutations_allowed_on_read(tmp_path: Path) -> None:
    registry, _store, _manager, _directory, settings = _build_harness(tmp_path)
    cases = (
        ("policy_role_set", {"role": "editor", "allow": ["docs_read"]}),
        ("policy_allow_add", {"role": "editor", "patterns": ["docs_read"]}),
        ("policy_list_set", {"list": "deny", "patterns": ["docs_search"]}),
        ("policy_rollback", {}),
    )
    for tool, args in cases:
        result = await _call(registry, settings, tool, args, identity=SERVICE)
        assert result["code"] == "forbidden"
        assert "policy changes require a human administrator" in result["message"]

    read = await _call(registry, settings, "policy_read", identity=SERVICE)
    assert read["state"] == "done"


@pytest.mark.asyncio
async def test_readonly_file_blocks_mutations_not_reads(tmp_path: Path) -> None:
    registry, _store, _manager, _directory, settings = _build_harness(tmp_path)
    policy_path = tmp_path / "rbac-policy.yaml"
    os.chmod(policy_path, 0o444)
    os.chmod(tmp_path, 0o555)
    try:
        blocked = await _call(
            registry,
            settings,
            "policy_allow_add",
            {"role": "editor", "patterns": ["users_list"]},
        )
        assert blocked["code"] == "policy_readonly"
        still_reads = await _call(registry, settings, "policy_read")
        assert still_reads["state"] == "done"
    finally:
        os.chmod(tmp_path, 0o700)
        os.chmod(policy_path, 0o644)


@pytest.mark.asyncio
async def test_policy_mutation_emits_audit_event(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:

    observability = MagicMock()
    registry, _store, _manager, _directory, settings = _build_harness(
        tmp_path, observability=observability
    )
    await _call(
        registry, settings, "policy_allow_add", {"role": "editor", "patterns": ["users_list"]}
    )
    observability.record_policy_mutation.assert_called()
    kwargs = observability.record_policy_mutation.call_args.kwargs
    assert kwargs["operation"] == "policy_allow_add"


@pytest.mark.asyncio
async def test_role_name_with_spaces_is_trimmed(tmp_path: Path) -> None:
    registry, _store, _manager, _directory, settings = _build_harness(tmp_path)
    result = await _call(
        registry,
        settings,
        "policy_allow_add",
        {"role": " editor ", "patterns": ["users_list"]},
    )
    assert result["state"] == "done"
    assert result["role"]["name"] == "editor"


@pytest.mark.asyncio
async def test_rollback_accepts_expected_hash(tmp_path: Path) -> None:
    registry, _store, _manager, _directory, settings = _build_harness(tmp_path)
    read_before = await _call(registry, settings, "policy_read")
    hash_before = read_before["file_hash"]
    await _call(
        registry, settings, "policy_allow_add", {"role": "editor", "patterns": ["users_list"]}
    )
    read_after_change = await _call(registry, settings, "policy_read")
    ok = await _call(
        registry,
        settings,
        "policy_rollback",
        {"expected_hash": read_after_change["file_hash"]},
    )
    assert ok["state"] == "done"
    assert ok["content_hash"] == hash_before
    bad = await _call(registry, settings, "policy_rollback", {"expected_hash": "0" * 64})
    assert bad["code"] == "policy_conflict"


@pytest.mark.asyncio
async def test_adapter_refusals_are_audited(tmp_path: Path) -> None:
    observability = MagicMock()
    registry, _store, _manager, _directory, settings = _build_harness(
        tmp_path, observability=observability
    )
    validation = await _call(registry, settings, "policy_role_set", {"role": "", "allow": ["*"]})
    assert validation["code"] == "validation_error"
    observability.record_policy_mutation.assert_called()
    assert observability.record_policy_mutation.call_args.kwargs["outcome"] == "refused"

    observability.reset_mock()

    async def broken_resolve(_email: str):
        raise RuntimeError("directory down")

    _directory.resolve_user = broken_resolve  # type: ignore[method-assign]
    unavailable = await _call(
        registry, settings, "policy_allow_add", {"role": "editor", "patterns": ["users_list"]}
    )
    assert unavailable["code"] == "service_unavailable"
    observability.record_policy_mutation.assert_called()

    observability.reset_mock()
    read = await _call(registry, settings, "policy_read")
    assert read["state"] == "done"
    observability.record_policy_mutation.assert_not_called()


@pytest.mark.asyncio
async def test_policy_catalog_lists_prompts_and_resources(tmp_path: Path) -> None:
    registry, _store, _manager, _directory, settings = _build_harness(
        tmp_path, extra_catalog_names=lambda: frozenset({"docs_readme"})
    )
    catalog = await _call(registry, settings, "policy_catalog")
    names = {entry["name"]: entry["source"] for entry in catalog["tools"]}
    assert names.get("docs_readme") == "live"


@pytest.mark.asyncio
async def test_allow_add_accepts_a_resource_name(tmp_path: Path) -> None:
    registry, _store, _manager, _directory, settings = _build_harness(
        tmp_path, extra_catalog_names=lambda: frozenset({"docs_readme"})
    )
    result = await _call(
        registry,
        settings,
        "policy_allow_add",
        {"role": "editor", "patterns": ["docs_readme"]},
    )
    assert result["state"] == "done"


def test_namespace_policy_is_reserved() -> None:
    document = {
        "schema_version": 1,
        "entries": [
            {"name": "svc", "url": "https://svc.example/mcp", "namespace": "policy"},
        ],
    }
    with pytest.raises(ValidationError, match="built-in tool policy_read"):
        assert_valid_upstream_registry(
            document, policy=UpstreamSecurityPolicy(allow_insecure_http=True)
        )
