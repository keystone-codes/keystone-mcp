"""users_* builtin admin tools — S2S proxy to mcp-users with actor from identity."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import MiddlewareContext

from keystone_mcp.adapters.users_admin import UsersAdminAdapter
from keystone_mcp.catalog.builtin import register_catalog
from keystone_mcp.config import Settings
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.rbac.loader import RbacPolicyManager, assert_live_catalog_validation
from keystone_mcp.rbac.policy import default_policy_path, load_policy
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.rbac_middleware import RbacMiddleware
from keystone_mcp.router.registry import Param, RouterRegistry
from keystone_mcp.user_directory import (
    build_in_memory_user_directory_resolver,
    build_user_directory,
)
from keystone_mcp.user_directory.http import ACTOR_EMAIL_HEADER, HttpUserDirectory

ADMIN = VerifiedIdentity(email="admin@example.com")
OPERATOR = VerifiedIdentity(email="operator@example.com")

USER_SUMMARY = {
    "email": "user@example.com",
    "full_name": "User",
    "roles": ["analyst"],
    "is_blocked": False,
    "created_at": "2026-07-24T12:00:00Z",
    "updated_at": "2026-07-24T12:00:00Z",
    "created_by": "admin@example.com",
    "note": None,
}


def _settings(tmp_path: Path | None = None) -> Settings:
    base = {
        "base_url": "http://localhost:8080",
        "users_backend": "http",
        "users_service_url": "http://mcp-users:8080",
        "users_service_token": "service-secret",
    }
    if tmp_path is None:
        return Settings(**base, rbac_mode="off")
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    return Settings(
        **base,
        rbac_mode="enforce",
        rbac_policy_path=str(policy),
        redis_url="redis://localhost:6379/0",
        rbac_audit_subject_salt="test-salt",
    )


def _registry(adapter: UsersAdminAdapter | None = None) -> tuple[RouterEngine, RouterRegistry]:
    engine = RouterEngine(_settings())
    return engine, RouterRegistry(engine)


def _http_directory(handler) -> HttpUserDirectory:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://mcp-users:8080",
        headers={"Authorization": "Bearer service-secret"},
    )
    return HttpUserDirectory(
        base_url="http://mcp-users:8080",
        service_token="service-secret",
        timeout_seconds=5.0,
        client=client,
    )


@pytest.mark.parametrize(
    ("tool_name", "args", "method", "path", "body_key"),
    [
        ("users_list", {}, "GET", "/v1/users", None),
        (
            "users_add",
            {"email": "new@example.com", "full_name": "New", "roles": ["analyst"]},
            "POST",
            "/v1/users",
            "email",
        ),
        (
            "users_update",
            {"email": "user@example.com", "full_name": "Renamed"},
            "PATCH",
            "/v1/users/user@example.com",
            "full_name",
        ),
        (
            "users_block",
            {"email": "user@example.com"},
            "POST",
            "/v1/users/user@example.com/block",
            None,
        ),
        (
            "users_unblock",
            {"email": "user@example.com"},
            "POST",
            "/v1/users/user@example.com/unblock",
            None,
        ),
        (
            "users_set_roles",
            {"email": "user@example.com", "roles": ["operator", "analyst"]},
            "PUT",
            "/v1/users/user@example.com/roles",
            "roles",
        ),
        (
            "users_grant_role",
            {"email": "user@example.com", "role": "operator"},
            "POST",
            "/v1/users/user@example.com/roles/operator",
            None,
        ),
        (
            "users_revoke_role",
            {"email": "user@example.com", "role": "analyst"},
            "DELETE",
            "/v1/users/user@example.com/roles/analyst",
            None,
        ),
    ],
)
async def test_users_tools_proxy_expected_endpoint(
    tool_name: str,
    args: dict,
    method: str,
    path: str,
    body_key: str | None,
):
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["auth"] = request.headers.get("authorization")
        captured["actor"] = request.headers.get(ACTOR_EMAIL_HEADER.lower())
        if request.content:
            captured["body"] = json.loads(request.content)
        if request.method == "GET":
            captured["params"] = dict(request.url.params)
        if tool_name == "users_list":
            return httpx.Response(200, json={"users": [USER_SUMMARY], "total": 1})
        return httpx.Response(200, json=USER_SUMMARY)

    adapter = UsersAdminAdapter(directory=_http_directory(handler))
    engine, reg = _registry()
    route = reg.add_route(tool_name, adapter, mode="live", params=[Param("x", str, required=False)])

    out = await engine.execute(route, args, identity=ADMIN)

    assert out["state"] == "done"
    assert captured["method"] == method
    assert captured["path"] == path
    assert captured["auth"] == "Bearer service-secret"
    if tool_name == "users_list":
        assert captured["params"] == {"is_blocked": "false"}
        assert out["total"] == 1
    else:
        assert captured["actor"] == "admin@example.com"
        if body_key == "email":
            assert captured["body"]["created_by"] == "admin@example.com"
            assert "created_by" not in args
        elif body_key == "roles":
            assert captured["body"]["roles"] == ["operator", "analyst"]


async def test_users_list_defaults_to_non_blocked_filter():
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"users": [], "total": 0})

    adapter = UsersAdminAdapter(directory=_http_directory(handler))
    engine, reg = _registry()
    route = reg.add_route("users_list", adapter, mode="live")

    await engine.execute(route, {}, identity=ADMIN)
    assert captured["params"] == {"is_blocked": "false"}


async def test_users_list_can_request_blocked_users():
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"users": [], "total": 0})

    adapter = UsersAdminAdapter(directory=_http_directory(handler))
    engine, reg = _registry()
    route = reg.add_route("users_list", adapter, mode="live")

    await engine.execute(route, {"is_blocked": True}, identity=ADMIN)
    assert captured["params"] == {"is_blocked": "true"}


@pytest.mark.parametrize(
    ("status_code", "payload", "expected_code"),
    [
        (404, {"detail": {"detail": "User not found", "code": "user_not_found"}}, "user_not_found"),
        (
            409,
            {"detail": "Cannot remove or block the last active administrator"},
            "last_administrator",
        ),
        (
            409,
            {
                "detail": {"detail": "self block", "code": "self_admin_mutation_forbidden"},
            },
            "self_admin_mutation_forbidden",
        ),
        (403, {"detail": {"detail": "forbidden", "code": "forbidden"}}, "forbidden"),
        (422, {"detail": [{"loc": ["body", "email"], "msg": "invalid"}]}, "validation_error"),
        (
            400,
            {"detail": {"detail": "actor required", "code": "actor_email_required"}},
            "actor_email_required",
        ),
    ],
)
async def test_users_service_errors_are_mapped(status_code, payload, expected_code):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=payload)

    adapter = UsersAdminAdapter(directory=_http_directory(handler))
    engine, reg = _registry()
    route = reg.add_route("users_block", adapter, mode="live")

    out = await engine.execute(route, {"email": "user@example.com"}, identity=ADMIN)

    assert out["state"] == "error"
    assert out["code"] == expected_code
    assert "service-secret" not in json.dumps(out)


class _RecordingObservability:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def record_users_mutation(self, **kwargs) -> None:
        self.calls.append(kwargs)


async def test_audit_is_recorded_when_service_response_cannot_be_parsed():
    """The service already applied the mutation once it answers 200: a

    malformed response body must still produce an audited error, not a bare
    exception that skips ``_record_mutation_audit`` entirely (X06 review
    finding).
    """

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    observability = _RecordingObservability()
    adapter = UsersAdminAdapter(directory=_http_directory(handler), observability=observability)
    engine, reg = _registry()
    route = reg.add_route("users_block", adapter, mode="live")

    out = await engine.execute(route, {"email": "user@example.com"}, identity=ADMIN)

    assert out["state"] == "error"
    assert out["code"] == "service_error"
    assert len(observability.calls) == 1
    call = observability.calls[-1]
    assert call["operation"] == "users_block"
    assert call["outcome"] == "error"
    assert call["code"] == "service_error"


async def test_actor_email_not_taken_from_tool_arguments():
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["actor"] = request.headers.get(ACTOR_EMAIL_HEADER.lower(), "")
        return httpx.Response(200, json=USER_SUMMARY)

    adapter = UsersAdminAdapter(directory=_http_directory(handler))
    engine, reg = _registry()
    route = reg.add_route("users_block", adapter, mode="live")

    await engine.execute(
        route,
        {
            "email": "user@example.com",
            "actor_email": "evil@example.com",
            "created_by": "evil@example.com",
        },
        identity=ADMIN,
    )
    assert captured["actor"] == "admin@example.com"


def test_catalog_registers_all_users_tools(tmp_path: Path):
    settings = _settings(tmp_path)
    engine = RouterEngine(settings)
    reg = RouterRegistry(engine)
    register_catalog(reg, settings, directory=build_user_directory(settings))

    expected = {
        "users_list",
        "users_add",
        "users_update",
        "users_block",
        "users_unblock",
        "users_set_roles",
        "users_grant_role",
        "users_revoke_role",
    }
    for name in expected:
        route = reg.get(name)
        assert route is not None, name
        assert route.mode == "live"
        assert route.admin is True
    assert expected <= {
        route.name for route in reg.routes.values() if route.name.startswith("users_")
    }


def test_policy_loader_accepts_live_users_tools_in_catalog(tmp_path: Path):
    settings = _settings(tmp_path)
    engine = RouterEngine(settings)
    reg = RouterRegistry(engine)
    register_catalog(reg, settings, directory=build_user_directory(settings))
    policy = load_policy(default_policy_path())
    live = {route.published_name for route in reg.routes.values() if route.mode == "live"}
    users_tools = {name for name in live if name.startswith("users_")}
    assert users_tools == {
        "users_list",
        "users_add",
        "users_update",
        "users_block",
        "users_unblock",
        "users_set_roles",
        "users_grant_role",
        "users_revoke_role",
    }
    result = assert_live_catalog_validation(policy, live)
    assert result.ok
    assert users_tools <= result.tool_names


USERS_RBAC_POLICY = """\
version: "test-users-rbac"
default_deny: true
roles:
  administrator:
    description: admin
    allow: ["*"]
  member:
    description: member
    allow: ["reports_read", "reports_write"]
"""


@pytest.mark.asyncio
async def test_rbac_denies_users_tools_for_non_administrator(tmp_path):
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text(USERS_RBAC_POLICY, encoding="utf-8")
    settings = Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy),
        users_service_url="http://mcp-users:8080",
        users_service_token="token",
    )
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed("operator@example.com", roles=("operator",))
    registry = RouterRegistry(RouterEngine(settings), FastMCP("policy-host"))
    registry.add_route("users_list", UsersAdminAdapter(), mode="live")
    registry.add_route("reports_read", UsersAdminAdapter(), mode="live")
    registry.add_route("reports_write", UsersAdminAdapter(), mode="live")
    manager = RbacPolicyManager(settings)
    manager.load_initial(registry)
    middleware = RbacMiddleware(
        settings=settings,
        policy_manager=manager,
        user_resolver=resolver,
    )

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        "keystone_mcp.router.rbac_middleware.resolve_verified_identity",
        lambda: OPERATOR,
    )
    ctx = MiddlewareContext(message=type("Msg", (), {"name": "users_list"})())
    with pytest.raises(ToolError, match="access denied"):
        await middleware.on_call_tool(ctx, _async_noop)
    monkeypatch.undo()


async def _async_noop(_context):
    return {"ok": True}


async def test_service_unconfigured_without_url():
    settings = Settings(
        base_url="http://localhost:8080",
        users_backend="http",
        users_service_url="",
        users_service_token="",
    )
    engine = RouterEngine(settings)
    reg = RouterRegistry(engine)
    adapter = UsersAdminAdapter()
    route = reg.add_route("users_list", adapter, mode="live")

    out = await engine.execute(route, {}, identity=ADMIN)

    assert out["state"] == "error"
    assert out["code"] == "service_unconfigured"
    assert "token" not in out["message"].lower()


async def test_service_unconfigured_without_token():
    settings = Settings(
        base_url="http://localhost:8080",
        users_backend="http",
        users_service_url="http://mcp-users:8080",
        users_service_token="",
    )
    engine = RouterEngine(settings)
    reg = RouterRegistry(engine)
    adapter = UsersAdminAdapter()
    route = reg.add_route("users_list", adapter, mode="live")

    out = await engine.execute(route, {}, identity=ADMIN)

    assert out["state"] == "error"
    assert out["code"] == "service_unconfigured"


async def test_service_timeout_returns_safe_error():
    class _TimeoutClient:
        async def request(self, *_args, **_kwargs):
            raise httpx.TimeoutException("timed out")

        async def aclose(self):
            return None

    directory = HttpUserDirectory(
        base_url="http://mcp-users:8080",
        service_token="service-secret",
        timeout_seconds=5.0,
        client=_TimeoutClient(),
    )
    adapter = UsersAdminAdapter(directory=directory)
    engine, reg = _registry()
    route = reg.add_route("users_list", adapter, mode="live")

    out = await engine.execute(route, {}, identity=ADMIN)

    assert out["state"] == "error"
    assert out["code"] == "service_timeout"
    assert out["message"] == "users service timed out"


async def test_service_unavailable_returns_safe_error():
    class _BrokenClient:
        async def request(self, *_args, **_kwargs):
            raise httpx.ConnectError("connection refused")

        async def aclose(self):
            return None

    directory = HttpUserDirectory(
        base_url="http://mcp-users:8080",
        service_token="service-secret",
        timeout_seconds=5.0,
        client=_BrokenClient(),
    )
    adapter = UsersAdminAdapter(directory=directory)
    engine, reg = _registry()
    route = reg.add_route("users_list", adapter, mode="live")

    out = await engine.execute(route, {}, identity=ADMIN)

    assert out["state"] == "error"
    assert out["code"] == "service_unavailable"
    assert "refused" not in out["message"]


MUTATION_TOOLS = [
    ("users_add", {"email": "new@example.com", "full_name": "New"}),
    ("users_update", {"email": "user@example.com", "full_name": "Renamed"}),
    ("users_block", {"email": "user@example.com"}),
    ("users_unblock", {"email": "user@example.com"}),
    ("users_set_roles", {"email": "user@example.com", "roles": ["operator"]}),
    ("users_grant_role", {"email": "user@example.com", "role": "operator"}),
    ("users_revoke_role", {"email": "user@example.com", "role": "operator"}),
]


@pytest.mark.parametrize(("tool_name", "args"), MUTATION_TOOLS)
async def test_every_mutation_sends_the_verified_actor(tool_name: str, args: dict):
    """The users service attributes and guards mutations by X-Actor-Email.

    users_unblock was the one mutation that omitted it, so an unblock arrived
    unattributed and escaped the service-side actor checks.
    """
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["actor"] = request.headers.get(ACTOR_EMAIL_HEADER.lower())
        return httpx.Response(200, json=USER_SUMMARY)

    adapter = UsersAdminAdapter(directory=_http_directory(handler))
    engine, reg = _registry()
    route = reg.add_route(tool_name, adapter, mode="live")

    out = await engine.execute(route, args, identity=ADMIN)
    assert out["state"] == "done"
    assert captured["actor"] == "admin@example.com"


async def test_unblock_actor_is_normalized_from_the_verified_identity():
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["actor"] = request.headers.get(ACTOR_EMAIL_HEADER.lower())
        return httpx.Response(200, json=USER_SUMMARY)

    adapter = UsersAdminAdapter(directory=_http_directory(handler))
    engine, reg = _registry()
    route = reg.add_route("users_unblock", adapter, mode="live")

    await engine.execute(
        route,
        {"email": "user@example.com", "actor_email": "evil@example.com"},
        identity=VerifiedIdentity(email="Admin@Example.COM"),
    )
    assert captured["actor"] == "admin@example.com"
