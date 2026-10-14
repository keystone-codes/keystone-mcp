"""Startup must say plainly when users_* admin tools are withheld.

Built-in ``users_*`` routes are published only with ``rbac_mode=enforce``.
With ``off`` or ``observe`` they are omitted from the catalog; startup should
say so instead of implying open user administration.
"""

from __future__ import annotations

from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.config import Settings, startup_warnings
from keystone_mcp.server import build_server
from support.login import dev_token_login
from support.test_env import UNUSED_REDIS_URL

BASE_URL = "http://localhost:8080"

ADMIN_TOOLS = {
    "users_list",
    "users_add",
    "users_update",
    "users_block",
    "users_unblock",
    "users_set_roles",
    "users_grant_role",
    "users_revoke_role",
}


def _build(settings: Settings, **kwargs):
    return build_server(
        login_providers=[dev_token_login({"token"})],
        settings=settings,
        oauth_store=InMemoryOAuthStore(),
        **kwargs,
    )


def _warnings(caplog) -> list[str]:
    return [record.getMessage() for record in caplog.records if record.levelname == "WARNING"]


def _withheld_warnings(caplog) -> list[str]:
    return [m for m in _warnings(caplog) if "users_* admin tools are not published" in m]


def test_rbac_off_warns_users_tools_are_not_published(caplog):
    settings = Settings(base_url=BASE_URL, rbac_mode="off")
    with caplog.at_level("WARNING", logger="keystone_mcp.server"):
        _mcp, registry, *_ = _build(settings, register_builtin_catalog=True)

    assert len(_withheld_warnings(caplog)) == 1
    message = _withheld_warnings(caplog)[0]
    assert "KEYSTONE_MCP_RBAC_MODE=off" in message
    for tool in ADMIN_TOOLS:
        assert registry.get(tool) is None, tool


def test_no_warning_when_the_builtin_catalog_is_not_registered(caplog):
    settings = Settings(base_url=BASE_URL, rbac_mode="off")
    with caplog.at_level("WARNING", logger="keystone_mcp.server"):
        _build(settings, register_builtin_catalog=False)
    assert not _withheld_warnings(caplog)


def test_observe_warns_users_tools_are_not_published(caplog, tmp_path):
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    resolver, _backend, _revision = _in_memory_resolver()
    settings = Settings(
        base_url=BASE_URL,
        rbac_mode="observe",
        rbac_policy_path=str(policy),
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url=UNUSED_REDIS_URL,
        rbac_audit_subject_salt="test-salt",
    )
    with caplog.at_level("WARNING", logger="keystone_mcp.server"):
        _build(settings, register_builtin_catalog=True, user_resolver=resolver)
    assert len(_withheld_warnings(caplog)) == 1
    assert "KEYSTONE_MCP_RBAC_MODE=observe" in _withheld_warnings(caplog)[0]


def test_no_withheld_warning_when_rbac_is_enforce(caplog, tmp_path):
    policy = tmp_path / "rbac-policy.yaml"
    policy.write_text("default_deny: true\nroles: {}\n", encoding="utf-8")
    resolver, _backend, _revision = _in_memory_resolver()
    settings = Settings(
        base_url=BASE_URL,
        rbac_mode="enforce",
        rbac_policy_path=str(policy),
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url=UNUSED_REDIS_URL,
        rbac_audit_subject_salt="test-salt",
    )
    with caplog.at_level("WARNING", logger="keystone_mcp.server"):
        _mcp, registry, *_ = _build(settings, register_builtin_catalog=True, user_resolver=resolver)
    assert not _withheld_warnings(caplog)
    for tool in ADMIN_TOOLS:
        assert registry.get(tool) is not None, tool


def _in_memory_resolver():
    from keystone_mcp.user_directory import build_in_memory_user_directory_resolver

    return build_in_memory_user_directory_resolver()


def test_users_service_http_in_production_warns():
    settings = Settings(
        deployment_profile="production",
        users_backend="http",
        users_service_url="http://users.internal",
        users_service_token="token",
    )
    warnings = startup_warnings(settings)
    assert any("KEYSTONE_MCP_USERS_SERVICE_URL" in w for w in warnings)


def test_users_service_http_flag_silences_warning():
    settings = Settings(
        deployment_profile="production",
        users_backend="http",
        users_service_url="http://users.internal",
        users_service_token="token",
        users_service_allow_insecure_http=True,
    )
    warnings = startup_warnings(settings)
    assert not any("KEYSTONE_MCP_USERS_SERVICE_URL uses http" in w for w in warnings)


def test_users_service_http_loopback_no_warning():
    settings = Settings(
        deployment_profile="production",
        users_backend="http",
        users_service_url="http://127.0.0.1:8080",
        users_service_token="token",
    )
    assert not any(
        "KEYSTONE_MCP_USERS_SERVICE_URL uses http" in w for w in startup_warnings(settings)
    )
    local = Settings(
        deployment_profile="local",
        users_backend="http",
        users_service_url="http://users.internal",
        users_service_token="token",
    )
    assert not any("KEYSTONE_MCP_USERS_SERVICE_URL uses http" in w for w in startup_warnings(local))


def test_dcr_without_allowlist_warns_in_production():
    settings = Settings(
        base_url=BASE_URL,
        deployment_profile="production",
        oauth_dcr_enabled=True,
        oauth_allowed_redirect_hosts=(),
        oauth_allowed_redirect_scheme_hosts=(),
    )
    warnings = startup_warnings(settings)
    assert any("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS is empty" in w for w in warnings)

    with_hosts = Settings(
        base_url=BASE_URL,
        deployment_profile="production",
        oauth_dcr_enabled=True,
        oauth_allowed_redirect_hosts=("claude.ai",),
    )
    assert not any(
        "KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS is empty" in w
        for w in startup_warnings(with_hosts)
    )

    dcr_off = Settings(
        base_url=BASE_URL,
        deployment_profile="production",
        oauth_dcr_enabled=False,
    )
    assert not any(
        "KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS is empty" in w for w in startup_warnings(dcr_off)
    )

    local = Settings(base_url=BASE_URL, deployment_profile="local", oauth_dcr_enabled=True)
    assert not any(
        "KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS is empty" in w for w in startup_warnings(local)
    )


def test_redis_without_password_warns_in_production():
    settings = Settings(
        base_url=BASE_URL,
        deployment_profile="production",
        redis_url="redis://redis.internal:6379/0",
    )
    warnings = startup_warnings(settings)
    assert any("KEYSTONE_MCP_REDIS_URL has no password" in w for w in warnings)


def test_redis_with_password_or_loopback_no_warning():
    cases = (
        Settings(
            base_url=BASE_URL,
            deployment_profile="production",
            redis_url="redis://:secret@redis.internal:6379/0",
        ),
        Settings(
            base_url=BASE_URL,
            deployment_profile="production",
            redis_url="rediss://user:secret@redis.internal:6379/0",
        ),
        Settings(
            base_url=BASE_URL,
            deployment_profile="production",
            redis_url="redis://localhost:6379/0",
        ),
        Settings(
            base_url=BASE_URL,
            deployment_profile="production",
            redis_url="unix:///run/redis.sock",
        ),
        Settings(base_url=BASE_URL, deployment_profile="local", redis_url=UNUSED_REDIS_URL),
    )
    for settings in cases:
        assert not any(
            "KEYSTONE_MCP_REDIS_URL has no password" in w for w in startup_warnings(settings)
        )
