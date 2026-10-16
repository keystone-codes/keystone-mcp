"""Secrets from ``<NAME>_FILE`` paths."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import jwt
import pytest
from asgi_lifespan import LifespanManager
from fastmcp import Client

from keystone_mcp import cli
from keystone_mcp.config import SECRET_VARIABLES, ConfigError, Settings, load_settings
from keystone_mcp.contract_tests.fake_oidc import FakeOidcIssuer
from keystone_mcp.identity import VerifiedIdentity
from keystone_mcp.identity_assertion import IdentityAssertionSigner, resolve_identity_secret
from keystone_mcp.login.factory import build_login_providers
from keystone_mcp.login.oidc import OidcLoginProvider
from keystone_mcp.plugins import PluginContext
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.router.upstream import UpstreamRegistry, resolve_stdio_child_env
from keystone_mcp.upstream_registry.load import load_upstream_registry_file
from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy
from support.lowlevel_upstream import (
    UPSTREAM_MCP_URL,
    asgi_http_client_factory,
    build_lowlevel_upstream_app,
)
from support.test_env import require_redis_url

REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATE_SCRIPT = REPO_ROOT / "scripts" / "generate_secret_variables_table.py"
ENVIRONMENT_MD = REPO_ROOT / "docs" / "environment.md"
STDIO_SERVER = Path(__file__).parent / "support" / "stdio_upstream.py"

_SETTINGS_FIELD: dict[str, str] = {
    "KEYSTONE_MCP_DEV_TOKENS": "dev_tokens",
    "KEYSTONE_MCP_GOOGLE_CLIENT_SECRET": "google_client_secret",
    "KEYSTONE_MCP_IDENTITY_SIGNING_KEY": "identity_signing_key",
    "KEYSTONE_MCP_IDENTITY_SIGNING_KEY_PREVIOUS": "identity_signing_key_previous",
    "KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT": "rbac_audit_subject_salt",
    "KEYSTONE_MCP_REDIS_URL": "redis_url",
    "KEYSTONE_MCP_USERS_DB_URL": "users_db_url",
    "KEYSTONE_MCP_USERS_SERVICE_TOKEN": "users_service_token",
}

_IDENTITY_SECRET = "s3cr3t-identity-" + "v" * 20


def _write_secret(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


@pytest.fixture
def permissive_policy() -> UpstreamSecurityPolicy:
    return UpstreamSecurityPolicy(allow_insecure_http=True, egress_allow_private=True)


@pytest.mark.parametrize("name", SECRET_VARIABLES)
def test_every_secret_variable_reads_from_file(name: str, monkeypatch, tmp_path: Path) -> None:
    secret_value = "secret-from-file"
    path = tmp_path / "secret.txt"
    _write_secret(path, secret_value + "\n")
    monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(f"{name}_FILE", str(path))
    settings = Settings()
    assert getattr(settings, _SETTINGS_FIELD[name]) == secret_value


def test_file_wins_over_variable_and_warns(monkeypatch, tmp_path: Path, caplog) -> None:
    path = tmp_path / "redis.txt"
    _write_secret(path, "redis-from-file\n")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", "redis-from-env")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL_FILE", str(path))
    caplog.set_level("WARNING")
    settings = Settings()
    assert settings.redis_url == "redis-from-file"
    matches = [
        r
        for r in caplog.records
        if "KEYSTONE_MCP_REDIS_URL and KEYSTONE_MCP_REDIS_URL_FILE are both set" in r.message
    ]
    assert len(matches) == 1
    assert "redis-from-env" not in matches[0].message
    assert "redis-from-file" not in matches[0].message


def test_missing_file_refuses_start(monkeypatch, tmp_path: Path) -> None:
    missing = tmp_path / "missing.txt"
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL_FILE", str(missing))
    with pytest.raises(ConfigError) as exc_info:
        load_settings()
    message = str(exc_info.value)
    assert "KEYSTONE_MCP_REDIS_URL_FILE" in message
    assert str(missing) in message


def test_directory_refuses_start(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL_FILE", str(tmp_path))
    with pytest.raises(ConfigError) as exc_info:
        load_settings()
    message = str(exc_info.value)
    assert "KEYSTONE_MCP_REDIS_URL_FILE" in message
    assert "directory" in message.lower()


def test_oversized_file_refuses_start(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "big.txt"
    path.write_bytes(b"x" * 65537)
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL_FILE", str(path))
    with pytest.raises(ConfigError) as exc_info:
        load_settings()
    message = str(exc_info.value)
    assert "KEYSTONE_MCP_REDIS_URL_FILE" in message
    assert "65536" in message


def test_non_utf8_refuses_start(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "bad.txt"
    path.write_bytes(b"\xff\xfe")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL_FILE", str(path))
    with pytest.raises(ConfigError) as exc_info:
        load_settings()
    message = str(exc_info.value)
    assert "KEYSTONE_MCP_REDIS_URL_FILE" in message
    assert str(path) in message


def test_empty_file_is_empty_value(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "empty.txt"
    path.write_bytes(b"")
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS_FILE", str(path))
    assert Settings().dev_tokens == ""


def test_crlf_trailing_newline_removed(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "crlf.txt"
    path.write_bytes(b"value\r\n")
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS_FILE", str(path))
    assert Settings().dev_tokens == "value"


def test_inner_whitespace_kept(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "spaces.txt"
    _write_secret(path, "  padded  \n")
    monkeypatch.setenv("KEYSTONE_MCP_DEV_TOKENS_FILE", str(path))
    assert Settings().dev_tokens == "  padded  "


@pytest.fixture
def patch_verified_identity(monkeypatch):
    ann = VerifiedIdentity(email="ann@example.com", claims={"auth_method": "google"})
    monkeypatch.setattr("keystone_mcp.identity.resolve_verified_identity", lambda: ann)


@pytest.mark.asyncio
async def test_registry_bearer_env_from_file(
    monkeypatch, tmp_path: Path, permissive_policy, patch_verified_identity
) -> None:
    token_path = tmp_path / "token.txt"
    _write_secret(token_path, "hello-bearer-token\n")
    registry = tmp_path / "upstreams.yaml"
    registry.write_text(
        """
schema_version: 1
entries:
  - name: hello-upstream
    namespace: hello
    url: http://upstream.test/mcp
    auth:
      bearer_env: KEYSTONE_MCP_UPSTREAM_HELLO_TOKEN
""",
        encoding="utf-8",
    )
    monkeypatch.delenv("KEYSTONE_MCP_UPSTREAM_HELLO_TOKEN", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_HELLO_TOKEN_FILE", str(token_path))
    load_upstream_registry_file(registry, policy=permissive_policy)

    observed: dict = {}
    app = build_lowlevel_upstream_app(tools=["whoami"], observed=observed)
    async with LifespanManager(app):
        from fastmcp import FastMCP

        settings = Settings(base_url="http://localhost:8080")
        main = FastMCP("keystone-test")
        registry_engine = RouterRegistry(RouterEngine(settings), main)
        upstreams = UpstreamRegistry(
            main_mcp=main,
            registry=registry_engine,
            http_client_factory=asgi_http_client_factory(app),
        )
        upstreams.add_upstream(
            "hello-upstream",
            UPSTREAM_MCP_URL,
            namespace="hello",
            bearer_env="KEYSTONE_MCP_UPSTREAM_HELLO_TOKEN",
        )
        await upstreams.discover_all()
        async with Client(main) as client:
            await client.call_tool_mcp("hello_whoami", {})
    assert observed["headers"].get("authorization") == "Bearer hello-bearer-token"


def test_identity_secret_env_from_file(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "identity.txt"
    _write_secret(path, _IDENTITY_SECRET + "\n")
    var = "KEYSTONE_MCP_UPSTREAM_HELLO_IDENTITY_SECRET"
    monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(f"{var}_FILE", str(path))
    secret = resolve_identity_secret("hello-upstream", var)
    human = VerifiedIdentity(email="ann@example.com", claims={"auth_method": "google"})
    signer = IdentityAssertionSigner(
        audience="hello-upstream",
        secret=secret,
        issuer="https://keystone.example",
    )
    token = signer.sign(
        identity=human,
        task_id="t",
        mcp_method="tools/call",
        mcp_target="whoami",
        timeout_seconds=30,
        rbac_mode="off",
    )
    jwt.decode(
        token,
        _IDENTITY_SECRET,
        algorithms=["HS256"],
        audience="hello-upstream",
        issuer="https://keystone.example",
    )


def test_stdio_env_from_file_passes_value_not_path(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "stdio-secret.txt"
    _write_secret(path, "stdio-secret-value\n")
    var = "KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN"
    monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(f"{var}_FILE", str(path))
    child_env = resolve_stdio_child_env([("NOTES_API_TOKEN", var)])
    assert child_env["NOTES_API_TOKEN"] == "stdio-secret-value"
    assert str(path) not in child_env.values()


def test_plugin_context_secret_reads_file(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "plugin.txt"
    _write_secret(path, "plugin-secret\n")
    monkeypatch.delenv("ACME_SECRET", raising=False)
    monkeypatch.setenv("ACME_SECRET_FILE", str(path))
    ctx = PluginContext(
        base_url="http://localhost:8080",
        deployment_profile="local",
        http_timeout_seconds=3.0,
        settings=Settings(),
    )
    assert ctx.secret("ACME_SECRET") == "plugin-secret"


@pytest.mark.asyncio
async def test_oidc_client_secret_from_file(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "oidc.txt"
    _write_secret(path, "oidc-client-secret\n")
    monkeypatch.delenv("KEYSTONE_MCP_LOGIN_ENTRA_SECRET", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_LOGIN_ENTRA_SECRET_FILE", str(path))
    providers_path = tmp_path / "providers.yaml"
    providers_path.write_text(
        """
version: 1
providers:
  - name: entra
    type: oidc
    issuer: https://idp.test
    client_id: cid
    client_secret_env: KEYSTONE_MCP_LOGIN_ENTRA_SECRET
""",
        encoding="utf-8",
    )
    settings = Settings(login_providers_path=str(providers_path))
    built = build_login_providers(settings, resolver=None)[0]
    assert isinstance(built, OidcLoginProvider)
    fake = FakeOidcIssuer(
        issuer=built.config.issuer,
        client_id=built.config.client_id,
        client_secret=built.config.client_secret,
    )
    provider = OidcLoginProvider(built.config, http_client_factory=fake.http_client)
    redirect = await provider.begin(state="st", callback_url="http://app/cb")
    params = await fake.authorize(redirect.url)
    identity = await provider.complete(
        params=params, callback_url="http://app/cb", attempt=redirect.attempt
    )
    assert identity.email == fake.user.email


def test_values_are_not_copied_to_os_environ(monkeypatch, tmp_path: Path) -> None:
    import os

    path = tmp_path / "redis.txt"
    file_value = require_redis_url() + "-from-file"
    _write_secret(path, file_value + "\n")
    monkeypatch.delenv("KEYSTONE_MCP_REDIS_URL", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL_FILE", str(path))
    load_settings()
    assert file_value not in os.environ.values()


def test_secret_table_in_environment_md_is_generated() -> None:
    generated = subprocess.check_output(
        [sys.executable, str(GENERATE_SCRIPT)],
        text=True,
        cwd=REPO_ROOT,
    )
    text = ENVIRONMENT_MD.read_text(encoding="utf-8")
    match = re.search(
        r"<!-- secret-files:begin -->\n(.*?)<!-- secret-files:end -->",
        text,
        re.DOTALL,
    )
    assert match is not None
    assert match.group(1).strip() == generated.strip()


def test_config_check_reports_unreadable_secret_file(monkeypatch, tmp_path: Path, capsys) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_ENV_FILE", "")
    monkeypatch.setenv("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "local")
    monkeypatch.setenv("KEYSTONE_MCP_BASE_URL", "http://localhost:8080")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_MODE", "off")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "a" * 32)
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", require_redis_url())
    missing = tmp_path / "missing-redis.txt"
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL_FILE", str(missing))
    monkeypatch.setattr(cli, "configure_logging", lambda settings: None)
    code = cli.main(["config", "check"])
    out = capsys.readouterr().out
    assert code == 1
    assert any(
        line.startswith("ERROR") and "KEYSTONE_MCP_REDIS_URL_FILE" in line
        for line in out.splitlines()
    )
