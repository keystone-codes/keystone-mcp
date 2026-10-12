"""Upstream registry loader, validator, and settings integration."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from keystone_mcp.config import load_settings
from keystone_mcp.upstream_registry.load import load_upstream_registry_file, parse_upstream_entry
from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy
from keystone_mcp.upstream_registry.validate import (
    ValidationError,
    assert_valid_upstream_registry,
    validate_upstream_url,
)


@pytest.fixture
def permissive_policy() -> UpstreamSecurityPolicy:
    return UpstreamSecurityPolicy(allow_insecure_http=True, egress_allow_private=True)


def test_validate_url_rejects_non_http_schemes():
    policy = UpstreamSecurityPolicy()
    errors = validate_upstream_url("file:///etc/passwd", policy=policy)
    assert any("http or https" in message for message in errors)


def test_validate_url_rejects_userinfo():
    policy = UpstreamSecurityPolicy(allow_insecure_http=True)
    errors = validate_upstream_url("http://user:pass@example.com/mcp", policy=policy)
    assert any("userinfo" in message for message in errors)


def test_validate_url_rejects_http_by_default():
    errors = validate_upstream_url("http://svc.example.com/mcp", policy=UpstreamSecurityPolicy())
    assert any("ALLOW_INSECURE_HTTP" in message for message in errors)


def test_validate_url_rejects_loopback_without_flags():
    errors = validate_upstream_url("https://127.0.0.1/mcp", policy=UpstreamSecurityPolicy())
    assert any("private" in message for message in errors)


def test_validate_url_rejects_obfuscated_ip_literals():
    policy = UpstreamSecurityPolicy()
    for url in (
        "https://0x7f000001/mcp",
        "https://2130706433/mcp",
        "https://127.1/mcp",
        "https://10.000.000.001/mcp",
    ):
        errors = validate_upstream_url(url, policy=policy)
        assert errors, f"expected rejection for {url}"
        assert any("canonical" in message or "private" in message for message in errors), url


def test_validate_url_allows_loopback_with_dev_flags(permissive_policy):
    errors = validate_upstream_url("http://127.0.0.1/mcp", policy=permissive_policy)
    assert errors == []


def test_validate_registry_duplicate_name(permissive_policy):
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "a",
                "url": "http://one.example/mcp",
                "namespace": "one",
            },
            {
                "name": "a",
                "url": "http://two.example/mcp",
                "namespace": "two",
            },
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any("duplicate upstream name" in message for message in exc.value.messages)


def test_load_yaml_registry(tmp_path: Path, permissive_policy):
    path = tmp_path / "upstreams.yaml"
    path.write_text(
        textwrap.dedent(
            """
            schema_version: 1
            entries:
              - name: reports
                url: http://reports-mcp:8081/mcp
                namespace: reports
                enabled: true
            """
        ),
        encoding="utf-8",
    )
    upstreams = load_upstream_registry_file(path, policy=permissive_policy)
    assert len(upstreams) == 1
    assert upstreams[0].namespace == "reports"


def test_settings_prefers_registry_file(monkeypatch, tmp_path: Path, permissive_policy):
    path = tmp_path / "registry.yaml"
    path.write_text(
        textwrap.dedent(
            """
            schema_version: 1
            entries:
              - name: from-file
                url: http://file-mcp:8081/mcp
                namespace: file_ns
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP", "true")
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS_PATH", str(path))
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(
            [
                {
                    "name": "from-env",
                    "url": "http://env-mcp:8081/mcp",
                    "namespace": "env_ns",
                }
            ]
        ),
    )
    settings = load_settings()
    assert len(settings.upstreams) == 1
    assert settings.upstreams[0].name == "from-file"


def test_parse_upstream_entry_route_mode_and_timeouts(permissive_policy):
    cfg = parse_upstream_entry(
        {
            "name": "svc",
            "url": "http://svc:8081/mcp",
            "namespace": "svc",
            "route_mode": "stub",
            "discovery_timeout_seconds": 5,
            "tool_timeout_seconds": 90,
        },
        policy=permissive_policy,
    )
    assert cfg.route_mode == "stub"
    assert cfg.discovery_timeout_seconds == 5.0
    assert cfg.tool_timeout_seconds == 90.0


def test_cli_validate_exits_nonzero_on_invalid(tmp_path: Path):
    from keystone_mcp.cli import main

    path = tmp_path / "bad.yaml"
    path.write_text("schema_version: 2\nentries: []\n", encoding="utf-8")
    assert main(["upstream", "validate", "--path", str(path)]) == 1


# --- namespace validation (P09) ----------------------------------------------------


def test_namespace_users_is_reserved(permissive_policy):
    document = {
        "schema_version": 1,
        "entries": [
            {"name": "svc", "url": "https://svc.example/mcp", "namespace": "users"},
        ],
    }
    with pytest.raises(ValidationError, match="built-in tool users_list"):
        assert_valid_upstream_registry(document, policy=permissive_policy)


def test_prefix_namespaces_are_refused(permissive_policy):
    colliding = {
        "schema_version": 1,
        "entries": [
            {"name": "a", "url": "https://a.example/mcp", "namespace": "billing"},
            {"name": "b", "url": "https://b.example/mcp", "namespace": "billing_admin"},
        ],
    }
    with pytest.raises(ValidationError, match="billing"):
        assert_valid_upstream_registry(colliding, policy=permissive_policy)

    not_colliding = {
        "schema_version": 1,
        "entries": [
            {"name": "a", "url": "https://a.example/mcp", "namespace": "billing"},
            {"name": "b", "url": "https://b.example/mcp", "namespace": "billingadmin"},
        ],
    }
    # Does not raise: no namespace here is another namespace plus "_suffix".
    assert_valid_upstream_registry(not_colliding, policy=permissive_policy)


@pytest.mark.parametrize("namespace", ["docs*", "_docs", "docs_"])
def test_namespace_with_glob_or_edge_underscore_is_refused(permissive_policy, namespace):
    document = {
        "schema_version": 1,
        "entries": [
            {"name": "svc", "url": "https://svc.example/mcp", "namespace": namespace},
        ],
    }
    with pytest.raises(ValidationError, match="must be 1-64 characters"):
        assert_valid_upstream_registry(document, policy=permissive_policy)


def test_json_upstreams_apply_the_same_namespace_rules(monkeypatch):
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(
            [
                {"name": "a", "url": "https://a.example/mcp", "namespace": "billing"},
                {"name": "b", "url": "https://b.example/mcp", "namespace": "billing_admin"},
            ]
        ),
    )
    settings = load_settings()
    with pytest.raises(ValueError, match="billing"):
        _ = settings.upstreams


def test_shipped_examples_pass_namespace_rules():
    from keystone_mcp.cli import main

    path = Path(__file__).resolve().parent.parent / "examples" / "upstreams-registry.example.yaml"
    assert main(["upstream", "validate", "--path", str(path)]) == 0


# --- upstream bearer auth (P08) -----------------------------------------------------


def test_registry_accepts_auth_bearer_env(monkeypatch, permissive_policy):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN", "s3cr3t-value")
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "docs-mcp",
                "url": "https://docs-mcp.example/mcp",
                "namespace": "docs",
                "auth": {"bearer_env": "KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN"},
            },
        ],
    }
    # Structural validation alone (no environment check) accepts the entry.
    assert_valid_upstream_registry(document, policy=permissive_policy)

    cfg = parse_upstream_entry(document["entries"][0], policy=permissive_policy)
    assert cfg.bearer_env == "KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN"
    assert "s3cr3t-value" not in repr(cfg)


@pytest.mark.parametrize("secret_key", ["token", "bearer", "secret", "password"])
def test_registry_rejects_inline_secret(permissive_policy, secret_key):
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "docs-mcp",
                "url": "https://docs-mcp.example/mcp",
                "namespace": "docs",
                "auth": {secret_key: "abc"},
            },
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any("secrets must not be stored" in message for message in exc.value.messages)


def test_registry_rejects_bad_env_name(permissive_policy):
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "docs-mcp",
                "url": "https://docs-mcp.example/mcp",
                "namespace": "docs",
                "auth": {"bearer_env": "lower-case"},
            },
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any(
        "auth.bearer_env must be an environment variable name" in message
        for message in exc.value.messages
    )


def test_registry_rejects_bearer_env_without_upstream_prefix(permissive_policy):
    """A deployer cannot point ``bearer_env`` at an arbitrary existing secret,

    e.g. ``KEYSTONE_MCP_GOOGLE_CLIENT_SECRET`` -- only names under the
    reserved ``KEYSTONE_MCP_UPSTREAM_`` prefix are accepted."""
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "docs-mcp",
                "url": "https://docs-mcp.example/mcp",
                "namespace": "docs",
                "auth": {"bearer_env": "KEYSTONE_MCP_GOOGLE_CLIENT_SECRET"},
            },
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any(
        "KEYSTONE_MCP_UPSTREAM_" in message and "bearer_env" in message
        for message in exc.value.messages
    )


def test_registry_rejects_bearer_env_colliding_with_keystone_config(permissive_policy):
    """``KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP`` has the right prefix but is

    itself read by ``config.py`` as a non-secret setting; naming it would make
    Keystone send that flag's value as a bearer token."""
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "docs-mcp",
                "url": "https://docs-mcp.example/mcp",
                "namespace": "docs",
                "auth": {"bearer_env": "KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP"},
            },
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any("bearer_env" in message for message in exc.value.messages)


def test_cli_validate_does_not_require_the_env_var(tmp_path: Path, monkeypatch):
    """``keystone-mcp upstream validate`` checks structure, not the real environment."""
    from keystone_mcp.cli import main

    monkeypatch.delenv("KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN", raising=False)
    path = tmp_path / "upstreams.yaml"
    path.write_text(
        textwrap.dedent(
            """
            schema_version: 1
            entries:
              - name: docs-mcp
                url: https://docs-mcp.example/mcp
                namespace: docs
                auth:
                  bearer_env: KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN
            """
        ),
        encoding="utf-8",
    )
    assert main(["upstream", "validate", "--path", str(path)]) == 0


def test_load_refuses_missing_bearer_env(tmp_path: Path, monkeypatch, permissive_policy):
    monkeypatch.delenv("KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN", raising=False)
    path = tmp_path / "upstreams.yaml"
    path.write_text(
        textwrap.dedent(
            """
            schema_version: 1
            entries:
              - name: docs-mcp
                url: https://docs-mcp.example/mcp
                namespace: docs
                auth:
                  bearer_env: KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN"):
        load_upstream_registry_file(path, policy=permissive_policy)


def test_json_upstreams_support_auth(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN", "s3cr3t-value")
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(
            [
                {
                    "name": "docs-mcp",
                    "url": "https://docs-mcp.example/mcp",
                    "namespace": "docs",
                    "auth": {"bearer_env": "KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN"},
                }
            ]
        ),
    )
    settings = load_settings()
    upstreams = settings.upstreams
    assert len(upstreams) == 1
    assert upstreams[0].bearer_env == "KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN"
