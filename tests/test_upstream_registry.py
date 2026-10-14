"""Upstream registry loader, validator, and settings integration."""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

from keystone_mcp.config import Settings, load_settings
from keystone_mcp.upstream_registry.load import (
    load_upstream_registry_file,
    parse_upstream_entries,
    parse_upstream_entry,
)
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


# --- upstream identity assertion secret (Y01) ---------------------------------------


def test_registry_accepts_identity_secret_env(monkeypatch, permissive_policy):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET", "x" * 40)
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "docs-mcp",
                "url": "https://docs-mcp.example/mcp",
                "namespace": "docs",
                "auth": {"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET"},
            },
        ],
    }
    assert_valid_upstream_registry(document, policy=permissive_policy)

    cfg = parse_upstream_entry(document["entries"][0], policy=permissive_policy)
    assert cfg.identity_secret_env == "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET"
    assert cfg.bearer_env is None
    assert "x" * 40 not in repr(cfg)


def test_identity_secret_env_must_differ_from_bearer_env(monkeypatch, permissive_policy):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN", "x" * 40)
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "docs-mcp",
                "url": "https://docs-mcp.example/mcp",
                "namespace": "docs",
                "auth": {
                    "bearer_env": "KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN",
                    "identity_secret_env": "KEYSTONE_MCP_UPSTREAM_DOCS_TOKEN",
                },
            },
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any(
        "identity_secret_env must differ from auth.bearer_env" in message
        for message in exc.value.messages
    )


def test_load_refuses_missing_identity_secret(tmp_path: Path, monkeypatch, permissive_policy):
    monkeypatch.delenv("KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET", raising=False)
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
                  identity_secret_env: KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET"):
        load_upstream_registry_file(path, policy=permissive_policy)


def test_load_refuses_short_identity_secret(tmp_path: Path, monkeypatch, permissive_policy):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET", "x" * 31)
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
                  identity_secret_env: KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="at least 32 bytes"):
        load_upstream_registry_file(path, policy=permissive_policy)


def test_cli_validate_does_not_require_identity_secret(tmp_path: Path, monkeypatch):
    """``keystone-mcp upstream validate`` checks structure, not the real environment."""
    from keystone_mcp.cli import main

    monkeypatch.delenv("KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET", raising=False)
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
                  identity_secret_env: KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET
            """
        ),
        encoding="utf-8",
    )
    assert main(["upstream", "validate", "--path", str(path)]) == 0


def test_json_upstreams_support_identity_secret_env(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET", "x" * 40)
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(
            [
                {
                    "name": "docs-mcp",
                    "url": "https://docs-mcp.example/mcp",
                    "namespace": "docs",
                    "auth": {
                        "identity_secret_env": "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET",
                    },
                }
            ]
        ),
    )
    settings = load_settings()
    upstreams = settings.upstreams
    assert len(upstreams) == 1
    assert upstreams[0].identity_secret_env == "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET"


def test_identity_secret_env_must_be_unique_across_entries(
    tmp_path: Path, monkeypatch, permissive_policy
):
    """Two upstreams declaring the same ``auth.identity_secret_env`` would let

    whichever one is compromised forge an assertion with the other's ``aud``.
    """
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_SHARED_IDENTITY_SECRET", "x" * 40)
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "docs-mcp",
                "url": "https://docs-mcp.example/mcp",
                "namespace": "docs",
                "auth": {"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_SHARED_IDENTITY_SECRET"},
            },
            {
                "name": "notes-mcp",
                "url": "https://notes-mcp.example/mcp",
                "namespace": "notes",
                "auth": {"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_SHARED_IDENTITY_SECRET"},
            },
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any(
        "entries[1].auth.identity_secret_env reuses the signing secret" in m
        for m in exc.value.messages
    )

    with pytest.raises(ValueError, match="reuses the signing secret"):
        load_upstream_registry_file(
            _write_registry_json(tmp_path, document), policy=permissive_policy
        )

    # Also exercised directly: KEYSTONE_MCP_UPSTREAMS (JSON env var) parses
    # entries via parse_upstream_entries without going through
    # assert_valid_upstream_registry at all (config._parse_upstreams_json).
    with pytest.raises(ValueError, match="reuses the signing secret"):
        parse_upstream_entries(document["entries"], policy=permissive_policy)


def test_bearer_env_must_not_reuse_foreign_identity_secret_env(
    tmp_path: Path, monkeypatch, permissive_policy
):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET", "x" * 40)
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN_UNUSED", "y" * 40)
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "docs-mcp",
                "url": "https://docs-mcp.example/mcp",
                "namespace": "docs",
                "auth": {"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET"},
            },
            {
                "name": "notes-mcp",
                "url": "https://notes-mcp.example/mcp",
                "namespace": "notes",
                # Same variable as docs-mcp's signing secret: notes-mcp would
                # receive it verbatim as its own Authorization: Bearer value.
                "auth": {"bearer_env": "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET"},
            },
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any(
        "entries[1].auth.bearer_env must not name the identity signing secret" in m
        for m in exc.value.messages
    )

    with pytest.raises(ValueError, match="auth.bearer_env must not name the identity signing"):
        load_upstream_registry_file(
            _write_registry_json(tmp_path, document), policy=permissive_policy
        )

    with pytest.raises(ValueError, match="auth.bearer_env must not name the identity signing"):
        parse_upstream_entries(document["entries"], policy=permissive_policy)


def test_stdio_env_must_not_reuse_foreign_identity_secret_env(
    tmp_path: Path, monkeypatch, permissive_policy
):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET", "x" * 40)
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "docs-mcp",
                "url": "https://docs-mcp.example/mcp",
                "namespace": "docs",
                "auth": {"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET"},
            },
            {
                "name": "notes",
                "namespace": "notes",
                "transport": "stdio",
                "command": "python",
                # notes's child process would receive docs-mcp's signing
                # secret verbatim as its own NOTES_TOKEN.
                "env": {"NOTES_TOKEN": "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET"},
            },
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any(
        "entries[1].env.NOTES_TOKEN must not name the identity signing secret" in m
        for m in exc.value.messages
    )

    with pytest.raises(ValueError, match="env.NOTES_TOKEN must not name the identity signing"):
        load_upstream_registry_file(
            _write_registry_json(tmp_path, document), policy=permissive_policy
        )

    with pytest.raises(ValueError, match="env.NOTES_TOKEN must not name the identity signing"):
        parse_upstream_entries(
            document["entries"], policy=permissive_policy, check_environment=False
        )


def test_stdio_entry_may_name_its_own_identity_secret_in_env(monkeypatch, permissive_policy):
    """The one allowed exception: a stdio process reading its own signing

    secret through ``env`` (e.g. to verify inbound assertions itself), not a
    foreign one.
    """
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET", "x" * 40)
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "notes",
                "namespace": "notes",
                "transport": "stdio",
                "command": "python",
                "env": {"NOTES_IDENTITY_SECRET": "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET"},
                "auth": {"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET"},
            },
        ],
    }
    assert_valid_upstream_registry(document, policy=permissive_policy)

    cfg = parse_upstream_entry(
        document["entries"][0], policy=permissive_policy, check_environment=False
    )
    assert cfg.identity_secret_env == "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET"
    assert cfg.env_from == (
        ("NOTES_IDENTITY_SECRET", "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET"),
    )


def _write_registry_json(tmp_path: Path, document: dict) -> Path:
    path = tmp_path / "upstreams.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


# --- transport: stdio (Y08) --------------------------------------------------------


def test_stdio_entry_is_accepted(permissive_policy):
    # Also covers the Y01/Y08 merge point: a stdio entry with
    # auth.identity_secret_env is accepted like any other.
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "notes",
                "namespace": "notes",
                "transport": "stdio",
                "command": "python",
                "args": ["server.py", "--root", "/srv/notes"],
                "env": {"NOTES_API_TOKEN": "KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN"},
                "cwd": "/opt/notes-mcp",
                "auth": {"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET"},
            }
        ],
    }
    assert_valid_upstream_registry(document, policy=permissive_policy)

    cfg = parse_upstream_entry(
        document["entries"][0], policy=permissive_policy, check_environment=False
    )
    assert cfg.transport == "stdio"
    assert cfg.url == ""
    assert cfg.bearer_env is None
    assert cfg.command == "python"
    assert cfg.args == ("server.py", "--root", "/srv/notes")
    assert cfg.env_from == (("NOTES_API_TOKEN", "KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN"),)
    assert cfg.cwd == "/opt/notes-mcp"
    assert cfg.identity_secret_env == "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET"


def test_check_environment_false_skips_runtime_checks(tmp_path: Path, permissive_policy):
    item = {
        "name": "notes",
        "namespace": "notes",
        "transport": "stdio",
        "command": "this-command-does-not-exist-anywhere",
        "env": {"NOTES_API_TOKEN": "KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN"},
        "cwd": str(tmp_path / "missing-dir"),
    }
    cfg = parse_upstream_entry(item, policy=permissive_policy, check_environment=False)
    assert cfg.command == "this-command-does-not-exist-anywhere"

    with pytest.raises(ValueError, match="is not a directory"):
        parse_upstream_entry(item, policy=permissive_policy, check_environment=True)

    item_valid_cwd = {**item, "cwd": str(tmp_path)}
    with pytest.raises(ValueError, match="not found or not executable"):
        parse_upstream_entry(item_valid_cwd, policy=permissive_policy, check_environment=True)


def test_stdio_rejects_url(permissive_policy):
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "notes",
                "namespace": "notes",
                "transport": "stdio",
                "command": "python",
                "url": "https://example.com/mcp",
            }
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any("url is not allowed with transport: stdio" in m for m in exc.value.messages)

    with pytest.raises(ValueError, match="url is not allowed with transport: stdio"):
        parse_upstream_entry(
            document["entries"][0], policy=permissive_policy, check_environment=False
        )


def test_http_rejects_command(permissive_policy):
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "docs-mcp",
                "namespace": "docs",
                "url": "https://docs-mcp.example/mcp",
                "command": "python",
            }
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any("command requires transport: stdio" in m for m in exc.value.messages)

    with pytest.raises(ValueError, match="command requires transport: stdio"):
        parse_upstream_entry(document["entries"][0], policy=permissive_policy)


def test_stdio_rejects_bearer_env(permissive_policy):
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "notes",
                "namespace": "notes",
                "transport": "stdio",
                "command": "python",
                "auth": {"bearer_env": "KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN"},
            }
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any(
        "auth.bearer_env is not supported with transport: stdio" in m for m in exc.value.messages
    )

    with pytest.raises(ValueError, match="auth.bearer_env is not supported with transport: stdio"):
        parse_upstream_entry(
            document["entries"][0], policy=permissive_policy, check_environment=False
        )


def test_env_value_must_be_variable_name(permissive_policy):
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "notes",
                "namespace": "notes",
                "transport": "stdio",
                "command": "python",
                "env": {"NOTES_API_TOKEN": "s3cr3t value"},
            }
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any(
        "env.NOTES_API_TOKEN must name an environment variable of keystone-mcp" in m
        for m in exc.value.messages
    )


def test_env_list_shorthand(permissive_policy):
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "notes",
                "namespace": "notes",
                "transport": "stdio",
                "command": "python",
                "env": ["KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN"],
            }
        ],
    }
    assert_valid_upstream_registry(document, policy=permissive_policy)

    cfg = parse_upstream_entry(
        document["entries"][0], policy=permissive_policy, check_environment=False
    )
    assert cfg.env_from == (
        ("KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN", "KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN"),
    )


def test_stdio_relative_command_is_resolved_against_cwd(
    tmp_path: Path, permissive_policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    svc = tmp_path / "svc"
    svc.mkdir()
    run_sh = svc / "run.sh"
    run_sh.write_text("#!/bin/sh\n", encoding="utf-8")
    run_sh.chmod(0o755)

    other = tmp_path / "other"
    other.mkdir()
    decoy = other / "run.sh"
    decoy.write_text("#!/bin/sh\n", encoding="utf-8")
    decoy.chmod(0o755)
    monkeypatch.chdir(other)

    item = {
        "name": "notes",
        "namespace": "notes",
        "transport": "stdio",
        "command": "./run.sh",
        "cwd": str(svc),
    }
    cfg = parse_upstream_entry(item, policy=permissive_policy, check_environment=True)
    assert cfg.command == "./run.sh"
    assert cfg.cwd == str(svc)


def test_stdio_relative_command_missing_in_cwd_is_refused(
    tmp_path: Path, permissive_policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    svc = tmp_path / "svc"
    svc.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    decoy = other / "run.sh"
    decoy.write_text("#!/bin/sh\n", encoding="utf-8")
    decoy.chmod(0o755)
    monkeypatch.chdir(other)

    item = {
        "name": "notes",
        "namespace": "notes",
        "transport": "stdio",
        "command": "./run.sh",
        "cwd": str(svc),
    }
    with pytest.raises(ValueError, match="not found or not executable"):
        parse_upstream_entry(item, policy=permissive_policy, check_environment=True)
    with pytest.raises(ValueError, match="resolved against cwd"):
        parse_upstream_entry(item, policy=permissive_policy, check_environment=True)


def test_load_refuses_unknown_command(tmp_path: Path, permissive_policy):
    path = tmp_path / "upstreams.yaml"
    path.write_text(
        textwrap.dedent(
            """
            schema_version: 1
            entries:
              - name: notes
                namespace: notes
                transport: stdio
                command: this-command-does-not-exist-anywhere
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not found or not executable"):
        load_upstream_registry_file(path, policy=permissive_policy)


def test_load_refuses_missing_env_variable(tmp_path: Path, monkeypatch, permissive_policy):
    monkeypatch.delenv("KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN", raising=False)
    path = tmp_path / "upstreams.yaml"
    path.write_text(
        textwrap.dedent(
            f"""
            schema_version: 1
            entries:
              - name: notes
                namespace: notes
                transport: stdio
                command: {sys.executable}
                env:
                  NOTES_API_TOKEN: KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN"):
        load_upstream_registry_file(path, policy=permissive_policy)


def test_load_refuses_missing_cwd(tmp_path: Path, permissive_policy):
    missing = tmp_path / "does-not-exist"
    path = tmp_path / "upstreams.yaml"
    path.write_text(
        textwrap.dedent(
            f"""
            schema_version: 1
            entries:
              - name: notes
                namespace: notes
                transport: stdio
                command: {sys.executable}
                cwd: {missing}
            """
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="is not a directory"):
        load_upstream_registry_file(path, policy=permissive_policy)


def test_cli_validate_does_not_check_command_or_env(tmp_path: Path, monkeypatch):
    from keystone_mcp.cli import main

    monkeypatch.delenv("KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN", raising=False)
    path = tmp_path / "upstreams.yaml"
    path.write_text(
        textwrap.dedent(
            """
            schema_version: 1
            entries:
              - name: notes
                namespace: notes
                transport: stdio
                command: this-command-does-not-exist-anywhere
                env:
                  NOTES_API_TOKEN: KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN
            """
        ),
        encoding="utf-8",
    )
    assert main(["upstream", "validate", "--path", str(path)]) == 0


def test_json_upstreams_support_stdio(monkeypatch):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN", "whatever")
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(
            [
                {
                    "name": "notes",
                    "namespace": "notes",
                    "transport": "stdio",
                    "command": sys.executable,
                    "env": {"NOTES_API_TOKEN": "KEYSTONE_MCP_UPSTREAM_NOTES_TOKEN"},
                }
            ]
        ),
    )
    settings = load_settings()
    upstreams = settings.upstreams
    assert len(upstreams) == 1
    assert upstreams[0].transport == "stdio"
    assert upstreams[0].command == sys.executable


def test_existing_http_entries_unchanged(permissive_policy):
    cfg = parse_upstream_entry(
        {"name": "svc", "url": "http://svc:8081/mcp", "namespace": "svc"},
        policy=permissive_policy,
    )
    assert cfg.transport == "http"
    assert cfg.command is None
    assert cfg.args == ()
    assert cfg.env_from == ()
    assert cfg.cwd is None


_SHARED_HS256 = "shared-hs256-secret-for-w30-test---" + "s" * 8


def test_same_hs256_value_under_two_variables_warns(permissive_policy):
    from keystone_mcp.config import UpstreamConfig
    from keystone_mcp.upstream_registry.load import identity_secret_value_warnings

    upstreams = (
        UpstreamConfig(
            name="docs-mcp",
            url="http://docs:8081/mcp",
            namespace="docs",
            identity_secret_env="KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET",
        ),
        UpstreamConfig(
            name="notes-mcp",
            url="http://notes:8081/mcp",
            namespace="notes",
            identity_secret_env="KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET",
        ),
    )
    environ = {
        "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET": _SHARED_HS256,
        "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET": _SHARED_HS256,
    }
    warnings = identity_secret_value_warnings(upstreams, environ)
    assert len(warnings) == 1
    line = warnings[0]
    assert "docs-mcp" in line and "notes-mcp" in line
    assert "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET" in line
    assert "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET" in line
    assert _SHARED_HS256 not in line


def test_distinct_values_no_warning(permissive_policy):
    from keystone_mcp.config import UpstreamConfig
    from keystone_mcp.upstream_registry.load import identity_secret_value_warnings

    upstreams = (
        UpstreamConfig(
            name="docs-mcp",
            url="http://docs:8081/mcp",
            namespace="docs",
            identity_secret_env="KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET",
        ),
        UpstreamConfig(
            name="notes-mcp",
            url="http://notes:8081/mcp",
            namespace="notes",
            identity_secret_env="KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET",
        ),
    )
    environ = {
        "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET": _SHARED_HS256,
        "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET": "another-distinct-secret-value-" + "x" * 8,
    }
    assert identity_secret_value_warnings(upstreams, environ) == []


def test_disabled_entry_ignored(permissive_policy):
    from keystone_mcp.config import UpstreamConfig
    from keystone_mcp.upstream_registry.load import identity_secret_value_warnings

    upstreams = (
        UpstreamConfig(
            name="docs-mcp",
            url="http://docs:8081/mcp",
            namespace="docs",
            enabled=False,
            identity_secret_env="KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET",
        ),
        UpstreamConfig(
            name="notes-mcp",
            url="http://notes:8081/mcp",
            namespace="notes",
            identity_secret_env="KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET",
        ),
    )
    environ = {
        "KEYSTONE_MCP_UPSTREAM_DOCS_IDENTITY_SECRET": _SHARED_HS256,
        "KEYSTONE_MCP_UPSTREAM_NOTES_IDENTITY_SECRET": _SHARED_HS256,
    }
    assert identity_secret_value_warnings(upstreams, environ) == []


def test_same_variable_name_still_refused(tmp_path: Path, monkeypatch, permissive_policy):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_SHARED_IDENTITY_SECRET", _SHARED_HS256)
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "docs-mcp",
                "url": "https://docs-mcp.example/mcp",
                "namespace": "docs",
                "auth": {"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_SHARED_IDENTITY_SECRET"},
            },
            {
                "name": "notes-mcp",
                "url": "https://notes-mcp.example/mcp",
                "namespace": "notes",
                "auth": {"identity_secret_env": "KEYSTONE_MCP_UPSTREAM_SHARED_IDENTITY_SECRET"},
            },
        ],
    }
    with pytest.raises(ValueError, match="reuses the signing secret"):
        parse_upstream_entries(document["entries"], policy=permissive_policy)


def test_limits_valid(permissive_policy):
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "billing",
                "url": "http://127.0.0.1/mcp",
                "namespace": "billing",
                "limits": {
                    "concurrency": 4,
                    "rate": 600,
                    "window": 60,
                    "breaker_failures": 5,
                    "breaker_recovery_seconds": 30,
                },
            },
        ],
    }
    assert_valid_upstream_registry(document, policy=permissive_policy)
    cfg = parse_upstream_entry(document["entries"][0], policy=permissive_policy)
    assert cfg.limits is not None
    assert cfg.limits.concurrency == 4
    assert cfg.limits.rate == 600


def test_limits_unknown_key_rejected(permissive_policy):
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "billing",
                "url": "http://127.0.0.1/mcp",
                "namespace": "billing",
                "limits": {"concurrency": 2, "burst": 1},
            },
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any("limits.burst is not supported" in message for message in exc.value.messages)


def test_limits_non_positive_rejected(permissive_policy):
    document = {
        "schema_version": 1,
        "entries": [
            {
                "name": "billing",
                "url": "http://127.0.0.1/mcp",
                "namespace": "billing",
                "limits": {"rate": 0},
            },
        ],
    }
    with pytest.raises(ValidationError) as exc:
        assert_valid_upstream_registry(document, policy=permissive_policy)
    assert any(
        "limits.rate must be a positive integer" in message for message in exc.value.messages
    )


def test_limits_in_upstreams_env_json(monkeypatch, permissive_policy):
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP", "true")
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE", "true")
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps(
            [
                {
                    "name": "billing",
                    "url": "http://127.0.0.1/mcp",
                    "namespace": "billing",
                    "limits": {"rate": 10, "window": 30},
                }
            ]
        ),
    )
    payload = json.loads(
        '{"name": "billing", "url": "http://127.0.0.1/mcp", "namespace": "billing", '
        '"limits": {"rate": 10, "window": 30}}'
    )
    upstreams = parse_upstream_entries([payload], policy=permissive_policy)
    assert len(upstreams) == 1
    assert upstreams[0].limits is not None
    assert upstreams[0].limits.rate == 10
    assert upstreams[0].limits.window_seconds == 30.0


def test_upstream_validate_cli_reports_limits_error(tmp_path: Path):
    from keystone_mcp.cli import main

    path = tmp_path / "upstreams.yaml"
    path.write_text(
        textwrap.dedent(
            """
            schema_version: 1
            entries:
              - name: billing
                url: http://127.0.0.1/mcp
                namespace: billing
                limits:
                  rate: -1
            """
        ),
        encoding="utf-8",
    )
    assert main(["upstream", "validate", "--path", str(path)]) == 1


def _hello_json_entry(**overrides: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "name": "hello-mcp",
        "url": "https://hello.example/mcp",
        "namespace": "hello",
    }
    entry.update(overrides)
    return entry


def test_json_upstreams_reject_zero_tool_timeout(monkeypatch):
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps([_hello_json_entry(tool_timeout_seconds=0)]),
    )
    with pytest.raises(ValueError, match=r"^KEYSTONE_MCP_UPSTREAMS:"):
        _ = Settings(base_url="http://127.0.0.1:8080").upstreams


def test_json_upstreams_reject_zero_discovery_timeout(monkeypatch):
    monkeypatch.setenv(
        "KEYSTONE_MCP_UPSTREAMS",
        json.dumps([_hello_json_entry(discovery_timeout_seconds=0)]),
    )
    with pytest.raises(ValueError, match=r"^KEYSTONE_MCP_UPSTREAMS:"):
        _ = Settings(base_url="http://127.0.0.1:8080").upstreams


def test_json_upstreams_over_64_entries_warn(monkeypatch, caplog):
    entries = [
        {
            "name": f"svc-{index}",
            "url": f"https://svc-{index}.example/mcp",
            "namespace": f"ns{index}",
        }
        for index in range(65)
    ]
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAMS", json.dumps(entries))
    import logging

    caplog.set_level(logging.WARNING)
    settings = Settings(base_url="http://127.0.0.1:8080")
    assert len(settings.upstreams) == 65
    assert any(
        "KEYSTONE_MCP_UPSTREAMS: entries must contain at most" in record.message
        for record in caplog.records
    )
