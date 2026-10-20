"""Static checks on the demo compose files and their mounted configuration.

No Docker: these tests only parse YAML with ``yaml.safe_load`` and load the
demo's RBAC policy and upstream registry through the same code paths the
running server uses. ``${VAR:-default}`` / ``${VAR:?message}`` placeholders
are checked as literal text, never substituted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from keystone_mcp.rbac.policy import load_policy_file
from keystone_mcp.upstream_registry.load import load_upstream_registry_file
from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_COMPOSE = REPO_ROOT / "docker-compose.demo.yml"
POSTGRES_OVERLAY = REPO_ROOT / "docker-compose.postgres.yml"
DEMO_POLICY = REPO_ROOT / "examples" / "demo" / "policy" / "rbac-policy.yaml"
DEMO_REGISTRY = REPO_ROOT / "examples" / "demo" / "upstreams.yaml"
PRODUCTION_COMPOSE = REPO_ROOT / "examples" / "production" / "docker-compose.yml"


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _services(*documents: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Merge the ``services`` section of one or more compose documents.

    Mirrors how Compose applies an overlay file: a service present in both
    documents is merged key-by-key, the later (overlay) document winning per
    key, so a key the overlay omits (e.g. ``keystone.healthcheck``, only
    declared in the base file) still shows up for a service-level check.
    """
    merged: dict[str, dict[str, Any]] = {}
    for document in documents:
        for name, body in (document.get("services") or {}).items():
            merged.setdefault(name, {}).update(body or {})
    return merged


def test_demo_publishes_only_keystone_on_loopback():
    demo = _load(DEMO_COMPOSE)
    overlay = _load(POSTGRES_OVERLAY)

    for file_services in (demo["services"], overlay.get("services", {})):
        for name, body in file_services.items():
            ports = body.get("ports")
            if ports is None:
                continue
            assert name == "keystone", f"unexpected published port(s) on service {name!r}"
            assert ports == ["127.0.0.1:8080:8080"]


def test_demo_keystone_env_is_local_profile():
    demo = _load(DEMO_COMPOSE)
    env = demo["services"]["keystone"]["environment"]

    assert env["KEYSTONE_MCP_DEPLOYMENT_PROFILE"] == "local"
    assert env["KEYSTONE_MCP_RBAC_MODE"] == "enforce"
    assert env["KEYSTONE_MCP_BASE_URL"] in ("http://localhost:8080", "http://127.0.0.1:8080")
    assert "${KEYSTONE_DEMO_TOKEN" in env["KEYSTONE_MCP_DEV_TOKENS"]


def test_demo_policy_loads():
    policy = load_policy_file(DEMO_POLICY)

    assert policy.role_names == {"administrator", "member"}
    assert policy.allows_role("member", "hello_greet")
    assert not policy.allows_role("member", "users_list")


def test_demo_hello_uses_identity_secret():
    demo = _load(DEMO_COMPOSE)
    registry = _load(DEMO_REGISTRY)

    hello_entry = next(e for e in registry["entries"] if e["name"] == "hello")
    secret_env = hello_entry["auth"]["identity_secret_env"]
    assert secret_env.startswith("KEYSTONE_MCP_UPSTREAM_")

    keystone_env = demo["services"]["keystone"]["environment"]
    hello_env = demo["services"]["hello-upstream"]["environment"]
    assert secret_env in keystone_env
    assert keystone_env[secret_env] == hello_env["HELLO_IDENTITY_SECRET"]
    assert "${KEYSTONE_DEMO_HELLO_SECRET" in keystone_env[secret_env]
    base_url = keystone_env["KEYSTONE_MCP_BASE_URL"].rstrip("/")
    assert hello_env.get("HELLO_IDENTITY_ISSUER") == base_url


def test_demo_registry_validates(monkeypatch):
    # The "hello" entry's auth.identity_secret_env must resolve to a real
    # value for a (non-strict) load to succeed -- same as at Keystone's own
    # startup; see test_demo_hello_uses_identity_secret for the name itself.
    monkeypatch.setenv("KEYSTONE_MCP_UPSTREAM_HELLO_IDENTITY_SECRET", "x" * 32)

    permissive = UpstreamSecurityPolicy(allow_insecure_http=True, egress_allow_private=False)
    upstreams = load_upstream_registry_file(
        DEMO_REGISTRY, policy=permissive, check_environment=False
    )

    assert len(upstreams) == 2
    assert {u.namespace for u in upstreams} == {"hello", "notes"}

    strict = UpstreamSecurityPolicy(allow_insecure_http=False, egress_allow_private=False)
    try:
        load_upstream_registry_file(DEMO_REGISTRY, policy=strict)
    except ValueError:
        pass
    else:
        raise AssertionError("loading the demo registry without ALLOW_INSECURE_HTTP should fail")


def test_demo_mounts_hello_stdio():
    demo = _load(DEMO_COMPOSE)
    volumes = demo["services"]["keystone"]["volumes"]
    assert "./examples/hello-stdio:/opt/hello-stdio:ro" in volumes


def test_demo_mounts_policy_writable():
    demo = _load(DEMO_COMPOSE)
    env = demo["services"]["keystone"]["environment"]
    volumes = demo["services"]["keystone"]["volumes"]

    assert env["KEYSTONE_MCP_RBAC_POLICY_PATH"] == "/etc/keystone-mcp/policy/rbac-policy.yaml"
    assert "demo-policy:/etc/keystone-mcp/policy" in volumes
    assert demo["services"]["policy-seed"]["volumes"][0] == "demo-policy:/policy"
    assert "./examples/demo/upstreams.yaml:/etc/keystone-mcp/upstreams.yaml:ro" in volumes


def test_production_mounts_policy_writable():
    production = _load(PRODUCTION_COMPOSE)
    volumes = production["services"]["keystone"]["volumes"]

    assert "./policy:/etc/keystone-mcp/policy" in volumes
    assert "./upstreams.yaml:/etc/keystone-mcp/upstreams.yaml:ro" in volumes


def test_demo_services_have_healthchecks():
    demo = _load(DEMO_COMPOSE)
    overlay = _load(POSTGRES_OVERLAY)
    services = _services(demo, overlay)

    assert services, "expected at least one service"
    for name, body in services.items():
        assert "healthcheck" in body, f"service {name!r} has no healthcheck"


def test_postgres_overlay_requires_password():
    overlay = _load(POSTGRES_OVERLAY)
    password = overlay["services"]["postgres"]["environment"]["POSTGRES_PASSWORD"]

    assert password == "${KEYSTONE_PG_PASSWORD:?Set KEYSTONE_PG_PASSWORD}"


def test_production_example_publishes_only_loopback():
    production = _load(PRODUCTION_COMPOSE)

    for name, body in production["services"].items():
        ports = body.get("ports")
        if ports is None:
            continue
        assert name == "keystone", f"unexpected published port(s) on service {name!r}"
        assert ports == ["127.0.0.1:8080:8080"]


def test_production_example_pins_image_tag():
    production = _load(PRODUCTION_COMPOSE)
    image = production["services"]["keystone"]["image"]

    assert ":" in image, f"expected a pinned tag, got {image!r}"
    assert not image.endswith(":latest"), f"production example must not use :latest, got {image!r}"
