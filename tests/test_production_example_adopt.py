"""Static checks that ``examples/production`` stays adoptable.

An external installer such as `keystonectl init --adopt
<https://github.com/keystone-codes/keystonectl>`_ recognizes
``examples/production`` by six properties (see
`docs/compatibility.md <../docs/compatibility.md#not-covered>`_ and
`issue #10 <https://github.com/keystone-codes/keystone-mcp/issues/10>`_).
``examples/`` is outside the public compatibility contract, so these tests
exist to make an accidental break visible, not to freeze the example.

No Docker, no `keystonectl`: this module only parses
``examples/production/docker-compose.yml`` with ``yaml.safe_load``.
``${VAR:-default}`` / ``${VAR:?message}`` placeholders are checked as
literal text, never substituted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_DIR = REPO_ROOT / "examples" / "production"
PRODUCTION_COMPOSE = PRODUCTION_DIR / "docker-compose.yml"


def _load_production_compose() -> dict[str, Any]:
    return yaml.safe_load(PRODUCTION_COMPOSE.read_text(encoding="utf-8"))


def _keystone_service(compose: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Return the one service whose image repository ends in ``keystone-mcp``."""
    candidates = [
        (name, body)
        for name, body in compose["services"].items()
        if _image_repository(body.get("image", "")).endswith("keystone-mcp")
    ]
    assert len(candidates) == 1, (
        "expected exactly one service with an image repository ending in "
        f"'keystone-mcp', found {[name for name, _ in candidates]!r}"
    )
    return candidates[0]


def _image_repository(image: str) -> str:
    """Strip a trailing ``:<tag>`` from an image reference, if present."""
    # A registry host portion may itself contain a colon (host:port), so only
    # the last colon-separated segment is a candidate tag.
    repository, _, tag = image.rpartition(":")
    if not repository:
        return image
    # A bare port-looking segment after the last colon is only a tag if it is
    # not part of a "host:port/path" reference without a path component.
    if "/" in tag:
        return image
    return repository


def test_production_example_is_docker_compose_yml_at_root():
    """Property 1: the compose file is ``docker-compose.yml`` at the example root."""
    assert PRODUCTION_COMPOSE.is_file()
    assert PRODUCTION_COMPOSE.parent == PRODUCTION_DIR


def test_production_example_has_exactly_one_keystone_mcp_service():
    """Property 2: exactly one service runs a ``keystone-mcp`` image."""
    compose = _load_production_compose()
    name, body = _keystone_service(compose)

    assert name == "keystone"
    assert body["image"].startswith("ghcr.io/keystone-codes/keystone-mcp:")


def test_production_example_keystone_service_uses_env_file_first():
    """Property 3: that service has ``env_file:`` with ``.env`` as the first entry."""
    compose = _load_production_compose()
    _, body = _keystone_service(compose)

    env_file = body["env_file"]
    first_entry = env_file[0] if isinstance(env_file, list) else env_file
    assert first_entry == ".env"


def test_production_example_registry_and_policy_are_bind_mounted_in_directory():
    """Property 4: registry/policy/catalog-snapshot reach the container through
    bind mounts of paths inside the directory, and no inline, non-empty
    ``KEYSTONE_MCP_UPSTREAMS`` is used instead.
    """
    compose = _load_production_compose()
    _, body = _keystone_service(compose)
    volumes = body.get("volumes", [])

    assert "./policy:/etc/keystone-mcp/policy" in volumes
    assert "./upstreams.yaml:/etc/keystone-mcp/upstreams.yaml:ro" in volumes
    for volume in volumes:
        host_path = volume.split(":", 1)[0]
        assert host_path.startswith("./") or not host_path.startswith("/"), (
            f"expected a bind mount from inside the example directory, got {volume!r}"
        )

    # No inline, non-empty KEYSTONE_MCP_UPSTREAMS: the registry comes from the
    # mounted file via env_file / KEYSTONE_MCP_UPSTREAMS_PATH only.
    inline_env = body.get("environment") or {}
    assert not inline_env.get("KEYSTONE_MCP_UPSTREAMS")


def test_production_example_keystone_service_does_not_join_upstreams_network():
    """Property 5: the service does not already join a network named
    ``keystone-mcp-upstreams`` -- that network is attached by the installer's
    own override file.
    """
    compose = _load_production_compose()
    _, body = _keystone_service(compose)

    networks = body.get("networks", [])
    network_names = networks if isinstance(networks, list) else list(networks)
    assert "keystone-mcp-upstreams" not in network_names


def test_production_example_top_level_name_is_keystone_production():
    """Property 6: the top-level ``name:`` stays ``keystone-production``."""
    compose = _load_production_compose()

    assert compose["name"] == "keystone-production"
