"""Load upstream registry files (YAML or JSON) into :class:`UpstreamConfig` tuples."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal

import yaml

from keystone_mcp.config import UpstreamConfig, _parse_prefix_list
from keystone_mcp.identity_assertion import resolve_identity_secret
from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy
from keystone_mcp.upstream_registry.validate import (
    assert_valid_upstream_registry,
    auth_field_errors,
    namespace_errors,
    validate_upstream_url,
)

RouteMode = Literal["live", "stub"]


def _parse_enabled(raw: object) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.lower() in ("1", "true", "yes")
    if isinstance(raw, int):
        return bool(raw)
    return True


def read_registry_document(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        data = yaml.safe_load(raw)
    elif suffix == ".json":
        data = json.loads(raw)
    else:
        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError:
            data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"upstream registry root must be an object: {path}")
    return data


def _parse_auth(item: dict[str, Any], *, name: str) -> tuple[str | None, str | None]:
    """Validate and resolve an entry's optional ``auth.bearer_env`` and
    ``auth.identity_secret_env``.

    Returns ``(bearer_env, identity_secret_env)`` — each the environment
    variable's *name*, never its value, so that
    :class:`~keystone_mcp.config.UpstreamConfig` only ever carries names a
    ``repr()`` can safely print. Raises ``ValueError`` if the ``auth`` field
    is malformed, or if either named variable is unset, empty, or (for
    ``identity_secret_env``) shorter than :data:`~keystone_mcp.
    identity_assertion.MIN_SECRET_BYTES` bytes — this path (unlike
    :func:`keystone_mcp.upstream_registry.validate.validate_upstream_registry`)
    runs with the real process environment, so the check here is what makes
    Keystone refuse to start.
    """
    auth = item.get("auth")
    errors = auth_field_errors(auth)
    if errors:
        raise ValueError(f"upstream {name!r}: {errors[0]}")
    if auth is None:
        return None, None

    bearer_env: str | None = None
    if "bearer_env" in auth:
        bearer_env = str(auth["bearer_env"]).strip()
        if not os.environ.get(bearer_env, "").strip():
            raise ValueError(
                f"upstream {name!r}: auth.bearer_env names {bearer_env}, which is not set or empty"
            )

    identity_secret_env: str | None = None
    if "identity_secret_env" in auth:
        identity_secret_env = str(auth["identity_secret_env"]).strip()
        # Validates presence and minimum length; the secret value itself is
        # read again (and actually used) by UpstreamRegistry.add_upstream.
        resolve_identity_secret(name, identity_secret_env)

    return bearer_env, identity_secret_env


def parse_upstream_entry(item: dict[str, Any], *, policy: UpstreamSecurityPolicy) -> UpstreamConfig:
    """Parse one registry/env entry dict into :class:`UpstreamConfig`."""
    name = str(item.get("name", "")).strip()
    url = str(item.get("url", "")).strip()
    namespace = str(item.get("namespace", "")).strip()
    enabled = _parse_enabled(item.get("enabled", True))

    if not name or not url or not namespace:
        raise ValueError("upstream entries require name, url, and namespace")

    bearer_env, identity_secret_env = _parse_auth(item, name=name)

    url_errors = validate_upstream_url(url, policy=policy)
    if url_errors:
        raise ValueError(f"upstream {name!r} url invalid: {url_errors[0]}")

    tool_prefix = str(item.get("tool_prefix", "")).strip()
    include_prefixes = _parse_prefix_list(
        item.get("include_prefixes"),
        field_name="include_prefixes",
    )
    if tool_prefix:
        include_prefixes = include_prefixes + (tool_prefix,)

    exclude_prefixes = _parse_prefix_list(
        item.get("exclude_prefixes"),
        field_name="exclude_prefixes",
    )
    strip_prefix = str(item.get("strip_prefix", "")).strip() or None
    if tool_prefix and strip_prefix is None:
        strip_prefix = tool_prefix
    if (
        strip_prefix
        and include_prefixes
        and not any(
            strip_prefix.startswith(prefix) or prefix.startswith(strip_prefix)
            for prefix in include_prefixes
        )
    ):
        raise ValueError(
            f"strip_prefix must align with include_prefixes/tool_prefix for upstream {name!r}"
        )

    route_mode_raw = str(item.get("route_mode", "live")).strip() or "live"
    if route_mode_raw not in ("live", "stub"):
        raise ValueError(f"route_mode must be 'live' or 'stub' for upstream {name!r}")

    discovery_timeout = item.get("discovery_timeout_seconds")
    tool_timeout = item.get("tool_timeout_seconds")
    if discovery_timeout is not None:
        if isinstance(discovery_timeout, bool) or not isinstance(discovery_timeout, (int, float)):
            raise ValueError(f"discovery_timeout_seconds must be numeric for upstream {name!r}")
        discovery_timeout = float(discovery_timeout)
    if tool_timeout is not None:
        if isinstance(tool_timeout, bool) or not isinstance(tool_timeout, (int, float)):
            raise ValueError(f"tool_timeout_seconds must be numeric for upstream {name!r}")
        tool_timeout = float(tool_timeout)

    return UpstreamConfig(
        name=name,
        url=url,
        namespace=namespace,
        enabled=enabled,
        include_prefixes=include_prefixes,
        exclude_prefixes=exclude_prefixes,
        strip_prefix=strip_prefix,
        route_mode=route_mode_raw,
        discovery_timeout_seconds=discovery_timeout,
        tool_timeout_seconds=tool_timeout,
        bearer_env=bearer_env,
        identity_secret_env=identity_secret_env,
    )


def parse_upstream_entries(
    entries: list[Any],
    *,
    policy: UpstreamSecurityPolicy,
) -> tuple[UpstreamConfig, ...]:
    upstreams: list[UpstreamConfig] = []
    seen_names: set[str] = set()
    seen_namespaces: set[str] = set()
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("each upstream entry must be an object")
        cfg = parse_upstream_entry(item, policy=policy)
        if cfg.name in seen_names:
            raise ValueError(f"duplicate upstream name: {cfg.name!r}")
        if cfg.namespace in seen_namespaces:
            raise ValueError(f"duplicate upstream namespace: {cfg.namespace!r}")
        seen_names.add(cfg.name)
        seen_namespaces.add(cfg.namespace)
        upstreams.append(cfg)

    ns_errors = namespace_errors([cfg.namespace for cfg in upstreams])
    if ns_errors:
        raise ValueError(ns_errors[0])

    return tuple(upstreams)


def load_upstream_registry_file(
    path: Path,
    *,
    policy: UpstreamSecurityPolicy,
    validate: bool = True,
) -> tuple[UpstreamConfig, ...]:
    document = read_registry_document(path)
    if validate:
        assert_valid_upstream_registry(document, policy=policy)
    entries = document.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("entries must be an array")
    return parse_upstream_entries(entries, policy=policy)
