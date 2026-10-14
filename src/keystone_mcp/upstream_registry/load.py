"""Load upstream registry files (YAML or JSON) into :class:`UpstreamConfig` tuples."""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

import yaml

from keystone_mcp.config import UpstreamConfig, UpstreamLimits, _parse_prefix_list
from keystone_mcp.identity_assertion import identity_signing_key_from_env, resolve_identity_secret
from keystone_mcp.secrets import read_secret, secret_is_set
from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy
from keystone_mcp.upstream_registry.validate import (
    _normalize_env_shorthand,
    assert_valid_upstream_registry,
    auth_field_errors,
    env_field_errors,
    identity_secret_reuse_errors,
    limits_field_errors,
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


def _parse_auth(
    item: dict[str, Any], *, name: str, transport: str, check_environment: bool = True
) -> tuple[str | None, str | None, Literal["ES256"] | None]:
    """Validate and resolve an entry's optional ``auth.bearer_env``,
    ``auth.identity_secret_env``, and ``auth.identity_alg``.

    Returns ``(bearer_env, identity_secret_env, identity_alg)`` — each the environment
    variable's *name*, never its value, so that
    :class:`~keystone_mcp.config.UpstreamConfig` only ever carries names a
    ``repr()`` can safely print. Raises ``ValueError`` if the ``auth`` field
    is malformed, or — when ``check_environment`` is true — if either named
    variable is unset, empty, or (for ``identity_secret_env``) shorter than
    :data:`~keystone_mcp.identity_assertion.MIN_SECRET_BYTES` bytes. This
    path (unlike
    :func:`keystone_mcp.upstream_registry.validate.validate_upstream_registry`)
    runs with the real process environment, so the check here is what makes
    Keystone refuse to start.

    ``auth.bearer_env`` with ``transport: stdio`` is rejected outright,
    before its environment variable is looked at: there are no HTTP headers
    to carry a bearer token to a child process, so checking whether the
    named variable happens to be set would only produce a confusing "which
    is not set" error instead of the real problem.
    """
    auth = item.get("auth")
    errors = auth_field_errors(auth)
    if errors:
        raise ValueError(f"upstream {name!r}: {errors[0]}")
    if auth is None:
        return None, None, None

    identity_alg: Literal["ES256"] | None = None
    if "identity_alg" in auth:
        raw_alg = auth.get("identity_alg")
        if not isinstance(raw_alg, str) or raw_alg.strip() != "ES256":
            raise ValueError(f"upstream {name!r}: auth.identity_alg must be ES256")
        identity_alg = "ES256"
        if check_environment and identity_signing_key_from_env() is None:
            raise ValueError(
                f"upstream {name!r}: auth.identity_alg ES256 needs KEYSTONE_MCP_IDENTITY_SIGNING_KEY"
            )

    bearer_env: str | None = None
    if "bearer_env" in auth:
        bearer_env = str(auth["bearer_env"]).strip()
        if transport == "stdio":
            raise ValueError(
                f"upstream {name!r}: auth.bearer_env is not supported with transport: stdio"
            )
        if check_environment:
            token = (read_secret(bearer_env) or "").strip()
            if not token:
                raise ValueError(
                    f"upstream {name!r}: auth.bearer_env names {bearer_env}, "
                    "which is not set or empty"
                )

    identity_secret_env: str | None = None
    if "identity_secret_env" in auth:
        if identity_alg is not None:
            raise ValueError(
                f"upstream {name!r}: auth: use either identity_secret_env (HS256) "
                "or identity_alg: ES256"
            )
        identity_secret_env = str(auth["identity_secret_env"]).strip()
        if check_environment:
            # Validates presence and minimum length; the secret value itself
            # is read again (and actually used) by
            # UpstreamRegistry.add_upstream.
            resolve_identity_secret(name, identity_secret_env)

    return bearer_env, identity_secret_env, identity_alg


def _parse_env_from(
    item: dict[str, Any], *, name: str, check_environment: bool
) -> tuple[tuple[str, str], ...]:
    """Validate and resolve a ``transport: stdio`` entry's ``env`` field.

    Returns pairs of (name in the child process, name of the keystone-mcp
    variable supplying it) — never the value. When ``check_environment`` is
    true, also refuses an entry naming a keystone-mcp variable that is not
    set at all (an empty value is accepted: some flags are meant to be set
    but empty).
    """
    env = item.get("env")
    errors = env_field_errors(env)
    if errors:
        raise ValueError(f"upstream {name!r}: {errors[0]}")
    if env is None:
        return ()

    mapping = _normalize_env_shorthand(env)
    assert mapping is not None  # env_field_errors already rejected anything else
    pairs: list[tuple[str, str]] = []
    for child, value in mapping.items():
        var = str(value).strip()
        if check_environment and not secret_is_set(var):
            raise ValueError(f"upstream {name!r}: env.{child} names {var}, which is not set")
        pairs.append((str(child), var))
    return tuple(pairs)


def _parse_limits(item: dict[str, Any], *, name: str) -> UpstreamLimits | None:
    raw = item.get("limits")
    if raw is None:
        return None
    errors = limits_field_errors(raw)
    if errors:
        raise ValueError(f"upstream {name!r}: {errors[0]}")
    assert isinstance(raw, dict)
    window_raw = raw.get("window", 60)
    recovery_raw = raw.get("breaker_recovery_seconds", 30)
    return UpstreamLimits(
        concurrency=raw.get("concurrency"),
        rate=raw.get("rate"),
        window_seconds=float(window_raw),
        breaker_failures=raw.get("breaker_failures"),
        breaker_recovery_seconds=float(recovery_raw),
    )


def parse_upstream_entry(
    item: dict[str, Any],
    *,
    policy: UpstreamSecurityPolicy,
    check_environment: bool = True,
) -> UpstreamConfig:
    """Parse one registry/env entry dict into :class:`UpstreamConfig`."""
    name = str(item.get("name", "")).strip()
    namespace = str(item.get("namespace", "")).strip()
    enabled = _parse_enabled(item.get("enabled", True))

    if not name or not namespace:
        raise ValueError("upstream entries require name and namespace")

    transport_raw = item.get("transport", "http")
    transport = transport_raw.strip() if isinstance(transport_raw, str) else transport_raw
    if transport not in ("http", "stdio"):
        raise ValueError(f"upstream {name!r}: transport must be 'http' or 'stdio'")

    bearer_env, identity_secret_env, identity_alg = _parse_auth(
        item, name=name, transport=transport, check_environment=check_environment
    )

    if transport == "stdio":
        url = ""
        if item.get("url"):
            raise ValueError(f"upstream {name!r}: url is not allowed with transport: stdio")
        # auth.bearer_env with transport: stdio is already rejected by
        # _parse_auth above, before it checks the named variable.

        command_raw = item.get("command")
        command = command_raw.strip() if isinstance(command_raw, str) else ""
        if not command or "\n" in command:
            raise ValueError(f"upstream {name!r}: command is required for transport: stdio")
        if check_environment and shutil.which(command) is None:
            raise ValueError(f"upstream {name!r}: command {command!r} not found or not executable")

        args_raw = item.get("args", [])
        if not (isinstance(args_raw, list) and all(isinstance(a, str) for a in args_raw)):
            raise ValueError(f"upstream {name!r}: args must be an array of strings")
        args = tuple(args_raw)

        cwd_raw = item.get("cwd")
        if cwd_raw is not None and not isinstance(cwd_raw, str):
            raise ValueError(f"upstream {name!r}: cwd must be a string")
        cwd = cwd_raw.strip() or None if isinstance(cwd_raw, str) else None
        if cwd is not None and check_environment and not Path(cwd).is_dir():
            raise ValueError(f"upstream {name!r}: cwd {cwd!r} is not a directory")

        env_from = _parse_env_from(item, name=name, check_environment=check_environment)
    else:
        url = str(item.get("url", "")).strip()
        if not url:
            raise ValueError("upstream entries require name, url, and namespace")

        url_errors = validate_upstream_url(url, policy=policy)
        if url_errors:
            raise ValueError(f"upstream {name!r} url invalid: {url_errors[0]}")

        for field_name in ("command", "args", "env", "cwd"):
            if item.get(field_name) is not None:
                raise ValueError(f"upstream {name!r}: {field_name} requires transport: stdio")
        command = None
        args = ()
        cwd = None
        env_from = ()

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

    publish_resources_raw = item.get("publish_resources", True)
    if not isinstance(publish_resources_raw, bool):
        raise ValueError(f"publish_resources must be a boolean for upstream {name!r}")
    publish_resources = publish_resources_raw

    resource_include_prefixes = _parse_prefix_list(
        item.get("resource_include_prefixes"),
        field_name="resource_include_prefixes",
    )
    resource_exclude_prefixes = _parse_prefix_list(
        item.get("resource_exclude_prefixes"),
        field_name="resource_exclude_prefixes",
    )

    limits = _parse_limits(item, name=name)

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
        identity_alg=identity_alg,
        transport=transport,
        command=command,
        args=args,
        env_from=env_from,
        cwd=cwd,
        publish_resources=publish_resources,
        resource_include_prefixes=resource_include_prefixes,
        resource_exclude_prefixes=resource_exclude_prefixes,
        limits=limits,
    )


def identity_secret_value_warnings(
    upstreams: Sequence[UpstreamConfig],
    environ: Mapping[str, str],
) -> list[str]:
    """Warn when two enabled upstreams share the same HS256 secret value."""
    by_hash: dict[str, list[tuple[str, str]]] = {}
    for cfg in upstreams:
        if not cfg.enabled or not cfg.identity_secret_env:
            continue
        var = cfg.identity_secret_env
        raw = environ.get(var, "")
        if not raw.strip():
            continue
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        by_hash.setdefault(digest, []).append((cfg.name, var))

    warnings: list[str] = []
    for group in by_hash.values():
        if len(group) < 2:
            continue
        vars_seen = {var for _name, var in group}
        if len(vars_seen) < 2:
            continue
        names = ", ".join(sorted(name for name, _var in group))
        var_list = ", ".join(sorted(vars_seen))
        warnings.append(
            f"upstreams {names} use the same HS256 signing secret value "
            f"(variables {var_list}); each can forge identity assertions for "
            "the other — give each upstream its own secret"
        )
    return warnings


def parse_upstream_entries(
    entries: list[Any],
    *,
    policy: UpstreamSecurityPolicy,
    check_environment: bool = True,
) -> tuple[UpstreamConfig, ...]:
    reuse_errors = identity_secret_reuse_errors(entries)
    if reuse_errors:
        raise ValueError(reuse_errors[0])

    upstreams: list[UpstreamConfig] = []
    seen_names: set[str] = set()
    seen_namespaces: set[str] = set()
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("each upstream entry must be an object")
        cfg = parse_upstream_entry(item, policy=policy, check_environment=check_environment)
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
    check_environment: bool = True,
) -> tuple[UpstreamConfig, ...]:
    document = read_registry_document(path)
    if validate:
        assert_valid_upstream_registry(document, policy=policy)
    entries = document.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("entries must be an array")
    return parse_upstream_entries(entries, policy=policy, check_environment=check_environment)
