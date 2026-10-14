"""Security-focused validation for upstream registry URLs and entries."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy

MAX_REGISTRY_ENTRIES = 64

#: Entry ``auth`` keys that name a secret directly; these are rejected with a
#: message pointing at ``auth.bearer_env`` instead of the generic
#: "not supported" message other unknown keys get.
_SECRET_LIKE_AUTH_KEYS = frozenset({"token", "bearer", "secret", "password"})

#: ``auth`` keys that name an environment variable (never a secret value
#: itself) and are validated identically: an optional, independent
#: ``KEYSTONE_MCP_UPSTREAM_*`` name. An entry may set neither, either, or
#: both.
_AUTH_ENV_NAME_KEYS = frozenset({"bearer_env", "identity_secret_env"})

#: Non-secret ``auth`` keys (``identity_alg``).
_AUTH_PLAIN_KEYS = frozenset({"identity_alg"})

#: ``auth.bearer_env`` (and, identically, ``auth.identity_secret_env``) must
#: look like a shell environment variable name AND live under this reserved
#: prefix. Without this, a registry entry could name *any* environment
#: variable -- e.g. `bearer_env: KEYSTONE_MCP_GOOGLE_CLIENT_SECRET` -- with a
#: matching ``url`` -- and Keystone would send that secret to the entry's
#: upstream as a bearer token, or sign identity assertions with it. Requiring
#: the prefix means the only variables an entry can ever name are ones an
#: operator deliberately created for this purpose.
_BEARER_ENV_PREFIX = "KEYSTONE_MCP_UPSTREAM_"
_BEARER_ENV_RE = re.compile(rf"^{re.escape(_BEARER_ENV_PREFIX)}[A-Z0-9_]+$")

#: Exact names already read by ``src/keystone_mcp/config.py`` as Keystone's
#: own (non-secret) settings. These happen to share ``_BEARER_ENV_PREFIX``, so
#: the prefix check alone would accept them; naming one in ``bearer_env``
#: would send that setting's value (not a token) as `Authorization: Bearer
#: <value>`, silently breaking that setting's own meaning. Kept in sync by
#: hand with ``config.py``; a new ``KEYSTONE_MCP_UPSTREAM_*`` setting added
#: there must be added here too.
_RESERVED_BEARER_ENV_NAMES = frozenset(
    {
        "KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP",
        "KEYSTONE_MCP_UPSTREAM_DISCOVERY_RETRIES",
        "KEYSTONE_MCP_UPSTREAM_DISCOVERY_TIMEOUT",
        "KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE",
        "KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL",
        "KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS",
        "KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUT_SECONDS",
        "KEYSTONE_MCP_UPSTREAM_MAX_RESPONSE_BYTES",
        "KEYSTONE_MCP_UPSTREAM_MAX_SCHEMA_BYTES",
        "KEYSTONE_MCP_UPSTREAM_MAX_CATALOG_ITEMS",
    }
)

_PRIVATE_HOSTNAMES = frozenset({"localhost"})

#: 1-64 chars, A-Z/a-z/0-9/_/-, not starting or ending with '_' or '-'.
_NAMESPACE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9])?$")

#: Fields only meaningful for ``transport: stdio`` entries; forbidden
#: with ``transport: http`` (the default).
_STDIO_ONLY_FIELDS = ("command", "args", "env", "cwd")

#: A name in the child process's own environment, set by ``env`` in a
#: ``transport: stdio`` entry — e.g. ``GITHUB_TOKEN``. Distinct from the name
#: of the keystone-mcp variable that supplies its value, which is checked the
#: same way as ``auth.bearer_env`` (see ``_BEARER_ENV_RE`` above).
_ENV_CHILD_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


class ValidationError(ValueError):
    """One or more upstream registry validation failures."""

    def __init__(self, messages: list[str]) -> None:
        self.messages = list(messages)
        super().__init__("\n".join(self.messages))


@dataclass(frozen=True, slots=True)
class _HostClassification:
    is_literal_ip: bool
    is_private_or_local: bool


def _host_looks_like_ip_literal(host: str) -> bool:
    """True when the host is plausibly an IP literal (including non-canonical forms)."""
    lowered = host.strip().lower().rstrip(".")
    if not lowered:
        return False
    if lowered.startswith("0x"):
        return True
    if lowered.isdigit():
        return True
    if ":" in lowered:
        return True
    if "." in lowered:
        parts = lowered.split(".")
        if parts and all(part.isdigit() or part.startswith("0x") for part in parts):
            return True
    return False


def _parse_canonical_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip().lower().rstrip("."))
    except ValueError:
        return None


def _is_private_or_local_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )


def _classify_host(host: str) -> _HostClassification:
    lowered = host.strip().lower().rstrip(".")
    if lowered in _PRIVATE_HOSTNAMES or lowered.endswith(".localhost"):
        return _HostClassification(is_literal_ip=False, is_private_or_local=True)
    if lowered.endswith(".local") or lowered.endswith(".internal"):
        return _HostClassification(is_literal_ip=False, is_private_or_local=True)

    if _host_looks_like_ip_literal(lowered):
        addr = _parse_canonical_ip(lowered)
        if addr is None:
            # Reject forms like 2130706433 or 10.000.000.001 that libc may map to
            # loopback/private addresses but stdlib ip_address does not accept.
            return _HostClassification(is_literal_ip=True, is_private_or_local=True)
        return _HostClassification(
            is_literal_ip=True,
            is_private_or_local=_is_private_or_local_ip(addr),
        )

    return _HostClassification(is_literal_ip=False, is_private_or_local=False)


def validate_upstream_url(url: str, *, policy: UpstreamSecurityPolicy) -> list[str]:
    """Return human-readable errors for ``url``; empty list means OK."""
    errors: list[str] = []
    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        errors.append(f"url must use http or https scheme (got {scheme or 'missing'!r})")
        return errors

    if scheme == "http" and not policy.allow_insecure_http:
        errors.append("http URLs require KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP=true")

    if parsed.username or parsed.password:
        errors.append("url must not include userinfo (user:pass@host)")

    host = parsed.hostname
    if not host:
        errors.append("url must include a host")
        return errors

    host_info = _classify_host(host)
    if (
        host_info.is_literal_ip
        and _host_looks_like_ip_literal(host)
        and _parse_canonical_ip(host) is None
    ):
        errors.append("url host must use canonical IPv4 or IPv6 address notation")
    elif host_info.is_private_or_local:
        if not (policy.allow_insecure_http and policy.egress_allow_private):
            errors.append(
                "private, loopback, or link-local upstream hosts require "
                "KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP=true and "
                "KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE=true"
            )

    if not parsed.path or parsed.path == "/":
        errors.append("url should include a path (e.g. /mcp)")

    return errors


def auth_field_errors(auth: Any) -> list[str]:
    """Structural errors for one entry's optional ``auth`` field.

    Messages are not prefixed with the entry index; callers that report
    per-entry errors (:func:`validate_upstream_registry`) prepend
    ``entries[i].`` themselves, callers that report per-name errors
    (:func:`keystone_mcp.upstream_registry.load.parse_upstream_entry`) prepend
    the upstream name instead.

    Never checks whether the named environment variable is actually set:
    ``keystone-mcp upstream validate`` runs on machines that do not hold the
    service's secrets.
    """
    if auth is None:
        return []
    if not isinstance(auth, dict):
        return ["auth must be an object"]

    errors: list[str] = []
    for key in auth:
        if key in _AUTH_ENV_NAME_KEYS or key in _AUTH_PLAIN_KEYS:
            continue
        if key in _SECRET_LIKE_AUTH_KEYS:
            errors.append(
                f"auth.{key}: secrets must not be stored in the registry; "
                "use auth.bearer_env with the name of an environment variable"
            )
        else:
            errors.append(f"auth.{key} is not supported")

    for key in _AUTH_ENV_NAME_KEYS:
        errors.extend(_auth_env_name_errors(auth, key))

    identity_alg = auth.get("identity_alg")
    if identity_alg is not None:
        if not isinstance(identity_alg, str) or identity_alg.strip() != "ES256":
            errors.append("auth.identity_alg must be ES256")
        elif "identity_secret_env" in auth:
            errors.append("auth: use either identity_secret_env (HS256) or identity_alg: ES256")

    bearer_env = auth.get("bearer_env")
    identity_secret_env = auth.get("identity_secret_env")
    if (
        isinstance(bearer_env, str)
        and isinstance(identity_secret_env, str)
        and bearer_env.strip()
        and bearer_env.strip() == identity_secret_env.strip()
    ):
        errors.append("auth.identity_secret_env must differ from auth.bearer_env")

    return errors


_LIMITS_KEYS = frozenset(
    {
        "concurrency",
        "rate",
        "window",
        "breaker_failures",
        "breaker_recovery_seconds",
    }
)


def limits_field_errors(limits: Any) -> list[str]:
    """Structural errors for one entry's optional ``limits`` field."""
    if limits is None:
        return []
    if not isinstance(limits, dict):
        return ["limits must be an object"]

    errors: list[str] = []
    for key in limits:
        if key not in _LIMITS_KEYS:
            errors.append(f"limits.{key} is not supported")

    for key in ("concurrency", "rate", "breaker_failures"):
        raw = limits.get(key)
        if raw is None:
            continue
        if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
            errors.append(f"limits.{key} must be a positive integer")

    for key in ("window", "breaker_recovery_seconds"):
        raw = limits.get(key)
        if raw is None:
            continue
        if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw <= 0:
            errors.append(f"limits.{key} must be a positive number")

    return errors


def _auth_env_name_errors(auth: dict[str, Any], key: str) -> list[str]:
    """Structural errors for one optional ``auth.<key>`` environment-variable name.

    ``key`` absent entirely is not an error -- both ``bearer_env`` and
    ``identity_secret_env`` are independently optional (an entry may set
    neither, either, or both).
    """
    if key not in auth:
        return []
    raw = auth.get(key)
    candidate = raw.strip() if isinstance(raw, str) else ""
    if not candidate or not _BEARER_ENV_RE.match(candidate):
        return [
            f"auth.{key} must be an environment variable name starting with "
            f"{_BEARER_ENV_PREFIX!r} (A-Z, 0-9, _ after the prefix)"
        ]
    if candidate in _RESERVED_BEARER_ENV_NAMES:
        return [
            f"auth.{key} must not name {candidate!r}: keystone-mcp's own "
            "configuration already reads that variable for a different purpose"
        ]
    return []


def _normalize_env_shorthand(env: Any) -> dict[Any, Any] | None:
    """Expand the ``env: [NAME, ...]`` shorthand to ``{NAME: NAME, ...}``.

    Returns ``None`` when ``env`` is neither a mapping nor a list of strings
    (a structural error the caller reports).
    """
    if isinstance(env, dict):
        return env
    if isinstance(env, list) and all(isinstance(item, str) for item in env):
        return {name: name for name in env}
    return None


def env_field_errors(env: Any) -> list[str]:
    """Structural errors for one ``transport: stdio`` entry's ``env`` field.

    ``env`` maps a name in the child process's environment to the name of the
    keystone-mcp environment variable that supplies its value (never the
    value itself — same rule as ``auth.bearer_env``), or is the shorthand list
    form ``[NAME, ...]`` equivalent to ``{NAME: NAME, ...}``. Messages are not
    prefixed with ``entries[i].``; see :func:`auth_field_errors`.
    """
    if env is None:
        return []
    mapping = _normalize_env_shorthand(env)
    if mapping is None:
        return ["env must be an object, or an array of environment variable names"]

    errors: list[str] = []
    for child, value in mapping.items():
        child_name = child if isinstance(child, str) else str(child)
        if not isinstance(child, str) or not _ENV_CHILD_NAME_RE.match(child_name):
            errors.append(
                f"env.{child_name} is not a valid environment variable name (A-Z, 0-9, _)"
            )
            continue
        candidate = value.strip() if isinstance(value, str) else ""
        if not candidate or not _BEARER_ENV_RE.match(candidate):
            errors.append(
                f"env.{child_name} must name an environment variable of keystone-mcp (A-Z, 0-9, _)"
            )
        elif candidate in _RESERVED_BEARER_ENV_NAMES:
            errors.append(
                f"env.{child_name} must not name {candidate!r}: keystone-mcp's own "
                "configuration already reads that variable for a different purpose"
            )

    return errors


def identity_secret_reuse_errors(entries: Sequence[Any]) -> list[str]:
    """Structural errors when a signing secret named by one entry's
    ``auth.identity_secret_env`` is reachable from any other entry.

    Every name that appears as some entry's ``auth.identity_secret_env``
    must occur exactly once in the whole registry -- as that entry's
    ``auth.identity_secret_env``, as any entry's ``auth.bearer_env``, or as
    any ``transport: stdio`` entry's ``env`` value. Without this, two
    entries could point at the same environment variable through different
    fields (one's ``auth.bearer_env`` naming another's
    ``auth.identity_secret_env``, or a stdio entry's ``env`` naming a
    foreign upstream's signing secret) and the upstream holding that value
    could forge an ``X-Keystone-Identity`` assertion with someone else's
    ``aud`` (D5) -- exactly what "one secret per upstream" exists to
    prevent.

    The one exception: a stdio entry's own ``env`` naming its own
    ``identity_secret_env`` is not reuse -- that process needs the secret
    itself to verify inbound assertions (D8), not to impersonate anyone.

    Operates on raw entry dicts (as loaded from YAML/JSON, before
    :func:`~keystone_mcp.upstream_registry.load.parse_upstream_entry`), so
    this one implementation serves both
    :func:`validate_upstream_registry` (structural check, messages
    collected rather than raised) and
    :func:`keystone_mcp.upstream_registry.load.parse_upstream_entries`
    (load time, raises on the first message). Messages are already prefixed
    with ``entries[i].``, unlike the other ``*_errors`` helpers in this
    module, since they always name a specific entry index.
    """
    identity_uses: dict[str, list[int]] = {}
    bearer_uses: dict[str, list[int]] = {}
    env_uses: dict[str, list[tuple[int, str]]] = {}
    entry_names: dict[int, str] = {}

    for index, item in enumerate(entries):
        if not isinstance(item, dict):
            continue
        entry_names[index] = str(item.get("name", "")).strip() or f"entries[{index}]"

        auth = item.get("auth")
        if isinstance(auth, dict):
            identity_secret_env = auth.get("identity_secret_env")
            if isinstance(identity_secret_env, str) and identity_secret_env.strip():
                identity_uses.setdefault(identity_secret_env.strip(), []).append(index)
            bearer_env = auth.get("bearer_env")
            if isinstance(bearer_env, str) and bearer_env.strip():
                bearer_uses.setdefault(bearer_env.strip(), []).append(index)

        mapping = _normalize_env_shorthand(item.get("env")) if item.get("env") is not None else None
        if mapping:
            for child, value in mapping.items():
                if isinstance(value, str) and value.strip():
                    env_uses.setdefault(value.strip(), []).append((index, str(child)))

    errors: list[str] = []
    for secret_name, owners in identity_uses.items():
        owner_index = owners[0]
        owner_name = entry_names[owner_index]

        for index in owners[1:]:
            errors.append(
                f"entries[{index}].auth.identity_secret_env reuses the signing secret of "
                f"upstream {owner_name!r} (entries[{owner_index}].auth.identity_secret_env); "
                f"give upstream {entry_names[index]!r} its own signing secret"
            )

        for index in bearer_uses.get(secret_name, []):
            errors.append(
                f"entries[{index}].auth.bearer_env must not name the identity signing "
                f"secret of upstream {owner_name!r} (entries[{owner_index}]"
                f".auth.identity_secret_env)"
            )

        for index, child in env_uses.get(secret_name, []):
            if index == owner_index:
                continue  # a stdio entry's own secret, needed to verify its own assertions
            errors.append(
                f"entries[{index}].env.{child} must not name the identity signing secret "
                f"of upstream {owner_name!r} (entries[{owner_index}].auth.identity_secret_env)"
            )

    return errors


def transport_field_errors(item: dict[str, Any]) -> tuple[str, list[str]]:
    """Validate the ``transport`` field and the fields it gates.

    Returns the effective transport (``"http"`` when the declared value is
    invalid, so the rest of :func:`validate_upstream_registry` can still run
    against a sensible default) and the list of error messages, not prefixed
    with ``entries[i].``.
    """
    errors: list[str] = []
    transport_raw = item.get("transport", "http")
    transport = transport_raw.strip() if isinstance(transport_raw, str) else transport_raw
    if transport not in ("http", "stdio"):
        errors.append(f"transport must be 'http' or 'stdio' (got {transport_raw!r})")
        transport = "http"

    if transport == "stdio":
        command = item.get("command")
        if not isinstance(command, str) or not command.strip() or "\n" in command:
            errors.append("command is required for transport: stdio")
        if item.get("url"):
            errors.append("url is not allowed with transport: stdio")
        args = item.get("args")
        if args is not None and not (
            isinstance(args, list) and all(isinstance(a, str) for a in args)
        ):
            errors.append("args must be an array of strings")
        cwd = item.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            errors.append("cwd must be a string")
        errors.extend(env_field_errors(item.get("env")))
        auth = item.get("auth")
        if isinstance(auth, dict) and "bearer_env" in auth:
            errors.append("auth.bearer_env is not supported with transport: stdio")
    else:
        for field_name in _STDIO_ONLY_FIELDS:
            if item.get(field_name) is not None:
                errors.append(f"{field_name} requires transport: stdio")

    return transport, errors


def namespace_errors(namespaces: Sequence[str]) -> list[str]:
    """Return human-readable errors for a set of upstream namespaces.

    Three independent checks, run against every namespace in ``namespaces``
    (including namespaces of ``enabled: false`` entries, so flipping one on
    later cannot silently break the configuration):

    - **Characters.** Each namespace must match
      ``^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62}[A-Za-z0-9])?$``.
    - **Built-in collisions.** A namespace is rejected if it is a prefix
      (``namespace + "_"``) of any built-in tool name
      (:data:`keystone_mcp.catalog.builtin.BUILTIN_TOOL_NAMES`), since that
      would make the proxied and built-in tool publish the same name.
    - **Namespace-pair collisions.** For a pair of distinct namespaces ``A``
      and ``B``, ``B`` is rejected if it starts with ``A + "_"`` — upstream
      ``A`` publishing tool ``B[len(A)+1:] + "_<anything>"`` would collide
      with upstream ``B`` publishing that same ``"_<anything>"`` tool.
      Comparison is case-sensitive, since MCP tool names are.
    """
    # Import here, not at module level: keeps the catalog module (which pulls
    # in adapters and Settings) out of the upstream_registry import graph
    # unless namespace validation actually runs.
    from keystone_mcp.catalog.builtin import BUILTIN_TOOL_NAMES

    errors: list[str] = []

    for ns in namespaces:
        if not _NAMESPACE_RE.match(ns):
            errors.append(
                f"namespace {ns!r} must be 1-64 characters of A-Z, a-z, 0-9, "
                "'_' or '-', not starting or ending with '_' or '-'"
            )

    for ns in namespaces:
        prefix = f"{ns}_"
        for builtin_name in sorted(BUILTIN_TOOL_NAMES):
            if builtin_name.startswith(prefix):
                errors.append(
                    f"namespace {ns!r} is reserved: published names {ns}_* can "
                    f"collide with built-in tool {builtin_name}"
                )

    distinct = sorted(set(namespaces))
    for a in distinct:
        for b in distinct:
            if a == b:
                continue
            if b.startswith(f"{a}_"):
                errors.append(
                    f"namespaces {a!r} and {b!r} can publish the same tool name "
                    f"({a}_x_y == {b}_y when {a} has a tool x_y); rename one of them"
                )

    return errors


def validate_upstream_registry(
    document: dict[str, Any],
    *,
    policy: UpstreamSecurityPolicy,
) -> list[str]:
    """Validate a loaded registry document; return all error messages."""
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["registry root must be an object"]

    version = document.get("schema_version")
    if version != 1:
        errors.append(f"schema_version must be 1 (got {version!r})")

    entries = document.get("entries")
    if entries is None:
        errors.append("entries is required")
        return errors
    if not isinstance(entries, list):
        errors.append("entries must be an array")
        return errors
    if len(entries) > MAX_REGISTRY_ENTRIES:
        errors.append(f"entries must contain at most {MAX_REGISTRY_ENTRIES} items")

    seen_names: set[str] = set()
    seen_namespaces: set[str] = set()
    all_namespaces: list[str] = []

    for index, item in enumerate(entries):
        prefix = f"entries[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix} must be an object")
            continue

        name = str(item.get("name", "")).strip()
        namespace = str(item.get("namespace", "")).strip()
        url = str(item.get("url", "")).strip()

        if not name:
            errors.append(f"{prefix}.name is required")
        elif name in seen_names:
            errors.append(f"duplicate upstream name: {name!r}")
        else:
            seen_names.add(name)

        if not namespace:
            errors.append(f"{prefix}.namespace is required")
        elif namespace in seen_namespaces:
            errors.append(f"duplicate upstream namespace: {namespace!r}")
        else:
            seen_namespaces.add(namespace)
            all_namespaces.append(namespace)

        transport, transport_errors = transport_field_errors(item)
        for message in transport_errors:
            errors.append(f"{prefix}.{message}")

        if transport == "stdio":
            # transport_field_errors already rejects a non-empty url above.
            pass
        elif not url:
            errors.append(f"{prefix}.url is required")
        else:
            for message in validate_upstream_url(url, policy=policy):
                errors.append(f"{prefix}.url: {message}")

        for message in auth_field_errors(item.get("auth")):
            errors.append(f"{prefix}.{message}")

        for message in limits_field_errors(item.get("limits")):
            errors.append(f"{prefix}.{message}")

        route_mode = item.get("route_mode", "live")
        if route_mode is not None and route_mode not in ("live", "stub"):
            errors.append(f"{prefix}.route_mode must be 'live' or 'stub'")

        for field_name in ("discovery_timeout_seconds", "tool_timeout_seconds"):
            raw = item.get(field_name)
            if raw is None:
                continue
            if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw <= 0:
                errors.append(f"{prefix}.{field_name} must be a positive number")

        if item.get("enabled") is not None and not isinstance(
            item.get("enabled"), (bool, str, int)
        ):
            errors.append(f"{prefix}.enabled must be a boolean")

        publish_resources = item.get("publish_resources")
        if publish_resources is not None and not isinstance(publish_resources, bool):
            errors.append(f"{prefix}.publish_resources must be a boolean")

        for field_name in ("resource_include_prefixes", "resource_exclude_prefixes"):
            raw = item.get(field_name)
            if raw is None:
                continue
            if isinstance(raw, str):
                continue
            if isinstance(raw, list) and all(isinstance(entry, str) for entry in raw):
                continue
            errors.append(f"{prefix}.{field_name} must be a string or array of strings")

    errors.extend(namespace_errors(all_namespaces))
    errors.extend(identity_secret_reuse_errors(entries))

    return errors


def assert_valid_upstream_registry(
    document: dict[str, Any], *, policy: UpstreamSecurityPolicy
) -> None:
    messages = validate_upstream_registry(document, policy=policy)
    if messages:
        raise ValidationError(messages)
