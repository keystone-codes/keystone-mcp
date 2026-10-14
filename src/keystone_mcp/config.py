"""Configuration for keystone-mcp.

Every setting is read from one ``KEYSTONE_MCP_*`` environment variable with a
documented default, and the whole set is materialised once into a frozen
:class:`Settings` instance. Nothing here reaches the environment again after
construction, so an embedding process (or a test) can build a Settings object
directly and every call site honours it.

Malformed input fails at startup rather than degrading silently: numeric
variables refuse garbage, enumerated ones refuse unknown values, and
:func:`validate_settings` refuses combinations that cannot work (a login method
that is not enabled, RBAC without its policy file or Redis, a file path that
does not exist).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import sys
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

LoginMethod = Literal["google", "api_key"]
RbacMode = Literal["off", "observe", "enforce"]
LoginIdentityBindingMode = Literal["off", "bind"]
LogFormat = Literal["json", "text"]
UsersBackend = str
DeploymentProfile = Literal["local", "production"]
PolicyToolsMode = Literal["full", "read-only", "off"]
_VALID_LOG_FORMATS = frozenset({"json", "text"})
_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
_VALID_LOGIN_METHODS = frozenset({"google", "api_key"})
_VALID_RBAC_MODES = frozenset({"off", "observe", "enforce"})
_USERS_BACKEND_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_VALID_DEPLOYMENT_PROFILES = frozenset({"local", "production"})
_VALID_POLICY_TOOLS_MODES = frozenset({"full", "read-only", "off"})

# Languages the login page ships translations for. Kept here (rather than
# imported from the auth layer) so settings validation stays free of an import
# cycle; a test pins this set to the provider's translation table.
LOGIN_LANGS = frozenset({"ar", "en", "he", "ru"})


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


class ConfigError(ValueError):
    """Raised when platform settings are missing or inconsistent at startup."""

    def __init__(
        self,
        message: str,
        *,
        variable: str | None = None,
        problems: tuple[str, ...] = (),
    ) -> None:
        super().__init__(message)
        self.variable = variable
        self.problems = problems or (message,)


_TRUE_BOOL = frozenset({"1", "true", "yes", "on"})
_FALSE_BOOL = frozenset({"0", "false", "no", "off"})
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

BOOL_VARIABLES: tuple[str, ...] = (
    "KEYSTONE_MCP_OAUTH_DCR_ENABLED",
    "KEYSTONE_MCP_LOG_REDACT",
    "KEYSTONE_MCP_LOG_ACCESS_ENABLED",
    "KEYSTONE_MCP_LOG_REQUEST_ID_RESPONSE",
    "KEYSTONE_MCP_USERS_SERVICE_ALLOW_INSECURE_HTTP",
    "KEYSTONE_MCP_RBAC_AUDIT_ENABLED",
    "KEYSTONE_MCP_REQUIRE_RESOURCE_INDICATOR",
    "KEYSTONE_MCP_METRICS_ENABLED",
    "KEYSTONE_MCP_INTERNAL_ENDPOINTS_ENABLED",
    "KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL",
    "KEYSTONE_MCP_PROXY_STATUS_ENVELOPE",
    "KEYSTONE_MCP_PROXY_ELICITATION",
    "KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP",
    "KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE",
    "KEYSTONE_MCP_USERS_SERVICE_ALLOW_INSECURE_HTTP",
)

LOGGING_VARIABLES = frozenset(
    {
        "KEYSTONE_MCP_LOG_LEVEL",
        "KEYSTONE_MCP_LOG_FORMAT",
        "KEYSTONE_MCP_LOG_REDACT",
    }
)

USERS_CLI_VARIABLES = frozenset(
    {
        "KEYSTONE_MCP_USERS_BACKEND",
        "KEYSTONE_MCP_USERS_DB_URL",
        "KEYSTONE_MCP_REDIS_URL",
        "KEYSTONE_MCP_USERS_REDIS_REVISION_KEY",
        "KEYSTONE_MCP_POLICY_REDIS_REVISION_KEY",
        "KEYSTONE_MCP_REDIS_KEY_PREFIX",
        "KEYSTONE_MCP_LOGIN_PENDING_KEY_PREFIX",
        "KEYSTONE_MCP_RBAC_MODE",
        "KEYSTONE_MCP_RBAC_POLICY_PATH",
        "KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT",
    }
)


@dataclass(frozen=True)
class RemovedVariable:
    """A ``KEYSTONE_MCP_*`` variable the code no longer reads.

    Kept in :data:`REMOVED_VARIABLES` so that a stale ``.env`` is reported
    instead of silently ignored.
    """

    removed_in: str
    """Release that stopped reading the variable, e.g. ``"0.5.0"``."""

    replacement: str
    """One English sentence: what to set instead."""

    fatal: bool
    """``True``: startup is refused while the variable is set (non-empty)."""


#: Variables that Keystone-MCP no longer reads. Kept so that a stale .env
#: is reported instead of silently ignored. Plain dict on purpose: tests
#: patch it with monkeypatch.setitem.
REMOVED_VARIABLES: dict[str, RemovedVariable] = {
    "KEYSTONE_MCP_RBAC_ENABLED": RemovedVariable(
        removed_in="0.5.0",
        replacement="Set KEYSTONE_MCP_RBAC_MODE=enforce (or observe, or off).",
        fatal=True,
    ),
    "KEYSTONE_MCP_DET_INTERNAL_URL": RemovedVariable(
        removed_in="0.5.0",
        replacement="Nothing to set: the placeholder adapter that read it was removed.",
        fatal=False,
    ),
    "KEYSTONE_MCP_FILE_API_URL": RemovedVariable(
        removed_in="0.5.0",
        replacement=(
            "The built-in file tools were removed. Run your file service as an "
            "upstream MCP server; see docs/connecting-services.md."
        ),
        fatal=True,
    ),
    "KEYSTONE_MCP_WEBHOOK_BASE_URL": RemovedVariable(
        removed_in="0.5.0",
        replacement=(
            "The webhook adapter moved to keystone_mcp.contrib.adapters and reads "
            "KEYSTONE_MCP_CONTRIB_WEBHOOK_* instead; see docs/contrib/adapters.md."
        ),
        fatal=False,
    ),
    "KEYSTONE_MCP_WEBHOOK_CLIENT": RemovedVariable(
        removed_in="0.5.0",
        replacement=(
            "The webhook adapter moved to keystone_mcp.contrib.adapters and reads "
            "KEYSTONE_MCP_CONTRIB_WEBHOOK_* instead; see docs/contrib/adapters.md."
        ),
        fatal=False,
    ),
    "KEYSTONE_MCP_WEBHOOK_PROJECT": RemovedVariable(
        removed_in="0.5.0",
        replacement=(
            "The webhook adapter moved to keystone_mcp.contrib.adapters and reads "
            "KEYSTONE_MCP_CONTRIB_WEBHOOK_* instead; see docs/contrib/adapters.md."
        ),
        fatal=False,
    ),
    "KEYSTONE_MCP_WEBHOOK_API_TOKEN": RemovedVariable(
        removed_in="0.5.0",
        replacement=(
            "The webhook adapter moved to keystone_mcp.contrib.adapters and reads "
            "KEYSTONE_MCP_CONTRIB_WEBHOOK_* instead; see docs/contrib/adapters.md."
        ),
        fatal=False,
    ),
    "KEYSTONE_MCP_LONG_POLL": RemovedVariable(
        removed_in="0.5.0",
        replacement=(
            "The webhook adapter moved to keystone_mcp.contrib.adapters and reads "
            "KEYSTONE_MCP_CONTRIB_WEBHOOK_LONG_POLL_SECONDS instead; see "
            "docs/contrib/adapters.md."
        ),
        fatal=False,
    ),
    "KEYSTONE_MCP_AUTH_SERVICE_URL": RemovedVariable(
        removed_in="0.5.0",
        replacement="API keys are issued and checked by the users directory; see docs/users.md.",
        fatal=True,
    ),
    "KEYSTONE_MCP_AUTH_SERVICE_TOKEN": RemovedVariable(
        removed_in="0.5.0",
        replacement="API keys are issued and checked by the users directory; see docs/users.md.",
        fatal=True,
    ),
}


def removed_variables_set(environ: Mapping[str, str]) -> list[tuple[str, RemovedVariable]]:
    """Return the removed variables that are set (non-empty) in ``environ``.

    A variable counts as set when it is present in ``environ`` and its value,
    after ``strip()``, is not empty — an empty value (e.g. from a Compose file
    using ``${X:-}``) must not trip a startup refusal. Ordered by name so the
    reported message is deterministic.
    """
    found: list[tuple[str, RemovedVariable]] = []
    for name in sorted(REMOVED_VARIABLES):
        if name in environ and environ[name].strip():
            found.append((name, REMOVED_VARIABLES[name]))
    return found


def _env_int(name: str, default: int) -> int:
    """Read an integer env var, failing fast (never silently defaulting) on garbage."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer; got {raw!r}", variable=name) from exc


def _env_float(name: str, default: float) -> float:
    """Read a float env var, failing fast (never silently defaulting) on garbage."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number; got {raw!r}", variable=name) from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE_BOOL:
        return True
    if value in _FALSE_BOOL or value == "":
        return False
    raise ConfigError(
        f"{name} must be one of 1/true/yes/on or 0/false/no/off (any case); got {raw!r}",
        variable=name,
    )


def _parse_login_method(raw: str, *, field_name: str) -> LoginMethod:
    value = raw.strip().lower()
    if value not in _VALID_LOGIN_METHODS:
        raise ConfigError(
            f"{field_name} must be one of {sorted(_VALID_LOGIN_METHODS)}; got {raw!r}",
            variable=field_name,
        )
    return value  # type: ignore[return-value]


def _parse_log_level(raw: str, *, field_name: str = "KEYSTONE_MCP_LOG_LEVEL") -> str:
    value = raw.strip().upper()
    if value not in _VALID_LOG_LEVELS:
        raise ConfigError(
            f"{field_name} must be one of {sorted(_VALID_LOG_LEVELS)}; got {raw!r}",
            variable=field_name,
        )
    return value


def _parse_log_format(raw: str, *, field_name: str = "KEYSTONE_MCP_LOG_FORMAT") -> LogFormat:
    value = raw.strip().lower()
    if value not in _VALID_LOG_FORMATS:
        raise ConfigError(
            f"{field_name} must be one of {sorted(_VALID_LOG_FORMATS)}; got {raw!r}",
            variable=field_name,
        )
    return value  # type: ignore[return-value]


def _parse_login_identity_binding(
    raw: str, *, field_name: str = "KEYSTONE_MCP_LOGIN_IDENTITY_BINDING"
) -> LoginIdentityBindingMode:
    value = raw.strip().lower()
    if value in ("off", "bind"):
        return value  # type: ignore[return-value]
    raise ConfigError(
        f"{field_name} must be 'off' or 'bind'; got {raw!r}",
        variable=field_name,
    )


def _parse_rbac_mode(raw: str, *, field_name: str = "KEYSTONE_MCP_RBAC_MODE") -> RbacMode:
    value = raw.strip().lower()
    if value not in _VALID_RBAC_MODES:
        raise ConfigError(
            f"{field_name} must be one of {sorted(_VALID_RBAC_MODES)}; got {raw!r}",
            variable=field_name,
        )
    return value  # type: ignore[return-value]


def _parse_deployment_profile(
    raw: str, *, field_name: str = "KEYSTONE_MCP_DEPLOYMENT_PROFILE"
) -> DeploymentProfile:
    value = raw.strip().lower()
    if value not in _VALID_DEPLOYMENT_PROFILES:
        raise ConfigError(
            f"{field_name} must be one of {sorted(_VALID_DEPLOYMENT_PROFILES)}; got {raw!r}",
            variable=field_name,
        )
    return value  # type: ignore[return-value]


def _parse_users_backend(
    raw: str, *, field_name: str = "KEYSTONE_MCP_USERS_BACKEND"
) -> UsersBackend:
    value = raw.strip().lower()
    if not _USERS_BACKEND_NAME_RE.fullmatch(value):
        raise ConfigError(
            f"{field_name} must match ^[a-z][a-z0-9_-]{{0,31}}$; got {raw!r}",
            variable=field_name,
        )
    return value


def _parse_policy_tools(
    raw: str, *, field_name: str = "KEYSTONE_MCP_POLICY_TOOLS"
) -> PolicyToolsMode:
    value = raw.strip().lower()
    if value not in _VALID_POLICY_TOOLS_MODES:
        raise ConfigError(
            f"{field_name} must be one of: full, read-only, off",
            variable=field_name,
        )
    return value  # type: ignore[return-value]


def _parse_cidrs(raw: str) -> tuple[str, ...]:
    """Parse ``KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS`` (comma-separated networks).

    Each entry is an IPv4/IPv6 network in CIDR form; a bare address is accepted
    and treated as a single-host network. A malformed entry is refused at
    startup rather than silently ignored, since dropping one would widen or
    narrow who can reach an unauthenticated endpoint.
    """
    networks: list[str] = []
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        try:
            ipaddress.ip_network(token, strict=False)
        except ValueError as exc:
            raise ConfigError(
                f"KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS entry {token!r} is not a valid "
                f"IP network: {exc}"
            ) from exc
        networks.append(token)
    return tuple(networks)


def _parse_redirect_host_entries(raw: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Parse ``KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS`` (comma-separated hosts).

    Returns ``(bare_hosts, scheme_qualified_entries)``. Most entries are a bare
    hostname or IP literal — no scheme, no port, no path, no mask — and match
    ``https`` for any host and ``http`` only for loopback (see
    ``_redirect_uri_allowed`` in ``keystone_oauth_provider.py``). An entry
    containing ``/`` or ``:`` is otherwise refused at startup, since accepting
    it silently would let a scheme, port or path slip into the allowlist where
    it can never match a parsed hostname.

    The one exception is ``scheme://host`` (e.g. ``cursor://anysphere.cursor-
    retrieval``): a native app's custom URI scheme has no ``https``/``http``
    equivalent to fall back on, so it can only be allowed by naming the scheme
    explicitly. ``http``/``https`` are refused in this form too — they are
    already covered by the bare-host rule above, and allowing them here would
    just be a second, redundant way to write the same thing (and silently
    bypass the loopback-only rule for ``http``, since this form does not carry
    one). Entries are lower-cased; an empty string (the default) means no
    restriction.
    """
    hosts: list[str] = []
    scheme_hosts: list[str] = []
    for part in raw.split(","):
        token = part.strip().lower()
        if not token:
            continue
        if "://" in token:
            scheme, _, rest = token.partition("://")
            if scheme in ("http", "https") or not scheme or not rest or "/" in rest or ":" in rest:
                raise ConfigError(
                    f"KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS entry {token!r} must be a bare "
                    "host name, or 'scheme://host' for a non-http(s) custom scheme (example: "
                    "'claude.ai,localhost,cursor://anysphere.cursor-retrieval')"
                )
            scheme_hosts.append(token)
            continue
        if "/" in token:
            raise ConfigError(
                f"KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS entry {token!r} must be a bare "
                "host name, without scheme or port (example: 'claude.ai,localhost')"
            )
        if ":" in token:
            # A bare IPv6 literal (finding #9) also contains ':', either
            # bracketed (as a human would copy it out of a URL, e.g. '[::1]')
            # or not (e.g. '::1'). Accept either spelling and normalize to
            # the bracket-free, compressed form: that is what
            # `urlparse(...).hostname` always returns (brackets are URL
            # syntax, never part of the host itself), and what
            # `_redirect_uri_allowed`/`_LOOPBACK_REDIRECT_HOSTS` already
            # compare against. Anything else containing ':' — a port
            # (`host:443`) or garbage — is still refused, same as before.
            candidate = token[1:-1] if token.startswith("[") and token.endswith("]") else token
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                address = None
            if address is None or address.version != 6:
                raise ConfigError(
                    f"KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS entry {token!r} must be a bare "
                    "host name, without scheme or port — or an IPv6 literal, optionally "
                    "bracketed (example: 'claude.ai,localhost,[::1]')"
                )
            hosts.append(str(address))
            continue
        hosts.append(token)
    return tuple(hosts), tuple(scheme_hosts)


def _parse_host_list(raw: str) -> tuple[str, ...]:
    return _parse_redirect_host_entries(raw)[0]


def _parse_scheme_host_list(raw: str) -> tuple[str, ...]:
    return _parse_redirect_host_entries(raw)[1]


def _parse_allowed_hosts(raw: str) -> tuple[str, ...]:
    """Parse ``KEYSTONE_MCP_ALLOWED_HOSTS`` (comma-separated, finding #1).

    Unlike ``KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS``, a port *is*
    meaningful here (``Host`` headers carry one) and is accepted as part of
    an entry: ``lb.internal`` matches that name on any port,
    ``lb.internal:8080`` only that exact pair. See
    ``keystone_mcp.http.host_guard`` for how an entry is matched. Still
    refuses a scheme or a path, which can never appear in a ``Host`` header
    and would only indicate a copy-paste mistake (a full URL instead of a
    bare host).
    """
    hosts: list[str] = []
    for part in raw.split(","):
        token = part.strip().lower()
        if not token:
            continue
        if "://" in token or "/" in token:
            raise ConfigError(
                f"KEYSTONE_MCP_ALLOWED_HOSTS entry {token!r} must be a bare host or "
                "host:port, without scheme or path (example: "
                "'lb.internal,edge.example.com:8443')"
            )
        hosts.append(token)
    return tuple(hosts)


def client_address_allowed(client_host: str | None, allowed_cidrs: tuple[str, ...]) -> bool:
    """Whether a peer address falls inside any configured network.

    An unparseable or absent peer address is refused: it cannot be shown to be
    inside the allowlist, and an unauthenticated endpoint should not be reached
    by a caller we cannot place. An empty allowlist denies everyone.
    """
    if not client_host or not allowed_cidrs:
        return False
    try:
        address = ipaddress.ip_address(client_host.strip())
    except ValueError:
        return False
    for cidr in allowed_cidrs:
        network = ipaddress.ip_network(cidr, strict=False)
        if address.version == network.version and address in network:
            return True
    return False


def _is_loopback_host(host: str) -> bool:
    """True for ``localhost``, ``*.localhost``, and a loopback IP literal.

    Used by the ``local`` deployment profile to refuse a ``KEYSTONE_MCP_BASE_URL``
    that is reachable from anywhere but this machine.
    """
    value = host.strip().lower()
    if value == "localhost" or value.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _legacy_ipv4_literal(value: str) -> ipaddress.IPv4Address | None:
    """Parse a decimal/hex/octal IPv4 literal (``134744072``, ``0x08080808``).

    Finding #10 (second review): ``ipaddress.ip_address`` only accepts
    dotted-quad notation, so a bare integer or hex address fell through
    ``_is_public_host``'s IP-literal check and was then classified by the
    bare-name fallback (``"." in value``) as *not* public — even though it is
    exactly the kind of address a browser or ``curl`` dereferences when it
    appears in a URL's host position (``http://134744072/`` connects to
    ``8.8.8.8``). ``socket.inet_aton`` accepts every legacy form glibc's
    ``inet_aton`` does (decimal, ``0x``-hex, ``0``-octal, per-octet or as one
    32-bit number) and is what actually decides where such a URL connects, so
    it is used here instead of re-implementing that grammar. Returns ``None``
    for anything that is not such a literal (including an ordinary hostname).
    """
    try:
        return ipaddress.IPv4Address(socket.inet_aton(value))
    except OSError:
        return None


def _is_unspecified_host(host: str) -> bool:
    """True for ``0.0.0.0``/``::`` (and other spellings of "every interface").

    Used by the ``local``-profile W5 warning (finding #10, second review):
    unlike ``KEYSTONE_MCP_BASE_URL``, ``KEYSTONE_MCP_HOST`` has no loopback
    requirement under L1, so a `local`-profile server can still bind every
    interface. An unparseable value (a hostname, never valid for a bind
    address) is not unspecified.
    """
    try:
        return ipaddress.ip_address(host.strip()).is_unspecified
    except ValueError:
        return False


def _is_public_host(host: str) -> bool:
    """True when a host name or address is reachable from the public internet.

    An IP literal is public exactly when ``ip.is_global`` — including a
    legacy decimal/hex/octal IPv4 literal (``_legacy_ipv4_literal``).
    ``localhost`` and ``*.localhost`` are never public. A bare name with no
    dot (a Docker or Kubernetes service name, e.g. ``keystone``) resolves only
    inside its own network and is not public either. Any other name —
    including one that merely *looks* internal, such as
    ``*.svc.cluster.local`` or ``*.internal`` — is treated as a public DNS
    name: a suffix convention is not a security boundary (nothing stops a
    public DNS record from using it), so this deliberately does not special-
    case those suffixes. See ``KEYSTONE_MCP_BASE_URL is a public http
    address`` in ``validate_settings`` (P4) for what a deployment that is
    genuinely internal-only should do instead.
    """
    value = host.strip().lower()
    if value == "localhost" or value.endswith(".localhost"):
        return False
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        pass
    legacy = _legacy_ipv4_literal(value)
    if legacy is not None:
        return legacy.is_global
    return "." in value


def _parse_login_lang(raw: str) -> str:
    """Validate the login-page fallback language against the shipped translations."""
    value = raw.strip().lower()
    if value not in LOGIN_LANGS:
        raise ConfigError(
            f"KEYSTONE_MCP_LOGIN_DEFAULT_LANG must be one of {sorted(LOGIN_LANGS)}; got {raw!r}",
            variable="KEYSTONE_MCP_LOGIN_DEFAULT_LANG",
        )
    return value


def _parse_login_brand(raw: str) -> str:
    """Validate the name shown on built-in sign-in pages."""
    if "\n" in raw or "\r" in raw:
        raise ConfigError("KEYSTONE_MCP_LOGIN_BRAND must not contain a newline")
    value = raw.strip()
    if not value:
        return "Keystone-MCP"
    if len(value) > 64:
        raise ConfigError("KEYSTONE_MCP_LOGIN_BRAND must be at most 64 characters")
    return value


def _resolve_rbac_mode() -> RbacMode:
    """Resolve the phased RBAC mode from the environment.

    Only ``KEYSTONE_MCP_RBAC_MODE`` is read; an unset or empty value means
    ``off``. The legacy ``KEYSTONE_MCP_RBAC_ENABLED`` boolean alias was
    removed in 0.5.0 (see ``REMOVED_VARIABLES``) and is not consulted here.
    """
    mode_raw = _env("KEYSTONE_MCP_RBAC_MODE", "").strip()
    if mode_raw:
        return _parse_rbac_mode(mode_raw)
    return "off"


def _parse_enabled_login_methods(raw: str) -> frozenset[LoginMethod]:
    if not raw.strip():
        return frozenset({"api_key"})
    methods: set[LoginMethod] = set()
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        methods.add(_parse_login_method(token, field_name="KEYSTONE_MCP_ENABLED_LOGIN_METHODS"))
    if not methods:
        raise ConfigError(
            "KEYSTONE_MCP_ENABLED_LOGIN_METHODS must not be empty",
            variable="KEYSTONE_MCP_ENABLED_LOGIN_METHODS",
        )
    return frozenset(methods)


def normalize_http_path(raw: str) -> str:
    """Return the Starlette route path for the Streamable HTTP endpoint."""
    value = raw.strip()
    if not value or value == "/":
        return "/"
    if not value.startswith("/"):
        value = f"/{value}"
    return value.rstrip("/")


def canonical_resource_url(base_url: str, http_path: str) -> str:
    """RFC 8707 resource indicator (no trailing slash on the host root)."""
    base = base_url.rstrip("/")
    path = normalize_http_path(http_path)
    if path == "/":
        return base
    return f"{base}{path}"


def protected_resource_metadata_path(http_path: str) -> str:
    """RFC 9728 metadata route for the configured MCP endpoint path."""
    path = normalize_http_path(http_path)
    if path == "/":
        return "/.well-known/oauth-protected-resource"
    return f"/.well-known/oauth-protected-resource{path}"


def mcp_transport_url(base_url: str, http_path: str) -> str:
    """URL passed to StreamableHttpTransport (trailing slash for the host root)."""
    base = base_url.rstrip("/")
    path = normalize_http_path(http_path)
    if path == "/":
        return f"{base}/"
    return f"{base}{path}/"


#: Ports that are implicit in a URL and so must compare equal to their absence.
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _normalize_resource(url: str) -> str:
    """Canonical form of a resource indicator, for audience comparison.

    Scheme and host are case-insensitive per RFC 3986, and a scheme's default
    port carries no meaning, so ``https://MCP.Example.com:443/mcp`` and
    ``https://mcp.example.com/mcp`` are the same resource. The path is
    case-sensitive and is compared as given, minus a trailing slash.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()

    port = parsed.port
    authority = host
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        authority = f"{host}:{port}"

    return f"{scheme}://{authority}{parsed.path.rstrip('/')}"


def resources_equivalent(left: str, right: str) -> bool:
    """Whether two resource indicators name the same protected resource.

    Ignores an optional trailing slash, host and scheme case, and a default
    port stated explicitly — differences that do not change which resource is
    addressed, and which would otherwise make a legitimate token look like it
    was minted for a foreign audience.
    """
    return _normalize_resource(left) == _normalize_resource(right)


@dataclass(frozen=True)
class UpstreamConfig:
    """One proxied downstream MCP API registered on the router."""

    name: str
    url: str
    namespace: str
    enabled: bool = True
    include_prefixes: tuple[str, ...] = ()
    exclude_prefixes: tuple[str, ...] = ()
    strip_prefix: str | None = None
    route_mode: Literal["live", "stub"] = "live"
    discovery_timeout_seconds: float | None = None
    tool_timeout_seconds: float | None = None
    # Name of the environment variable holding the upstream's bearer token
    # (``auth.bearer_env`` in the registry entry) — never the token value
    # itself, so this dataclass's repr stays safe to log.
    bearer_env: str | None = None
    # Name of the environment variable holding this upstream's identity
    # assertion secret (``auth.identity_secret_env``, Y01) — again, only the
    # variable's name, never its value. ``None`` means this upstream receives
    # no ``X-Keystone-Identity`` header, only the unsigned ``X-Author-Email``.
    identity_secret_env: str | None = None
    # When ``"ES256"``, Keystone signs assertions with
    # ``KEYSTONE_MCP_IDENTITY_SIGNING_KEY`` instead of ``identity_secret_env``.
    identity_alg: Literal["ES256"] | None = None
    # ``transport: stdio`` fields (Y08). ``url`` is ``""`` for a stdio entry.
    # ``env_from`` pairs a name in the child process's environment with the
    # name of the keystone-mcp environment variable that supplies it — never
    # the value itself, for the same reason as ``bearer_env`` above.
    transport: Literal["http", "stdio"] = "http"
    command: str | None = None
    args: tuple[str, ...] = ()
    env_from: tuple[tuple[str, str], ...] = ()
    cwd: str | None = None
    publish_resources: bool = True
    resource_include_prefixes: tuple[str, ...] = ()
    resource_exclude_prefixes: tuple[str, ...] = ()

    def build_tool_filter(self):
        """Return a predicate for downstream tool names (discovery filter)."""
        from keystone_mcp.router.upstream import build_prefix_tool_filter

        return build_prefix_tool_filter(
            include_prefixes=self.include_prefixes,
            exclude_prefixes=self.exclude_prefixes,
        )

    def build_resource_filter(self):
        """Return a predicate for upstream resource/template names (discovery filter)."""
        from keystone_mcp.router.upstream import build_prefix_tool_filter

        return build_prefix_tool_filter(
            include_prefixes=self.resource_include_prefixes,
            exclude_prefixes=self.resource_exclude_prefixes,
        )


def _parse_prefix_list(raw: object, *, field_name: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        value = raw.strip()
        return (value,) if value else ()
    if isinstance(raw, list):
        prefixes = tuple(str(item).strip() for item in raw if str(item).strip())
        if not prefixes:
            raise ValueError(f"{field_name} must contain at least one non-empty prefix")
        return prefixes
    raise ValueError(f"{field_name} must be a string or array of strings")


def _parse_upstream_tool_timeouts(raw: str) -> dict[str, float]:
    """Parse ``KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS`` (per-published-tool overrides).

    Format: a JSON object mapping a published tool name to a timeout in seconds,
    e.g. ``{"reports_build": 30, "reports_publish": 30}``. Keys should name the
    published tool; the upstream's own tool name still works but is deprecated
    since 0.6.0 (Keystone logs a warning). Unknown keys are logged after
    discovery. An empty or unset value means "no overrides" (every proxied call
    uses ``KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUT_SECONDS``).
    """
    if not raw.strip():
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS must be valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigError(
            "KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS must be a JSON object "
            'of {"<tool_name>": <seconds>}'
        )

    timeouts: dict[str, float] = {}
    for tool_name, value in payload.items():
        name = str(tool_name).strip()
        if not name:
            raise ConfigError(
                "KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS keys must be non-empty tool names"
            )
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(
                f"KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS[{name!r}] must be a number "
                f"of seconds; got {value!r}"
            )
        if value <= 0:
            raise ConfigError(
                f"KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS[{name!r}] must be positive; got {value!r}"
            )
        timeouts[name] = float(value)
    return timeouts


def _upstream_security_policy(settings: Settings) -> "UpstreamSecurityPolicy":
    from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy

    return UpstreamSecurityPolicy(
        allow_insecure_http=settings.upstream_allow_insecure_http,
        egress_allow_private=settings.upstream_egress_allow_private,
    )


def _parse_upstreams_json(
    raw: str, *, policy: "UpstreamSecurityPolicy"
) -> tuple[UpstreamConfig, ...]:
    if not raw.strip():
        return ()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"KEYSTONE_MCP_UPSTREAMS must be valid JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise ValueError("KEYSTONE_MCP_UPSTREAMS must be a JSON array")

    from keystone_mcp.upstream_registry.load import parse_upstream_entries

    return parse_upstream_entries(payload, policy=policy)


def _resolve_upstreams(settings: Settings) -> tuple[UpstreamConfig, ...]:
    from keystone_mcp.upstream_registry.load import load_upstream_registry_file

    policy = _upstream_security_policy(settings)
    path_raw = settings.upstreams_path.strip()
    if path_raw:
        registry_path = Path(path_raw)
        if registry_path.is_file():
            if settings.upstreams_json.strip():
                logger.info(
                    "KEYSTONE_MCP_UPSTREAMS_PATH is set; ignoring KEYSTONE_MCP_UPSTREAMS env"
                )
            return load_upstream_registry_file(registry_path, policy=policy)
    return _parse_upstreams_json(settings.upstreams_json, policy=policy)


@dataclass(frozen=True)
class Settings:
    # NOTE: KEYSTONE_MCP_ENV_FILE is not a field here. It is read before
    # Settings is constructed, by keystone_mcp.env_file.load_env_file, which
    # decides which .env file (if any) to merge into the process environment.
    # Settings only ever reads from the process environment.

    # ── Deployment profile ─────────────────────────────────────────────────
    # ``local``: loopback-only KEYSTONE_MCP_BASE_URL, DEV tokens allowed under
    # any RBAC_MODE. ``production`` (the default): enforce required, no DEV
    # tokens, API-key sign-in needs an external auth service, no plain http on
    # a public host. See validate_settings and startup_warnings below.
    deployment_profile: DeploymentProfile = field(
        default_factory=lambda: _parse_deployment_profile(
            _env("KEYSTONE_MCP_DEPLOYMENT_PROFILE", "production")
        )
    )

    # ── Server / OAuth ────────────────────────────────────────────────────
    # Public base URL that MCP clients reach; drives OAuth metadata and the
    # resource indicator.
    base_url: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_BASE_URL", "http://localhost:8080")
    )
    http_path_raw: str = field(default_factory=lambda: _env("KEYSTONE_MCP_HTTP_PATH", "/"))
    host: str = field(default_factory=lambda: _env("KEYSTONE_MCP_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("KEYSTONE_MCP_PORT", 8080))
    shutdown_grace_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS", 25)
    )
    # Extra names `HostGuardMiddleware` (finding #1) accepts on the `Host`
    # header beyond `KEYSTONE_MCP_BASE_URL` and its loopback aliases — a load
    # balancer's hostname, an internal DNS name, a bare IP a health check
    # reaches this process on. Comma-separated; each entry is either a bare
    # host (matches on any port) or `host:port` (that exact pair only). See
    # `effective_allowed_hosts`.
    allowed_hosts_extra: tuple[str, ...] = field(
        default_factory=lambda: _parse_allowed_hosts(_env("KEYSTONE_MCP_ALLOWED_HOSTS", ""))
    )
    # Dynamic client registration (RFC 7591, POST /register). Disabling it
    # removes the route and the `registration_endpoint` from the authorization
    # server metadata; operators then register OAuth clients manually (see
    # docs/environment.md#registering-a-client-manually).
    oauth_dcr_enabled: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_OAUTH_DCR_ENABLED", True)
    )
    # Soft cap on the number of live (non-expired) registered OAuth clients.
    # `0` means unlimited; a negative value is a startup error. Registration
    # beyond the cap evicts the oldest client that never completed a sign-in;
    # if every client has been used, registration is refused with
    # `invalid_client_metadata`.
    oauth_max_clients: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_OAUTH_MAX_CLIENTS", 10000)
    )
    # Hosts a registered client's redirect_uri may point to. Comma-separated
    # bare hostnames, lower-cased; empty (the default) means no restriction —
    # the 0.3.1 behaviour. When set, both client registration and /authorize
    # refuse a redirect_uri whose host is not in this list (exact match only,
    # no subdomains or wildcards). A bare host matches `https` for that host
    # and `http` only when the host is also loopback (localhost/127.0.0.1/::1);
    # see `oauth_allowed_redirect_scheme_hosts` below for custom schemes.
    oauth_allowed_redirect_hosts: tuple[str, ...] = field(
        default_factory=lambda: _parse_host_list(
            _env("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "")
        )
    )
    # `scheme://host` entries from the same KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS
    # value (e.g. `cursor://anysphere.cursor-retrieval`): a custom (non-http(s))
    # URI scheme is only matched when its exact `scheme://host` pair is listed
    # here, so a bare `anysphere.cursor-retrieval` entry does not implicitly
    # allow every scheme on that host.
    oauth_allowed_redirect_scheme_hosts: tuple[str, ...] = field(
        default_factory=lambda: _parse_scheme_host_list(
            _env("KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS", "")
        )
    )

    log_level: str = field(
        default_factory=lambda: _parse_log_level(_env("KEYSTONE_MCP_LOG_LEVEL", "INFO"))
    )
    log_format: LogFormat = field(
        default_factory=lambda: _parse_log_format(_env("KEYSTONE_MCP_LOG_FORMAT", "json"))
    )
    log_redact: bool = field(default_factory=lambda: _env_bool("KEYSTONE_MCP_LOG_REDACT", True))
    log_access_enabled: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_LOG_ACCESS_ENABLED", True)
    )
    log_request_id_header: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_LOG_REQUEST_ID_HEADER", "X-Request-ID")
    )
    log_request_id_response: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_LOG_REQUEST_ID_RESPONSE", True)
    )

    # Access-token lifetime in seconds (default 24 h).
    token_cache_ttl_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_TOKEN_TTL", 86400)
    )
    # Authorization code lifetime (short-lived, RFC 6749).
    auth_code_ttl_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_AUTH_CODE_TTL", 600)
    )
    # Refresh-token lifetime: how long a client may keep renewing access tokens
    # without logging in again. Bounds the session, and the per-refresh-token
    # auth_method marker is held for exactly this long.
    refresh_token_ttl_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_REFRESH_TOKEN_TTL", 30 * 24 * 3600)
    )
    session_max_age_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_SESSION_MAX_AGE_SECONDS", 30 * 24 * 3600)
    )
    oauth_refresh_grace_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS", 10)
    )

    # OAuth session store (required at runtime outside tests).
    redis_url: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_REDIS_URL", ""), repr=False
    )
    redis_key_prefix: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_REDIS_KEY_PREFIX", "km:oauth:")
    )
    login_pending_key_prefix: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_LOGIN_PENDING_KEY_PREFIX", "km:login:")
    )
    login_pending_txn_ttl_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_LOGIN_PENDING_TXN_TTL", 600)
    )

    # Comma-separated api_tokens accepted on the sign-in page (local profile only).
    dev_tokens: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_DEV_TOKENS", ""), repr=False
    )

    # ── Login methods and RBAC ────────────────────────────────────────────
    # Independent switches: how users sign in vs whether per-tool RBAC runs.
    primary_login_method: LoginMethod = field(
        default_factory=lambda: _parse_login_method(
            _env("KEYSTONE_MCP_PRIMARY_LOGIN_METHOD", "api_key"),
            field_name="KEYSTONE_MCP_PRIMARY_LOGIN_METHOD",
        )
    )
    enabled_login_methods: frozenset[LoginMethod] = field(
        default_factory=lambda: _parse_enabled_login_methods(
            _env("KEYSTONE_MCP_ENABLED_LOGIN_METHODS", "")
        )
    )
    rbac_mode: RbacMode = field(default_factory=_resolve_rbac_mode)

    # Login-page language used when the browser asks for nothing we translate.
    login_default_lang: str = field(
        default_factory=lambda: _parse_login_lang(_env("KEYSTONE_MCP_LOGIN_DEFAULT_LANG", "en"))
    )
    login_brand: str = field(
        default_factory=lambda: _parse_login_brand(_env("KEYSTONE_MCP_LOGIN_BRAND", "Keystone-MCP"))
    )

    # Google OIDC (required when google login is enabled).
    google_client_id: str = field(default_factory=lambda: _env("KEYSTONE_MCP_GOOGLE_CLIENT_ID", ""))
    google_client_secret: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", ""),
        repr=False,
    )
    google_allowed_domain: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_GOOGLE_ALLOWED_DOMAIN", "")
    )
    login_providers_path: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_LOGIN_PROVIDERS_PATH", "")
    )
    login_identity_binding: LoginIdentityBindingMode = field(
        default_factory=lambda: _parse_login_identity_binding(
            _env("KEYSTONE_MCP_LOGIN_IDENTITY_BINDING", "off")
        )
    )

    # Users directory: built in by default (local), or an external HTTP service
    # (fork-only; see docs/users.md).
    users_backend: UsersBackend = field(
        default_factory=lambda: _parse_users_backend(_env("KEYSTONE_MCP_USERS_BACKEND", "local"))
    )
    # Whether KEYSTONE_MCP_USERS_BACKEND was set in the process environment, as
    # opposed to resolving to its "local" default. validate_settings uses this
    # to tell an upgraded 0.3.x deployment (USERS_SERVICE_URL set, BACKEND never
    # mentioned) apart from a deployment that explicitly opted into "local".
    users_backend_explicit: bool = field(
        default_factory=lambda: os.environ.get("KEYSTONE_MCP_USERS_BACKEND") is not None
    )
    users_backend_config: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_USERS_BACKEND_CONFIG", ""),
        repr=False,
    )
    users_db_url: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_USERS_DB_URL", "sqlite:///./keystone-users.db"),
        repr=False,
    )
    superadmin_email: str = field(default_factory=lambda: _env("KEYSTONE_MCP_SUPERADMIN_EMAIL", ""))

    # MCP users directory (required when rbac_enabled and users_backend=="http").
    users_service_url: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_USERS_SERVICE_URL", "")
    )
    users_service_token: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_USERS_SERVICE_TOKEN", ""),
        repr=False,
    )
    users_service_timeout_seconds: float = field(
        default_factory=lambda: _env_float("KEYSTONE_MCP_USERS_SERVICE_TIMEOUT_SECONDS", 3.0)
    )
    users_service_allow_insecure_http: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_USERS_SERVICE_ALLOW_INSECURE_HTTP", False)
    )
    users_cache_allow_ttl_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_USERS_CACHE_ALLOW_TTL_SECONDS", 60)
    )
    users_cache_deny_ttl_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_USERS_CACHE_DENY_TTL_SECONDS", 30)
    )
    users_redis_revision_key: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_USERS_REDIS_REVISION_KEY", "km:users:revision")
    )
    policy_redis_revision_key: str = field(
        default_factory=lambda: _env(
            "KEYSTONE_MCP_POLICY_REDIS_REVISION_KEY", "km:rbac:policy:revision"
        )
    )
    users_circuit_failure_threshold: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_USERS_CIRCUIT_FAILURE_THRESHOLD", 5)
    )
    users_circuit_recovery_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_USERS_CIRCUIT_RECOVERY_SECONDS", 30)
    )

    # Versioned RBAC policy YAML (required when rbac_enabled).
    rbac_policy_path: str = field(default_factory=lambda: _env("KEYSTONE_MCP_RBAC_POLICY_PATH", ""))

    # Optional catalog snapshot YAML declaring active/reserved/wip tool names
    # for policy validation. Empty means "no snapshot" (validate against the
    # discovered live catalog only).
    rbac_catalog_snapshot_path: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_RBAC_CATALOG_SNAPSHOT", "")
    )

    # RBAC audit and metrics (independent of rbac_enabled).
    rbac_audit_enabled: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_RBAC_AUDIT_ENABLED", True)
    )
    rbac_audit_list_tools_sample_rate: float = field(
        default_factory=lambda: _env_float("KEYSTONE_MCP_RBAC_AUDIT_LIST_TOOLS_SAMPLE_RATE", 0.1)
    )
    rbac_audit_subject_salt: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", ""),
        repr=False,
    )
    # Whether the policy_* tools (V02) may change the policy file through this
    # process: "full" reads and writes, "read-only" reads and validates only
    # (for a replica with no write access to a shared policy volume), "off"
    # publishes no policy_* tools at all.
    policy_tools: PolicyToolsMode = field(
        default_factory=lambda: _parse_policy_tools(_env("KEYSTONE_MCP_POLICY_TOOLS", "full"))
    )
    # RFC 8707: refuse an access token that names no resource at all. Default
    # false, because a client that predates resource indicators would otherwise
    # stop working; true is the stricter posture for a deployment whose clients
    # all send one.
    require_resource_indicator: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_REQUIRE_RESOURCE_INDICATOR", False)
    )
    metrics_enabled: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_METRICS_ENABLED", False)
    )
    metrics_path: str = field(default_factory=lambda: _env("KEYSTONE_MCP_METRICS_PATH", "/metrics"))
    metrics_tool_name: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_METRICS_TOOL_NAME", "full").strip().lower()
    )
    # Caps the number of distinct oauth_client_id values reported per process
    # on tool-call metrics; the first N clients seen keep their own label,
    # the rest are folded into "other". 0 means every client is "other".
    metrics_oauth_client_id_limit: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_METRICS_OAUTH_CLIENT_ID_LIMIT", 50)
    )

    # ── Unauthenticated internal endpoints ────────────────────────────────
    # /metrics and the live-published-names introspection route carry no
    # credential, so who may reach them is decided by source address.
    internal_allowed_cidrs: tuple[str, ...] = field(
        default_factory=lambda: _parse_cidrs(
            _env("KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS", "127.0.0.1/32,::1/128")
        )
    )
    # The introspection route lists every published tool name. Off by default;
    # a deployment turns it on when it actually consumes it.
    internal_endpoints_enabled: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_INTERNAL_ENDPOINTS_ENABLED", False)
    )

    # ── Throttle (per-identity, sliding window) ───────────────────────────
    throttle_max_requests: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_THROTTLE_MAX", 120)
    )
    throttle_window_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_THROTTLE_WINDOW", 60)
    )

    # ── Login attempt throttle (IP per POST, email on failed login only) ──
    login_throttle_ip_max: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_LOGIN_THROTTLE_IP_MAX", 30)
    )
    login_throttle_email_max: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_LOGIN_THROTTLE_EMAIL_MAX", 10)
    )
    login_throttle_window_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_LOGIN_THROTTLE_WINDOW", 300)
    )
    # Separate IP budget for /authorize and /token (shared window with login).
    oauth_throttle_ip_max: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_OAUTH_THROTTLE_IP_MAX", 120)
    )

    # ── Upstream MCP proxy ────────────────────────────────────────────────
    upstream_discovery_retries: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_UPSTREAM_DISCOVERY_RETRIES", 3)
    )
    upstream_discovery_timeout_seconds: float = field(
        default_factory=lambda: _env_float("KEYSTONE_MCP_UPSTREAM_DISCOVERY_TIMEOUT", 10.0)
    )
    # true = refuse to start if any configured upstream is unreachable at startup.
    # By default an unreachable upstream is logged and retried on every refresh tick.
    upstream_require_all: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL", False)
    )
    refresh_interval_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS", 300)
    )
    upstream_tool_timeout_seconds: float = field(
        default_factory=lambda: _env_float("KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUT_SECONDS", 180.0)
    )
    # Per-published-tool timeout overrides, JSON: {"<tool_name>": <seconds>}.
    # Empty by default; a deployment sets it for tools that need a shorter or
    # longer budget than upstream_tool_timeout_seconds.
    upstream_tool_timeouts: dict[str, float] = field(
        default_factory=lambda: _parse_upstream_tool_timeouts(
            _env("KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUTS", "")
        )
    )
    upstream_max_response_bytes: int = field(
        default_factory=lambda: _env_int(
            "KEYSTONE_MCP_UPSTREAM_MAX_RESPONSE_BYTES", 16 * 1024 * 1024
        )
    )
    upstream_max_schema_bytes: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_UPSTREAM_MAX_SCHEMA_BYTES", 64 * 1024)
    )
    upstream_max_catalog_items: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_UPSTREAM_MAX_CATALOG_ITEMS", 2000)
    )
    # Optional JSON file of upstream inputSchema property patches (see
    # keystone_mcp.router.proxy_schema for the format). Empty means no patches.
    proxy_schema_patches_path: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_PROXY_SCHEMA_PATCHES", "")
    )
    # false (default): the proxy is transparent — the upstream's response
    # (content blocks, structuredContent, isError, and _meta minus upstream
    # connection stamps) reaches the client unchanged. true: wrap it in the
    # 0.3.x {state, tool, task_id, result}
    # envelope and map a `status` field of error/refused/accepted to an error,
    # a rate-limit error, or a pending task.
    proxy_status_envelope: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_PROXY_STATUS_ENVELOPE", False)
    )
    # true (default): HTTP upstream elicitation/create (form mode) and upstream
    # InputRequiredResult round-trips reach the Keystone client. false: no
    # upstream elicitation handler and no InputRequired passthrough (Y03 path).
    proxy_elicitation: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_PROXY_ELICITATION", True)
    )
    upstreams_path: str = field(default_factory=lambda: _env("KEYSTONE_MCP_UPSTREAMS_PATH", ""))
    upstream_allow_insecure_http: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP", False)
    )
    upstream_egress_allow_private: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE", False)
    )
    upstreams_json: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_UPSTREAMS", ""), repr=False
    )
    # Optional EC P-256 PEM private key for ES256 identity assertions (Y11).
    # Empty means ES256 is unavailable; upstream entries with
    # ``auth.identity_alg: ES256`` refuse to start without it.
    identity_signing_key: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_IDENTITY_SIGNING_KEY", ""),
        repr=False,
    )
    identity_signing_key_previous: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_IDENTITY_SIGNING_KEY_PREVIOUS", ""),
        repr=False,
    )

    @property
    def http_path(self) -> str:
        """Starlette route path for the Streamable HTTP MCP endpoint."""
        return normalize_http_path(self.http_path_raw)

    @property
    def resource_url(self) -> str:
        """RFC 8707 resource indicator clients must target (the MCP endpoint)."""
        return canonical_resource_url(self.base_url, self.http_path)

    @property
    def protected_resource_metadata_path(self) -> str:
        """OAuth protected-resource metadata URL path for this MCP endpoint."""
        return protected_resource_metadata_path(self.http_path)

    @property
    def transport_url(self) -> str:
        """Client transport URL for Streamable HTTP MCP connections."""
        return mcp_transport_url(self.base_url, self.http_path)

    @property
    def upstreams(self) -> tuple[UpstreamConfig, ...]:
        """Resolved upstream MCP APIs from file registry or ``KEYSTONE_MCP_UPSTREAMS``."""
        return _resolve_upstreams(self)

    @property
    def api_key_login_enabled(self) -> bool:
        return "api_key" in self.enabled_login_methods

    @property
    def google_login_enabled(self) -> bool:
        return "google" in self.enabled_login_methods

    @property
    def users_directory_is_local(self) -> bool:
        """True when the built-in users directory backend is in use."""
        return self.users_backend == "local"

    @property
    def rbac_enabled(self) -> bool:
        """True when RBAC middleware is active (observe or enforce)."""
        return self.rbac_mode in ("observe", "enforce")

    @property
    def rbac_enforcing(self) -> bool:
        """True when RBAC decisions are applied (hard deny / catalog filter)."""
        return self.rbac_mode == "enforce"

    @property
    def google_redirect_uri(self) -> str:
        """OAuth redirect URI registered with Google."""
        return f"{self.base_url.rstrip('/')}/login/google/callback"


def effective_allowed_hosts(settings: Settings) -> tuple[str, ...]:
    """The ``Host``/``Origin`` allowlist for ``HostGuardMiddleware`` (finding #1).

    Always includes the host parsed out of ``KEYSTONE_MCP_BASE_URL`` — the
    name a legitimate client is told to reach this server at — on any port
    (a reverse proxy commonly rewrites or omits the port in the ``Host`` it
    forwards, and there is nothing unsafe about being lenient on the *port*
    for a host the operator explicitly named: an attacker still cannot make
    their own, different hostname equal it). When that host is loopback,
    ``localhost``/``127.0.0.1``/``[::1]`` on the *same port* as
    ``KEYSTONE_MCP_BASE_URL`` are added too (a developer or a demo hitting
    any of those spellings should not be refused) — these stay pinned to
    that one port, unlike the base host itself.
    ``KEYSTONE_MCP_ALLOWED_HOSTS`` adds further names verbatim (a load
    balancer's hostname, an internal DNS name, each either bare — any port —
    or ``host:port``), for names this process cannot predict ahead of time.

    ``/healthz`` and ``/readyz`` are exempt from the check entirely (a
    Kubernetes probe's source pod IP cannot be enumerated in advance either)
    — see ``keystone_mcp.http.host_guard``.
    """
    parsed = urlparse(settings.base_url)
    host = (parsed.hostname or "").lower()
    if not host:
        return settings.allowed_hosts_extra

    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    def pinned(h: str) -> str:
        return f"[{h}]:{port}" if ":" in h else f"{h}:{port}"

    hosts = [host, pinned(host)]
    if _is_loopback_host(host):
        hosts.extend(pinned(alias) for alias in ("localhost", "127.0.0.1", "::1"))
    hosts.extend(settings.allowed_hosts_extra)
    return tuple(dict.fromkeys(hosts))  # de-duplicate, keep first occurrence's order


def _refusal_base_url(settings: Settings) -> str | None:
    parsed = urlparse(settings.base_url.strip())
    scheme = (parsed.scheme or "").lower()
    host = parsed.hostname or ""
    if scheme not in ("http", "https") or not host:
        return (
            "KEYSTONE_MCP_BASE_URL must be an absolute http(s) URL such as https://mcp.example.com"
        )
    return None


def _refusal_port(settings: Settings) -> str | None:
    if settings.port < 1 or settings.port > 65535:
        return "KEYSTONE_MCP_PORT must be between 1 and 65535"
    return None


def _refusal_token_ttls(settings: Settings) -> list[str]:
    problems: list[str] = []
    for name, value in (
        ("KEYSTONE_MCP_TOKEN_TTL", settings.token_cache_ttl_seconds),
        ("KEYSTONE_MCP_AUTH_CODE_TTL", settings.auth_code_ttl_seconds),
        ("KEYSTONE_MCP_REFRESH_TOKEN_TTL", settings.refresh_token_ttl_seconds),
        ("KEYSTONE_MCP_LOGIN_PENDING_TXN_TTL", settings.login_pending_txn_ttl_seconds),
    ):
        if value <= 0:
            problems.append(f"{name} must be a positive number of seconds")
    return problems


def _refusal_log_request_id_header(settings: Settings) -> str | None:
    header = settings.log_request_id_header.strip()
    if not header or not _HEADER_NAME_RE.fullmatch(header):
        return "KEYSTONE_MCP_LOG_REQUEST_ID_HEADER must be a header name such as X-Request-ID"
    return None


def _refusal_metrics_path(settings: Settings) -> str | None:
    if not settings.metrics_enabled:
        return None
    path = settings.metrics_path.strip()
    if not path.startswith("/"):
        return (
            'KEYSTONE_MCP_METRICS_PATH must start with "/" and differ from KEYSTONE_MCP_HTTP_PATH'
        )
    if normalize_http_path(path) == normalize_http_path(settings.http_path):
        return (
            'KEYSTONE_MCP_METRICS_PATH must start with "/" and differ from KEYSTONE_MCP_HTTP_PATH'
        )
    return None


def _settings_refusals(settings: Settings) -> list[str]:
    problems: list[str] = []
    problems.extend(_refusal_token_ttls(settings))
    port_problem = _refusal_port(settings)
    if port_problem:
        problems.append(port_problem)
    base_problem = _refusal_base_url(settings)
    if base_problem:
        problems.append(base_problem)
    header_problem = _refusal_log_request_id_header(settings)
    if header_problem:
        problems.append(header_problem)
    metrics_problem = _refusal_metrics_path(settings)
    if metrics_problem:
        problems.append(metrics_problem)
    if not settings.redis_url.strip():
        problems.append("KEYSTONE_MCP_REDIS_URL is required (OAuth sessions are stored in Redis)")
    return problems


def _warn_base_url_path_query(settings: Settings) -> str | None:
    parsed = urlparse(settings.base_url)
    path = parsed.path or ""
    has_path = path not in ("", "/")
    has_query = bool(parsed.query)
    has_fragment = bool(parsed.fragment)
    if not (has_path or has_query or has_fragment):
        return None
    if settings.deployment_profile == "production":
        return (
            "KEYSTONE_MCP_BASE_URL includes a path, query, or fragment; OAuth "
            "metadata and redirect URIs should use the site root only"
        )
    return (
        "KEYSTONE_MCP_BASE_URL includes a path, query, or fragment; OAuth "
        "metadata and redirect URIs should use the site root only"
    )


def _warn_token_ttl(settings: Settings) -> str | None:
    if settings.token_cache_ttl_seconds > 86400:
        return (
            "KEYSTONE_MCP_TOKEN_TTL is longer than 86400 seconds (24 h); "
            "shorter lifetimes limit exposure if a token leaks"
        )
    return None


def _warn_auth_code_ttl(settings: Settings) -> str | None:
    if settings.auth_code_ttl_seconds > 600:
        return (
            "KEYSTONE_MCP_AUTH_CODE_TTL is longer than 600 seconds; "
            "authorization codes should be short-lived"
        )
    return None


def _warn_audit_salt(settings: Settings) -> str | None:
    if not settings.rbac_audit_enabled:
        return None
    salt = settings.rbac_audit_subject_salt
    if settings.rbac_mode == "off" and not salt.strip():
        return (
            "KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT is empty while audit is enabled: "
            "audit records are not pseudonymous"
        )
    if len(salt.encode("utf-8")) < 16:
        return (
            "KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT is shorter than 16 bytes; "
            "use a longer random secret so audit subject hashes are not guessable"
        )
    return None


def _warn_internal_cidr_any(settings: Settings) -> str | None:
    for cidr in settings.internal_allowed_cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if network.prefixlen == 0:
            return (
                "KEYSTONE_MCP_INTERNAL_ALLOWED_CIDRS includes a /0 network "
                "(0.0.0.0/0 or ::/0); that allows any address to reach internal endpoints"
            )
    return None


def _warn_rbac_audit_disabled_production(settings: Settings) -> str | None:
    if settings.deployment_profile == "production" and not settings.rbac_audit_enabled:
        return (
            "KEYSTONE_MCP_RBAC_AUDIT_ENABLED=false in production; "
            "authorization decisions will not be recorded for compliance review"
        )
    return None


def _warn_log_redact_production(settings: Settings) -> str | None:
    if settings.deployment_profile == "production" and not settings.log_redact:
        return "KEYSTONE_MCP_LOG_REDACT=false in production; tokens and secrets may appear in logs"
    return None


def _warn_log_level_debug_production(settings: Settings) -> str | None:
    if settings.deployment_profile == "production" and settings.log_level == "DEBUG":
        return (
            "KEYSTONE_MCP_LOG_LEVEL=DEBUG in production; "
            "verbose logs may include sensitive request details"
        )
    return None


def _warn_redis_without_tls(settings: Settings) -> str | None:
    if settings.deployment_profile != "production":
        return None
    raw = settings.redis_url.strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    if scheme != "redis":
        return None
    host = (parsed.hostname or "").lower()
    if _is_loopback_host(host):
        return None
    from keystone_mcp.observability.logging.redact import redact_url_credentials

    display = redact_url_credentials(raw)
    return (
        f"KEYSTONE_MCP_REDIS_URL ({display}) uses redis:// to a non-loopback host; "
        "use rediss:// or a private network so Redis traffic is encrypted"
    )


def _warn_refresh_interval_off(settings: Settings) -> str | None:
    if settings.rbac_mode != "off":
        return None
    if settings.refresh_interval_seconds < 0:
        return (
            "KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS is negative while RBAC is off; "
            "the reconciler does not run, but set a non-negative value to avoid confusion"
        )
    return None


def _warn_forwarded_allow_ips(settings: Settings, environ: Mapping[str, str]) -> str | None:
    if settings.deployment_profile != "production":
        return None
    if "FORWARDED_ALLOW_IPS" in environ and environ["FORWARDED_ALLOW_IPS"].strip():
        return None
    if settings.allowed_hosts_extra:
        return (
            "FORWARDED_ALLOW_IPS is not set while KEYSTONE_MCP_ALLOWED_HOSTS is configured; "
            "set FORWARDED_ALLOW_IPS to the addresses of trusted reverse proxies"
        )
    if not _is_loopback_host(settings.host.strip()):
        return (
            "FORWARDED_ALLOW_IPS is not set while KEYSTONE_MCP_HOST is not loopback; "
            "set FORWARDED_ALLOW_IPS to the addresses of trusted reverse proxies"
        )
    return None


def _warn_empty_bool_variables(environ: Mapping[str, str]) -> list[str]:
    warnings: list[str] = []
    for name in BOOL_VARIABLES:
        if name not in environ:
            continue
        if environ[name].strip() == "":
            warnings.append(
                f"{name} is set to an empty value and is read as false; "
                "set it to true or false explicitly"
            )
    return warnings


def settings_for_command(
    required: frozenset[str] | set[str],
    *,
    environ: Mapping[str, str] | None = None,
    report: Callable[[str], None] | None = None,
) -> Settings:
    """Build Settings for a CLI command, ignoring invalid unrelated variables."""
    process_backup = dict(os.environ)
    env = dict(process_backup if environ is None else environ)
    report_fn = report or (lambda message: print(message, file=sys.stderr))
    try:
        while True:
            os.environ.clear()
            os.environ.update(env)
            try:
                return Settings()
            except ConfigError as exc:
                var = exc.variable
                if var is None or var in required or var not in env:
                    raise
                report_fn(f"keystone-mcp: ignoring {var} for this command: {exc}")
                env.pop(var, None)
    finally:
        os.environ.clear()
        os.environ.update(process_backup)


def validate_settings(settings: Settings) -> None:
    """Fail fast on missing or inconsistent login/RBAC configuration."""
    refusals = _settings_refusals(settings)
    if refusals:
        raise ConfigError("; ".join(refusals), problems=tuple(refusals))

    if settings.metrics_tool_name not in ("full", "coarse"):
        raise ConfigError(
            "KEYSTONE_MCP_METRICS_TOOL_NAME must be 'full' or 'coarse' "
            f"(got {settings.metrics_tool_name!r})"
        )

    if settings.metrics_oauth_client_id_limit < 0:
        raise ConfigError(
            "KEYSTONE_MCP_METRICS_OAUTH_CLIENT_ID_LIMIT must be >= 0 "
            f"(got {settings.metrics_oauth_client_id_limit!r})"
        )

    grace = settings.oauth_refresh_grace_seconds
    if grace < 0 or grace > 60:
        raise ConfigError(
            f"KEYSTONE_MCP_OAUTH_REFRESH_GRACE_SECONDS must be between 0 and 60 (got {grace!r})"
        )

    if settings.primary_login_method not in settings.enabled_login_methods:
        raise ConfigError(
            "KEYSTONE_MCP_PRIMARY_LOGIN_METHOD must be included in "
            "KEYSTONE_MCP_ENABLED_LOGIN_METHODS"
        )

    providers_file = settings.login_providers_path.strip()
    if providers_file:
        from keystone_mcp.login.config import load_login_providers_file

        load_login_providers_file(
            providers_file,
            deployment_profile=settings.deployment_profile,
            environ=os.environ,
        )

    if settings.google_login_enabled and not providers_file:
        missing_google = [
            name
            for name, value in (
                ("KEYSTONE_MCP_GOOGLE_CLIENT_ID", settings.google_client_id),
                ("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", settings.google_client_secret),
            )
            if not value.strip()
        ]
        if missing_google:
            raise ConfigError(
                "Google login is enabled but required settings are missing: "
                + ", ".join(missing_google)
            )

    # An upgraded 0.3.x deployment set KEYSTONE_MCP_USERS_SERVICE_URL (and a
    # token) to talk to the external users directory, and never heard of
    # KEYSTONE_MCP_USERS_BACKEND (added in 0.4.0, default "local"). Silently
    # resolving to "local" here would start the server against an empty,
    # brand-new SQLite database: every user looks unknown, so `enforce` denies
    # everyone and nothing in the log explains why. Refuse instead, unless the
    # deployment explicitly chose "local" (migration in progress) — in which
    # case just warn that the URL is now ignored.
    if settings.users_service_url.strip():
        if not settings.users_backend_explicit:
            raise ConfigError(
                "KEYSTONE_MCP_USERS_SERVICE_URL is set but KEYSTONE_MCP_USERS_BACKEND "
                "was never set, so it defaults to 'local' and the external users "
                "service would be silently ignored. Set KEYSTONE_MCP_USERS_BACKEND=http "
                "to keep using the external users service, or set "
                "KEYSTONE_MCP_USERS_BACKEND=local and copy the people over with "
                "`keystone-mcp users import` before dropping the old service."
            )
        if settings.users_backend == "local":
            logger.warning(
                "KEYSTONE_MCP_USERS_SERVICE_URL is set but KEYSTONE_MCP_USERS_BACKEND=local; "
                "the URL is ignored. Use `keystone-mcp users import` to copy people from "
                "that service into the built-in directory, then remove the URL."
            )

    # Google OIDC always resolves the email in the users catalog
    # (unknown/blocked → deny), independent of rbac_enabled; the RBAC middleware
    # needs the same directory when rbac_enabled=true. The built-in (local)
    # backend needs neither URL nor token: it has its own checks below.
    from keystone_mcp.login.factory import api_key_login_configured, file_has_interactive_providers

    needs_users_for_login = settings.rbac_enabled
    if providers_file:
        needs_users_for_login = needs_users_for_login or file_has_interactive_providers(settings)
    else:
        needs_users_for_login = needs_users_for_login or settings.google_login_enabled

    if settings.users_backend == "http" and needs_users_for_login:
        missing_users = [
            name
            for name, value in (
                ("KEYSTONE_MCP_USERS_SERVICE_URL", settings.users_service_url),
                ("KEYSTONE_MCP_USERS_SERVICE_TOKEN", settings.users_service_token),
            )
            if not value.strip()
        ]
        if missing_users:
            raise ConfigError(
                "Users directory settings are required when interactive sign-in or RBAC "
                "is enabled but missing: " + ", ".join(missing_users)
            )

    if settings.users_backend == "local":
        from keystone_mcp.users.db import UsersConfigError, check_users_db_url

        try:
            check_users_db_url(settings.users_db_url)
        except UsersConfigError as exc:
            raise ConfigError(f"KEYSTONE_MCP_USERS_DB_URL: {exc}") from exc

    if settings.superadmin_email.strip():
        from keystone_mcp.users.emails import require_valid_email
        from keystone_mcp.users.errors import InvalidUserFieldError

        try:
            require_valid_email(settings.superadmin_email)
        except InvalidUserFieldError as exc:
            raise ConfigError(f"KEYSTONE_MCP_SUPERADMIN_EMAIL: {exc}") from exc

        if settings.users_backend == "http":
            logger.warning(
                "KEYSTONE_MCP_SUPERADMIN_EMAIL is set but KEYSTONE_MCP_USERS_BACKEND=http; "
                "it is ignored, the external users directory creates the first "
                "administrator instead"
            )

    patches_path_raw = settings.proxy_schema_patches_path.strip()
    if patches_path_raw and not Path(patches_path_raw).is_file():
        raise ConfigError(
            f"KEYSTONE_MCP_PROXY_SCHEMA_PATCHES does not exist or is not a file: {patches_path_raw}"
        )

    dev_token_set = {t for t in settings.dev_tokens.split(",") if t.strip()}

    # ── Deployment profile (local | production, §4) ───────────────────────
    base_host = (urlparse(settings.base_url).hostname or "").lower()
    base_scheme = (urlparse(settings.base_url).scheme or "").lower()

    if settings.deployment_profile == "local":
        # L1: a local server only ever listens for loopback traffic.
        if not _is_loopback_host(base_host):
            raise ConfigError(
                "KEYSTONE_MCP_DEPLOYMENT_PROFILE=local serves only a loopback "
                "KEYSTONE_MCP_BASE_URL (localhost, 127.0.0.1, ::1); got "
                f"{settings.base_url!r}. Use production for any other address."
            )
        # L2: DEV tokens are allowed under any RBAC_MODE, including enforce
        # (setup.sh's DEV branch writes exactly that pair); startup_warnings
        # emits W4 for enforce + DEV tokens, but this is not a startup error.
    else:
        # P1: DEV tokens are a local-only convenience.
        if dev_token_set:
            raise ConfigError(
                "KEYSTONE_MCP_DEV_TOKENS is local-only: anyone holding one of these "
                "tokens signs in as any person in the users directory. Clear "
                "KEYSTONE_MCP_DEV_TOKENS, or set KEYSTONE_MCP_DEPLOYMENT_PROFILE=local."
            )
        # P2: production always runs RBAC in enforce.
        if settings.rbac_mode != "enforce":
            raise ConfigError(
                "KEYSTONE_MCP_DEPLOYMENT_PROFILE=production requires "
                f"KEYSTONE_MCP_RBAC_MODE=enforce; got {settings.rbac_mode!r}. Use "
                "KEYSTONE_MCP_DEPLOYMENT_PROFILE=local for off/observe."
            )
        # P3: api_key sign-in in production needs a directory that stores keys.
        if api_key_login_configured(settings) and settings.users_backend == "http":
            raise ConfigError(
                "API-key sign-in in production needs a users directory that stores "
                "API keys (KEYSTONE_MCP_USERS_BACKEND=local). Remove api_key from "
                "the login providers or switch the directory."
            )
        interactive_login = file_has_interactive_providers(settings) or (
            not providers_file and settings.google_login_enabled
        )
        if api_key_login_configured(settings) and interactive_login:
            raise ConfigError(
                "api_key sign-in for people is not available in the production profile "
                "when an interactive provider is configured; people sign in through the "
                "provider, machines use Bearer keys"
            )
        # P4: no unencrypted OAuth traffic to a publicly reachable host. This
        # also refuses an internal-looking name such as `*.svc.cluster.local`
        # or `*.internal` (finding #10, second review): `_is_public_host`
        # deliberately does not special-case those suffixes (a DNS suffix is
        # not a trust boundary — nothing stops a public record from using
        # one), so a closed-cluster deployment still needs to terminate TLS
        # somewhere in front of it, same as a public one.
        if base_scheme == "http" and _is_public_host(base_host):
            raise ConfigError(
                "KEYSTONE_MCP_BASE_URL is a public http address "
                f"({settings.base_url!r}); terminate TLS and use https. This "
                "also refuses an internal-only name such as '*.internal' or "
                "'*.svc.cluster.local': its DNS suffix is not a trust "
                "boundary, so a closed-cluster install still needs a "
                "TLS-terminating proxy (or sidecar) in front of it before "
                "KEYSTONE_MCP_BASE_URL can be https://... with "
                "KEYSTONE_MCP_DEPLOYMENT_PROFILE=production."
            )
        # P5: the built-in users directory needs Postgres in production. SQLite
        # is one file per replica: two replicas each write their own copy and
        # roles drift apart with no single source of truth, and the file is
        # lost with the container unless a volume happens to be mounted on it.
        # Only the "local" backend is affected — an external
        # KEYSTONE_MCP_USERS_BACKEND=http directory manages its own storage.
        if settings.users_backend == "local":
            users_db_url = settings.users_db_url.strip()
            users_db_scheme = urlparse(users_db_url).scheme.split("+")[0]
            if not users_db_url or users_db_scheme == "sqlite":
                raise ConfigError(
                    "KEYSTONE_MCP_DEPLOYMENT_PROFILE=production needs a Postgres users "
                    "directory: set KEYSTONE_MCP_USERS_DB_URL=postgresql+psycopg://"
                    "user:password@host:5432/db. SQLite is local-only (one file per "
                    "replica, roles drift)."
                )

    for name, value in (
        ("KEYSTONE_MCP_LOGIN_THROTTLE_IP_MAX", settings.login_throttle_ip_max),
        ("KEYSTONE_MCP_LOGIN_THROTTLE_EMAIL_MAX", settings.login_throttle_email_max),
        ("KEYSTONE_MCP_LOGIN_THROTTLE_WINDOW", settings.login_throttle_window_seconds),
        ("KEYSTONE_MCP_OAUTH_THROTTLE_IP_MAX", settings.oauth_throttle_ip_max),
        ("KEYSTONE_MCP_OAUTH_MAX_CLIENTS", settings.oauth_max_clients),
        ("KEYSTONE_MCP_SESSION_MAX_AGE_SECONDS", settings.session_max_age_seconds),
    ):
        if value < 0:
            raise ConfigError(f"{name} must be zero or positive (got {value})")

    for name, value in (
        ("KEYSTONE_MCP_UPSTREAM_MAX_RESPONSE_BYTES", settings.upstream_max_response_bytes),
        ("KEYSTONE_MCP_UPSTREAM_MAX_SCHEMA_BYTES", settings.upstream_max_schema_bytes),
        ("KEYSTONE_MCP_UPSTREAM_MAX_CATALOG_ITEMS", settings.upstream_max_catalog_items),
    ):
        if value <= 0:
            raise ConfigError(f"{name} must be positive (got {value})")

    from keystone_mcp.identity_assertion import load_ec_p256_private_key

    if settings.identity_signing_key.strip():
        try:
            load_ec_p256_private_key(settings.identity_signing_key)
        except ValueError:
            raise ConfigError(
                "KEYSTONE_MCP_IDENTITY_SIGNING_KEY must be a PEM EC P-256 private key"
            )

    if settings.identity_signing_key_previous.strip():
        try:
            load_ec_p256_private_key(settings.identity_signing_key_previous)
        except ValueError:
            raise ConfigError(
                "KEYSTONE_MCP_IDENTITY_SIGNING_KEY_PREVIOUS must be a PEM EC P-256 private key"
            )

    if settings.shutdown_grace_seconds < 0 or settings.shutdown_grace_seconds > 3600:
        raise ConfigError(
            "KEYSTONE_MCP_SHUTDOWN_GRACE_SECONDS must be between 0 and 3600 "
            f"(got {settings.shutdown_grace_seconds})"
        )

    if settings.rbac_mode == "off":
        return

    if settings.rbac_audit_enabled and not settings.rbac_audit_subject_salt.strip():
        raise ConfigError(
            "RBAC audit is enabled but KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT is empty. "
            "The salt pseudonymizes subject identifiers in audit records; without a "
            "deployment-specific value the hashes are guessable from an email "
            "address, so the records are not pseudonymous. Set a random secret, or "
            "set KEYSTONE_MCP_RBAC_AUDIT_ENABLED=false to turn audit off."
        )

    if not settings.rbac_policy_path.strip():
        raise ConfigError(
            "RBAC is enabled but required settings are missing: KEYSTONE_MCP_RBAC_POLICY_PATH"
        )

    policy_path = Path(settings.rbac_policy_path)
    if not policy_path.is_file():
        raise ConfigError(
            f"KEYSTONE_MCP_RBAC_POLICY_PATH does not exist or is not a file: "
            f"{settings.rbac_policy_path}"
        )

    snapshot_path_raw = settings.rbac_catalog_snapshot_path.strip()
    if snapshot_path_raw and not Path(snapshot_path_raw).is_file():
        raise ConfigError(
            f"KEYSTONE_MCP_RBAC_CATALOG_SNAPSHOT does not exist or is not a file: "
            f"{snapshot_path_raw}"
        )

    if settings.refresh_interval_seconds < 0:
        raise ConfigError(
            "KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS must be zero or positive "
            f"(got {settings.refresh_interval_seconds})"
        )


def startup_warnings(settings: Settings, *, environ: Mapping[str, str] | None = None) -> list[str]:
    """Operator-facing warnings for a configuration that starts but is risky.

    Pure: never logs, never raises, so it can be unit-tested without
    ``caplog``. ``server.main`` calls this once, after ``configure_logging``
    (``validate_settings`` itself runs before logging is configured), and
    logs every returned line at WARNING. Later cards append to this function
    rather than growing a separate set of ad hoc ``if`` checks in ``main``.

    ``environ`` defaults to ``os.environ`` and is only used to report
    non-fatal entries of :data:`REMOVED_VARIABLES`; fatal ones already made
    ``load_settings()`` raise before this function is reached.
    """
    warnings: list[str] = []
    for name, removed in removed_variables_set(os.environ if environ is None else environ):
        if not removed.fatal:
            warnings.append(
                f"{name} was removed in {removed.removed_in} and has no effect. "
                f"{removed.replacement}"
            )
    base_host = (urlparse(settings.base_url).hostname or "").lower()
    base_scheme = (urlparse(settings.base_url).scheme or "").lower()

    if settings.deployment_profile == "production":
        # W1
        if base_scheme == "http" and not _is_public_host(base_host):
            warnings.append(
                "KEYSTONE_MCP_BASE_URL uses http on a non-public host "
                f"({settings.base_url!r}); clients outside this network cannot "
                "complete OAuth over plain http"
            )
        # W2
        if settings.upstream_allow_insecure_http:
            warnings.append(
                "KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP=true: upstream calls "
                "are not encrypted; keep upstreams on a private network"
            )
        # W20
        users_url = settings.users_service_url.strip()
        if settings.users_backend == "http" and users_url:
            users_parsed = urlparse(users_url)
            users_host = (users_parsed.hostname or "").lower()
            if (
                users_parsed.scheme == "http"
                and not _is_loopback_host(users_host)
                and not settings.users_service_allow_insecure_http
            ):
                warnings.append(
                    "KEYSTONE_MCP_USERS_SERVICE_URL uses http: the users directory token "
                    "and every answer about roles travel unencrypted. Use https, or set "
                    "KEYSTONE_MCP_USERS_SERVICE_ALLOW_INSECURE_HTTP=true if the directory "
                    "is on a private network you trust."
                )
        # W3
        if settings.upstream_egress_allow_private:
            warnings.append(
                "KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE=true: upstream URLs "
                "may point at private addresses; keep the upstream registry "
                "under operator control"
            )
        # W6 (Y01): an upstream with no identity_secret_env only ever learns
        # who is calling from the unsigned, deprecated X-Author-Email header
        # -- except a stdio upstream (D8), which never receives that header
        # at all (there are no HTTP headers to a child process), so its
        # warning must say that instead of naming a header it never gets.
        for cfg in settings.upstreams:
            if cfg.enabled and cfg.transport == "stdio":
                command = cfg.command or ""
                warnings.append(
                    f"upstream namespace={cfg.namespace} runs local command "
                    f"{os.path.basename(command)} with keystone-mcp's own user and no "
                    "sandbox; trust it as you trust keystone-mcp"
                )
        for cfg in settings.upstreams:
            if (
                not cfg.enabled
                or cfg.identity_secret_env is not None
                or cfg.identity_alg == "ES256"
            ):
                continue
            if cfg.transport == "stdio":
                warnings.append(
                    f"upstream namespace={cfg.namespace} (stdio) has no "
                    "auth.identity_secret_env: the process has no way to verify "
                    "who is calling it"
                )
            else:
                warnings.append(
                    f"upstream namespace={cfg.namespace} receives only the unsigned "
                    "X-Author-Email header; set auth.identity_secret_env so the "
                    "service can verify who is calling"
                )
        # W21
        if (
            settings.oauth_dcr_enabled
            and not settings.oauth_allowed_redirect_hosts
            and not settings.oauth_allowed_redirect_scheme_hosts
        ):
            warnings.append(
                "Dynamic client registration is open (KEYSTONE_MCP_OAUTH_DCR_ENABLED=true) "
                "and KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS is empty: any site can "
                "register an OAuth client. List the redirect hosts of the clients you use."
            )
        # W22
        redis_url = settings.redis_url.strip()
        if redis_url:
            redis_parsed = urlparse(redis_url)
            if redis_parsed.scheme != "unix":
                redis_host = (redis_parsed.hostname or "").lower()
                if not _is_loopback_host(redis_host) and not redis_parsed.password:
                    warnings.append(
                        "KEYSTONE_MCP_REDIS_URL has no password: anyone who can reach "
                        "this Redis can read and forge sessions. Use a Redis (or ACL user) "
                        "that only Keystone-MCP can reach, with a password and TLS "
                        "(rediss://)."
                    )
    else:
        dev_token_set = {t for t in settings.dev_tokens.split(",") if t.strip()}
        # W4: the only local-profile warning (dev tokens under off/observe are
        # unremarkable: the users_* admin tools are not published in that mode).
        if settings.rbac_mode == "enforce" and dev_token_set:
            warnings.append(
                "KEYSTONE_MCP_DEV_TOKENS is set: anyone holding the token can "
                "sign in as any person in the users directory, including "
                "administrators. Local profile only; never expose this server "
                "beyond loopback."
            )
        # W5 (finding #10, second review): L1 only looks at
        # KEYSTONE_MCP_BASE_URL (which `local` requires to be loopback), so a
        # `local`-profile server that also binds KEYSTONE_MCP_HOST to every
        # interface was never flagged — and this is not hypothetical: the
        # Docker demo's own container listens on 0.0.0.0 internally (its
        # published port mapping is what actually restricts reachability).
        # Not a refusal: that demo is a legitimate `local` deployment. Only
        # worth a warning when DEV tokens are also configured, since an empty
        # KEYSTONE_MCP_DEV_TOKENS is no more reachable than any other `local`
        # server bound this way.
        if dev_token_set and _is_unspecified_host(settings.host):
            warnings.append(
                "KEYSTONE_MCP_HOST={!r} is listening on all interfaces with "
                "DEV tokens configured: anyone who can reach this port signs "
                "in as any person in the users directory. Safe only when "
                "something else restricts reachability (e.g. a container's "
                "own port mapping); bind KEYSTONE_MCP_HOST to loopback "
                "otherwise.".format(settings.host)
            )

    # W7: a deployment that wants policy_* tools to write the policy file
    # (KEYSTONE_MCP_POLICY_TOOLS=full, the default) but mounted it read-only
    # (e.g. the ":ro" examples) is not refused at startup -- read-only tools
    # still work -- but every mutating policy_* call will refuse with
    # policy_readonly until the operator remounts read-write or switches this
    # replica to KEYSTONE_MCP_POLICY_TOOLS=read-only.
    if (
        settings.rbac_enforcing
        and settings.policy_tools == "full"
        and settings.rbac_policy_path.strip()
    ):
        policy_path = Path(settings.rbac_policy_path)
        if policy_path.is_file() and not (
            os.access(policy_path, os.W_OK) and os.access(policy_path.parent, os.W_OK)
        ):
            warnings.append(
                f"policy file {settings.rbac_policy_path} is not writable: "
                "policy_* mutation tools will refuse with policy_readonly "
                "(mount it read-write or set KEYSTONE_MCP_POLICY_TOOLS=read-only)"
            )

    _LEGACY_LOGIN_ENV = (
        "KEYSTONE_MCP_GOOGLE_CLIENT_ID",
        "KEYSTONE_MCP_GOOGLE_CLIENT_SECRET",
        "KEYSTONE_MCP_GOOGLE_ALLOWED_DOMAIN",
        "KEYSTONE_MCP_ENABLED_LOGIN_METHODS",
        "KEYSTONE_MCP_PRIMARY_LOGIN_METHOD",
    )
    env_map = os.environ if environ is None else environ
    legacy_set = any(env_map.get(name, "").strip() for name in _LEGACY_LOGIN_ENV)
    if settings.users_backend_config.strip() and settings.users_backend in ("local", "http"):
        warnings.append(
            "KEYSTONE_MCP_USERS_BACKEND_CONFIG is set but has no effect for the "
            f"built-in {settings.users_backend!r} users directory"
        )

    if legacy_set:
        base_msg = (
            "KEYSTONE_MCP_GOOGLE_*, KEYSTONE_MCP_ENABLED_LOGIN_METHODS and "
            "KEYSTONE_MCP_PRIMARY_LOGIN_METHOD are deprecated since 0.5.0 and will "
            "be removed in a future major version. Describe sign-in providers in the "
            "file named by KEYSTONE_MCP_LOGIN_PROVIDERS_PATH (docs/login-providers.md)."
        )
        if settings.login_providers_path.strip():
            warnings.append(
                f"{base_msg} They are ignored because KEYSTONE_MCP_LOGIN_PROVIDERS_PATH is set."
            )
        else:
            warnings.append(base_msg)

    env_map = os.environ if environ is None else environ
    for rule in (
        _warn_base_url_path_query,
        _warn_token_ttl,
        _warn_auth_code_ttl,
        _warn_audit_salt,
        _warn_internal_cidr_any,
        _warn_rbac_audit_disabled_production,
        _warn_log_redact_production,
        _warn_log_level_debug_production,
        _warn_redis_without_tls,
        _warn_refresh_interval_off,
    ):
        line = rule(settings)
        if line:
            warnings.append(line)
    forwarded = _warn_forwarded_allow_ips(settings, env_map)
    if forwarded:
        warnings.append(forwarded)
    warnings.extend(_warn_empty_bool_variables(env_map))

    from keystone_mcp.identity_assertion import normalize_pem_env_value
    from keystone_mcp.upstream_registry.load import identity_secret_value_warnings

    try:
        warnings.extend(identity_secret_value_warnings(settings.upstreams, env_map))
    except ValueError:
        pass

    previous_pem = settings.identity_signing_key_previous.strip()
    current_pem = settings.identity_signing_key.strip()
    if previous_pem and not current_pem:
        warnings.append(
            "KEYSTONE_MCP_IDENTITY_SIGNING_KEY_PREVIOUS is set but "
            "KEYSTONE_MCP_IDENTITY_SIGNING_KEY is empty: the previous key has no effect"
        )
    elif (
        previous_pem
        and current_pem
        and normalize_pem_env_value(previous_pem) == normalize_pem_env_value(current_pem)
    ):
        warnings.append(
            "KEYSTONE_MCP_IDENTITY_SIGNING_KEY_PREVIOUS is the same as "
            "KEYSTONE_MCP_IDENTITY_SIGNING_KEY: only one key will be published in JWKS"
        )

    return warnings


@dataclass(frozen=True)
class ConfigReport:
    env_file: str | None
    errors: tuple[str, ...]
    warnings: tuple[str, ...]


def _build_settings_for_check(
    environ: MutableMapping[str, str],
) -> tuple[Settings | None, list[str], bool]:
    """Parse ``Settings`` from ``environ``, collecting one error per bad variable.

    Returns ``(settings, errors, incomplete)``. When ``incomplete`` is true,
    ``settings`` is ``None`` and steps that need a parsed ``Settings`` must be
    skipped (fatal parse failure, typically ``variable is None``).
    """
    errors: list[str] = []
    env = dict(environ)
    process_backup = dict(os.environ)
    try:
        os.environ.clear()
        os.environ.update(env)
        while True:
            try:
                return Settings(), errors, False
            except ConfigError as exc:
                if exc.variable is None:
                    if exc.problems:
                        errors.extend(exc.problems)
                    else:
                        errors.append(str(exc))
                    return None, errors, True
                message = exc.problems[0] if exc.problems else str(exc)
                errors.append(message)
                env.pop(exc.variable, None)
                os.environ.clear()
                os.environ.update(env)
    finally:
        os.environ.clear()
        os.environ.update(process_backup)


def check_configuration(
    environ: MutableMapping[str, str] | None = None,
    *,
    env_file: str | None = None,
    env_file_ignored_forwarded: bool = False,
) -> ConfigReport:
    """Collect startup refusals and warnings without logging or raising.

    Operates on a copy of the environment: callers should load ``.env`` into
    ``environ`` first (see :func:`keystone_mcp.env_file.load_env_file`). Does
    not connect to Redis, Postgres, upstreams, or OIDC discovery endpoints;
    provider assembly uses ``resolver=None`` like the server's pre-warm check.
    """
    env_map: dict[str, str] = dict(os.environ if environ is None else environ)
    errors: list[str] = []
    warnings: list[str] = []

    for name, removed in removed_variables_set(env_map):
        if removed.fatal:
            errors.append(
                f"{name} was removed in {removed.removed_in} and is no longer read. "
                f"{removed.replacement} Remove the variable to start."
            )
        else:
            warnings.append(
                f"{name} was removed in {removed.removed_in} and has no effect. "
                f"{removed.replacement}"
            )

    settings, parse_errors, incomplete = _build_settings_for_check(env_map)
    errors.extend(parse_errors)
    if incomplete or settings is None:
        return ConfigReport(env_file=env_file, errors=tuple(errors), warnings=tuple(warnings))

    refusal_lines = _settings_refusals(settings)
    errors.extend(refusal_lines)
    refusal_set = set(refusal_lines)

    try:
        validate_settings(settings)
    except ConfigError as exc:
        for problem in exc.problems:
            if problem not in refusal_set:
                errors.append(problem)
                refusal_set.add(problem)

    try:
        _ = settings.upstreams
    except ValueError as exc:
        errors.append(f"upstream registry: {exc}")

    from keystone_mcp.login.factory import (
        build_login_providers,
        check_login_providers_for_profile,
        validate_login_providers,
    )

    try:
        providers = build_login_providers(settings, resolver=None)
        validate_login_providers(providers)
        check_login_providers_for_profile(settings, providers)
    except (ConfigError, ValueError) as exc:
        errors.append(str(exc))

    if settings.rbac_enabled:
        policy_path = settings.rbac_policy_path.strip()
        if policy_path and Path(policy_path).is_file():
            from keystone_mcp.rbac.policy import PolicyContractError, load_policy_file

            try:
                load_policy_file(policy_path)
            except PolicyContractError as exc:
                errors.append(f"policy: {exc}")

    warnings.extend(startup_warnings(settings, environ=env_map))
    if env_file_ignored_forwarded and env_file:
        warnings.append(
            f"FORWARDED_ALLOW_IPS in {env_file} is ignored: it is read by uvicorn from the "
            "process environment, not from .env; set it in the service environment "
            "(systemd Environment=, docker -e, Kubernetes env)"
        )

    deduped_warnings: list[str] = []
    seen: set[str] = set()
    for line in warnings:
        if line in seen:
            continue
        seen.add(line)
        deduped_warnings.append(line)

    return ConfigReport(
        env_file=env_file,
        errors=tuple(errors),
        warnings=tuple(deduped_warnings),
    )


def load_settings() -> Settings:
    fatal = [
        (name, removed) for name, removed in removed_variables_set(os.environ) if removed.fatal
    ]
    if fatal:
        messages = [
            f"{name} was removed in {removed.removed_in} and is no longer read. "
            f"{removed.replacement} Remove the variable to start."
            for name, removed in fatal
        ]
        raise ConfigError(" ".join(messages))
    settings = Settings()
    validate_settings(settings)
    return settings
