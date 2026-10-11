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
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from keystone_mcp.upstream_registry.policy import UpstreamSecurityPolicy
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

LoginMethod = Literal["google", "api_key"]
RbacMode = Literal["off", "observe", "enforce"]
LogFormat = Literal["json", "text"]
UsersBackend = Literal["local", "http"]
DeploymentProfile = Literal["local", "production"]
_VALID_LOG_FORMATS = frozenset({"json", "text"})
_VALID_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
_VALID_LOGIN_METHODS = frozenset({"google", "api_key"})
_VALID_RBAC_MODES = frozenset({"off", "observe", "enforce"})
_VALID_USERS_BACKENDS = frozenset({"local", "http"})
_VALID_DEPLOYMENT_PROFILES = frozenset({"local", "production"})

# Languages the login page ships translations for. Kept here (rather than
# imported from the auth layer) so settings validation stays free of an import
# cycle; a test pins this set to the provider's translation table.
LOGIN_LANGS = frozenset({"ar", "en", "he", "ru"})

# Shared between validate_settings and server.build_identity_provider so the
# startup refusal and the defence-in-depth check say exactly the same thing.
AUTH_SERVICE_URL_WITHOUT_TOKEN_ERROR = (
    "KEYSTONE_MCP_AUTH_SERVICE_URL is set but KEYSTONE_MCP_AUTH_SERVICE_TOKEN is empty. "
    "Set both to verify API keys with an external service, or clear "
    "KEYSTONE_MCP_AUTH_SERVICE_URL to use KEYSTONE_MCP_DEV_TOKENS."
)


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


class ConfigError(ValueError):
    """Raised when platform settings are missing or inconsistent at startup."""


def _env_int(name: str, default: int) -> int:
    """Read an integer env var, failing fast (never silently defaulting) on garbage."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer; got {raw!r}") from exc


def _env_float(name: str, default: float) -> float:
    """Read a float env var, failing fast (never silently defaulting) on garbage."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw.strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number; got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes")


def _parse_login_method(raw: str, *, field_name: str) -> LoginMethod:
    value = raw.strip().lower()
    if value not in _VALID_LOGIN_METHODS:
        raise ConfigError(
            f"{field_name} must be one of {sorted(_VALID_LOGIN_METHODS)}; got {raw!r}"
        )
    return value  # type: ignore[return-value]


def _parse_log_level(raw: str, *, field_name: str = "KEYSTONE_MCP_LOG_LEVEL") -> str:
    value = raw.strip().upper()
    if value not in _VALID_LOG_LEVELS:
        raise ConfigError(f"{field_name} must be one of {sorted(_VALID_LOG_LEVELS)}; got {raw!r}")
    return value


def _parse_log_format(raw: str, *, field_name: str = "KEYSTONE_MCP_LOG_FORMAT") -> LogFormat:
    value = raw.strip().lower()
    if value not in _VALID_LOG_FORMATS:
        raise ConfigError(f"{field_name} must be one of {sorted(_VALID_LOG_FORMATS)}; got {raw!r}")
    return value  # type: ignore[return-value]


def _parse_rbac_mode(raw: str, *, field_name: str = "KEYSTONE_MCP_RBAC_MODE") -> RbacMode:
    value = raw.strip().lower()
    if value not in _VALID_RBAC_MODES:
        raise ConfigError(f"{field_name} must be one of {sorted(_VALID_RBAC_MODES)}; got {raw!r}")
    return value  # type: ignore[return-value]


def _parse_deployment_profile(
    raw: str, *, field_name: str = "KEYSTONE_MCP_DEPLOYMENT_PROFILE"
) -> DeploymentProfile:
    value = raw.strip().lower()
    if value not in _VALID_DEPLOYMENT_PROFILES:
        raise ConfigError(
            f"{field_name} must be one of {sorted(_VALID_DEPLOYMENT_PROFILES)}; got {raw!r}"
        )
    return value  # type: ignore[return-value]


def _parse_users_backend(
    raw: str, *, field_name: str = "KEYSTONE_MCP_USERS_BACKEND"
) -> UsersBackend:
    value = raw.strip().lower()
    if value not in _VALID_USERS_BACKENDS:
        raise ConfigError(
            f"{field_name} must be one of {sorted(_VALID_USERS_BACKENDS)}; got {raw!r}"
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
            f"KEYSTONE_MCP_LOGIN_DEFAULT_LANG must be one of {sorted(LOGIN_LANGS)}; got {raw!r}"
        )
    return value


def _warn_rbac_enabled_deprecated() -> None:
    """Warn once per resolution that the legacy boolean alias is in use."""
    logger.warning(
        "KEYSTONE_MCP_RBAC_ENABLED is deprecated and will be removed; "
        "set KEYSTONE_MCP_RBAC_MODE (off | observe | enforce) instead "
        "(RBAC_ENABLED=true is equivalent to RBAC_MODE=enforce)"
    )


def _resolve_rbac_mode() -> RbacMode:
    """Resolve the phased RBAC mode from the environment.

    ``KEYSTONE_MCP_RBAC_MODE`` takes precedence when set. Otherwise the
    deprecated ``KEYSTONE_MCP_RBAC_ENABLED=true`` still maps to ``enforce``;
    setting it at all logs a deprecation warning.
    """
    mode_raw = _env("KEYSTONE_MCP_RBAC_MODE", "").strip()
    enabled_raw = os.environ.get("KEYSTONE_MCP_RBAC_ENABLED")
    if enabled_raw is not None:
        _warn_rbac_enabled_deprecated()
    if mode_raw:
        mode = _parse_rbac_mode(mode_raw)
        if enabled_raw is not None:
            legacy_enabled = enabled_raw.lower() in ("1", "true", "yes")
            if mode == "off" and legacy_enabled:
                raise ConfigError(
                    "KEYSTONE_MCP_RBAC_MODE=off conflicts with KEYSTONE_MCP_RBAC_ENABLED=true"
                )
        return mode
    if _env_bool("KEYSTONE_MCP_RBAC_ENABLED", False):
        return "enforce"
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
        raise ConfigError("KEYSTONE_MCP_ENABLED_LOGIN_METHODS must not be empty")
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

    def build_tool_filter(self):
        """Return a predicate for downstream tool names (discovery filter)."""
        from keystone_mcp.router.upstream import build_prefix_tool_filter

        return build_prefix_tool_filter(
            include_prefixes=self.include_prefixes,
            exclude_prefixes=self.exclude_prefixes,
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
    e.g. ``{"catalog_advance": 30, "catalog_record_decision": 30}``. An empty or
    unset value means "no overrides" (every proxied call uses
    ``KEYSTONE_MCP_UPSTREAM_TOOL_TIMEOUT_SECONDS``).
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
    # beyond the cap is refused with `invalid_client_metadata`; existing
    # clients are never evicted to make room.
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

    # OAuth session store (shared platform Redis; required at runtime outside tests).
    redis_url: str = field(default_factory=lambda: _env("KEYSTONE_MCP_REDIS_URL", ""))
    redis_key_prefix: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_REDIS_KEY_PREFIX", "km:oauth:")
    )
    login_pending_key_prefix: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_LOGIN_PENDING_KEY_PREFIX", "km:login:")
    )
    login_pending_txn_ttl_seconds: int = field(
        default_factory=lambda: _env_int("KEYSTONE_MCP_LOGIN_PENDING_TXN_TTL", 600)
    )

    # ── Auth-service introspection (production) ───────────────────────────
    auth_service_url: str = field(default_factory=lambda: _env("KEYSTONE_MCP_AUTH_SERVICE_URL", ""))
    auth_service_token: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_AUTH_SERVICE_TOKEN", "")
    )
    # Comma-separated api_tokens accepted without an auth service (local dev).
    # Ignored once auth_service_url is set.
    dev_tokens: str = field(default_factory=lambda: _env("KEYSTONE_MCP_DEV_TOKENS", ""))

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

    # Google OIDC (required when google login is enabled).
    google_client_id: str = field(default_factory=lambda: _env("KEYSTONE_MCP_GOOGLE_CLIENT_ID", ""))
    google_client_secret: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_GOOGLE_CLIENT_SECRET", "")
    )
    google_allowed_domain: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_GOOGLE_ALLOWED_DOMAIN", "")
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
    users_db_url: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_USERS_DB_URL", "sqlite:///./keystone-users.db")
    )
    superadmin_email: str = field(default_factory=lambda: _env("KEYSTONE_MCP_SUPERADMIN_EMAIL", ""))

    # MCP users directory (required when rbac_enabled and users_backend=="http").
    users_service_url: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_USERS_SERVICE_URL", "")
    )
    users_service_token: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_USERS_SERVICE_TOKEN", "")
    )
    users_service_timeout_seconds: float = field(
        default_factory=lambda: _env_float("KEYSTONE_MCP_USERS_SERVICE_TIMEOUT_SECONDS", 3.0)
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
        default_factory=lambda: _env("KEYSTONE_MCP_RBAC_AUDIT_SUBJECT_SALT", "")
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

    # ── Webhook adapter target ────────────────────────────────────────────
    # Base URL the reference webhook adapter submits to
    # (POST /api/v1/webhooks/{client}/{project}).
    webhook_base_url: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_WEBHOOK_BASE_URL", "http://localhost:8000")
    )
    # Webhook route segments (POST /api/v1/webhooks/{client}/{project}). No
    # default: a deployment that registers webhook routes must name its own.
    webhook_client_id: str = field(default_factory=lambda: _env("KEYSTONE_MCP_WEBHOOK_CLIENT", ""))
    webhook_project_id: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_WEBHOOK_PROJECT", "")
    )
    # Optional token sent as Authorization to the webhook and to the file API.
    webhook_api_token: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_WEBHOOK_API_TOKEN", "")
    )
    # Long-poll hint for GET /tasks/{id}/result (server-side ~30-50s).
    long_poll_seconds: int = field(default_factory=lambda: _env_int("KEYSTONE_MCP_LONG_POLL", 40))

    # ── Optional file API for the built-in file tools ─────────────────────
    file_api_base_url: str = field(default_factory=lambda: _env("KEYSTONE_MCP_FILE_API_URL", ""))

    @property
    def file_tools_enabled(self) -> bool:
        """Whether ``create_upload_url`` and ``get_download_link`` are published.

        True only when ``KEYSTONE_MCP_FILE_API_URL`` is set; there is no
        fallback to the webhook base URL.
        """
        return bool(self.file_api_base_url.strip())

    @property
    def resolved_file_api_base_url(self) -> str:
        """Base URL for POST /api/v1/files (``KEYSTONE_MCP_FILE_API_URL``, no fallback)."""
        return self.file_api_base_url.strip().rstrip("/")

    # ── det_internal target (placeholder adapter) ─────────────────────────
    det_internal_base_url: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_DET_INTERNAL_URL", "http://localhost:8000")
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
    # Optional JSON file of upstream inputSchema property patches (see
    # keystone_mcp.router.proxy_schema for the format). Empty means no patches.
    proxy_schema_patches_path: str = field(
        default_factory=lambda: _env("KEYSTONE_MCP_PROXY_SCHEMA_PATCHES", "")
    )
    # false (default): the proxy is transparent — the upstream's response
    # (content blocks, structuredContent, _meta, isError) reaches the client
    # unchanged. true: wrap it in the 0.3.x {state, tool, task_id, result}
    # envelope and map a `status` field of error/refused/accepted to an error,
    # a rate-limit error, or a pending task.
    proxy_status_envelope: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_PROXY_STATUS_ENVELOPE", False)
    )
    upstreams_path: str = field(default_factory=lambda: _env("KEYSTONE_MCP_UPSTREAMS_PATH", ""))
    upstream_allow_insecure_http: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_UPSTREAM_ALLOW_INSECURE_HTTP", False)
    )
    upstream_egress_allow_private: bool = field(
        default_factory=lambda: _env_bool("KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE", False)
    )
    upstreams_json: str = field(default_factory=lambda: _env("KEYSTONE_MCP_UPSTREAMS", ""))

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


def validate_settings(settings: Settings) -> None:
    """Fail fast on missing or inconsistent login/RBAC configuration."""
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

    if settings.primary_login_method not in settings.enabled_login_methods:
        raise ConfigError(
            "KEYSTONE_MCP_PRIMARY_LOGIN_METHOD must be included in "
            "KEYSTONE_MCP_ENABLED_LOGIN_METHODS"
        )

    if settings.google_login_enabled:
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
    if settings.users_backend == "http" and (
        settings.google_login_enabled or settings.rbac_enabled
    ):
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
                "Users directory settings are required when Google login or RBAC "
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

    if settings.auth_service_url.strip() and not settings.auth_service_token.strip():
        raise ConfigError(AUTH_SERVICE_URL_WITHOUT_TOKEN_ERROR)

    dev_token_set = {t for t in settings.dev_tokens.split(",") if t.strip()}
    auth_service_configured = bool(
        settings.auth_service_url.strip() and settings.auth_service_token.strip()
    )

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
        # P3: api_key sign-in needs an external key-verification service in
        # production; an empty KEYSTONE_MCP_ENABLED_LOGIN_METHODS defaults to
        # api_key (_parse_enabled_login_methods), so a production deployment
        # with no explicit sign-in configuration is refused here too.
        if settings.api_key_login_enabled and not auth_service_configured:
            raise ConfigError(
                "API-key sign-in in production needs KEYSTONE_MCP_AUTH_SERVICE_URL "
                "and _TOKEN; DEV tokens are local-only. Remove api_key from "
                "KEYSTONE_MCP_ENABLED_LOGIN_METHODS or configure the service."
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
    ):
        if value < 0:
            raise ConfigError(f"{name} must be zero or positive (got {value})")

    if settings.rbac_mode == "off":
        return

    if not settings.redis_url.strip():
        raise ConfigError(
            "RBAC is enabled but required settings are missing: "
            "KEYSTONE_MCP_REDIS_URL (shared revision marker for multi-replica cache)"
        )

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


def startup_warnings(settings: Settings) -> list[str]:
    """Operator-facing warnings for a configuration that starts but is risky.

    Pure: never logs, never raises, so it can be unit-tested without
    ``caplog``. ``server.main`` calls this once, after ``configure_logging``
    (``validate_settings`` itself runs before logging is configured), and
    logs every returned line at WARNING. Later cards append to this function
    rather than growing a separate set of ad hoc ``if`` checks in ``main``.
    """
    warnings: list[str] = []
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
        # W3
        if settings.upstream_egress_allow_private:
            warnings.append(
                "KEYSTONE_MCP_UPSTREAM_EGRESS_ALLOW_PRIVATE=true: upstream URLs "
                "may point at private addresses; keep the upstream registry "
                "under operator control"
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

    return warnings


def load_settings() -> Settings:
    settings = Settings()
    validate_settings(settings)
    return settings
