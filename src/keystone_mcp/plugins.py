"""Entry-point discovery for login providers and users directories.

Third-party packages declare implementations in ``pyproject.toml`` under
``keystone_mcp.login_providers`` and ``keystone_mcp.user_directories``.
Keystone loads only the entry selected in configuration (``ep.load()`` by
name), not every declared plugin at startup.

Factory rules:

- Validate ``options`` and raise ``ValueError`` with a clear message; Keystone
  prefixes it with the provider or directory name when reporting.
- Do not perform network I/O in the factory (network belongs in ``warm_up`` /
  ``ping``).
- Read secrets only through :meth:`PluginContext.secret`.
"""

from __future__ import annotations

import functools
import importlib.metadata
import os
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.metadata import EntryPoint
from typing import Any, Literal, Protocol

from keystone_mcp.config import ConfigError
from keystone_mcp.login.protocol import LoginProvider
from keystone_mcp.user_directory.protocol import UserDirectory

LOGIN_PROVIDERS_GROUP = "keystone_mcp.login_providers"
USER_DIRECTORIES_GROUP = "keystone_mcp.user_directories"

_BUILTIN_LOGIN_NAMES = frozenset({"oidc", "google", "api_key"})
_BUILTIN_DIRECTORY_NAMES = frozenset({"local", "http"})

_RESERVED_BY_GROUP: dict[str, frozenset[str]] = {
    LOGIN_PROVIDERS_GROUP: _BUILTIN_LOGIN_NAMES,
    USER_DIRECTORIES_GROUP: _BUILTIN_DIRECTORY_NAMES,
}


class PluginConflictError(ConfigError):
    """Two distributions declared the same plugin name, or a reserved name."""


@dataclass(frozen=True, slots=True)
class PluginContext:
    """Runtime context passed to plugin factories."""

    base_url: str
    deployment_profile: Literal["local", "production"]
    http_timeout_seconds: float
    # keystone_mcp.config.Settings — internal; not part of the stable contract.
    settings: object
    # Used by built-in api_key login only; not part of the stable contract.
    user_resolver: object | None = None

    def secret(self, env_name: str) -> str:
        """Return an environment variable value or raise :class:`ConfigError`."""
        value = os.environ.get(env_name, "").strip()
        if not value:
            raise ConfigError(
                f"environment variable {env_name!r} is missing or empty"
            )
        return value


@dataclass(frozen=True, slots=True)
class LoginProviderConfig:
    name: str
    type: str
    title: str | None
    options: Mapping[str, Any]


class LoginProviderFactory(Protocol):
    def __call__(
        self, config: LoginProviderConfig, context: PluginContext
    ) -> LoginProvider: ...


class UserDirectoryFactory(Protocol):
    def __call__(
        self, context: PluginContext, options: Mapping[str, Any]
    ) -> UserDirectory: ...


def keystone_distribution() -> str:
    """Return the PyPI distribution name that provides ``keystone_mcp``."""
    mapping = importlib.metadata.packages_distributions()
    names = list(mapping.get("keystone_mcp") or [])
    if not names:
        for ep in importlib.metadata.entry_points(group=LOGIN_PROVIDERS_GROUP):
            if ep.name == "oidc" and ep.dist is not None:
                return ep.dist.metadata["Name"]
        raise ConfigError(
            "keystone_mcp is not installed as a package; run `uv sync` so "
            "entry points are registered"
        )
    if len(names) > 1:
        joined = ", ".join(sorted(names))
        raise ConfigError(
            f"several distributions provide the keystone_mcp module: {joined}; "
            "uninstall the unrelated one"
        )
    return names[0]


def _entry_dist_name(ep: EntryPoint) -> str:
    dist = ep.dist
    if dist is None:
        return "<unknown distribution>"
    return dist.metadata["Name"]


def _entry_dist_version(ep: EntryPoint) -> str:
    dist = ep.dist
    if dist is None:
        return "?"
    return dist.version


def entry_point_label(ep: EntryPoint) -> tuple[str, str, str]:
    """Return ``(distribution name, version, module:attr)`` for an entry point."""
    return _entry_dist_name(ep), _entry_dist_version(ep), ep.value


def is_builtin_entry(group: str, name: str, ep: EntryPoint) -> bool:
    reserved = _RESERVED_BY_GROUP.get(group, frozenset())
    if name not in reserved:
        return False
    try:
        ks_dist = keystone_distribution()
    except ConfigError:
        return False
    return _entry_dist_name(ep) == ks_dist


@functools.cache
def discover(group: str) -> dict[str, EntryPoint]:
    """Return entry points in ``group``, keyed by name (process-cached)."""
    eps = list(importlib.metadata.entry_points(group=group))
    by_name: dict[str, list[EntryPoint]] = defaultdict(list)
    for ep in eps:
        by_name[ep.name].append(ep)

    try:
        ks_dist = keystone_distribution()
    except ConfigError:
        ks_dist = None

    reserved = _RESERVED_BY_GROUP.get(group, frozenset())
    result: dict[str, EntryPoint] = {}
    for name, group_eps in by_name.items():
        if len(group_eps) > 1:
            a, b = group_eps[0], group_eps[1]
            raise PluginConflictError(
                f"plugin name {name!r} in {group} is provided by both "
                f"{_entry_dist_name(a)} {_entry_dist_version(a)} and "
                f"{_entry_dist_name(b)} {_entry_dist_version(b)}"
            )
        ep = group_eps[0]
        if name in reserved and ks_dist is not None and _entry_dist_name(ep) != ks_dist:
            raise PluginConflictError(
                f"plugin name {name!r} in {group} is reserved for the built-in "
                f"implementation; {_entry_dist_name(ep)} {_entry_dist_version(ep)} "
                "cannot claim it"
            )
        result[name] = ep
    return result


def _reset_cache() -> None:
    if hasattr(discover, "cache_clear"):
        discover.cache_clear()


def load_factory(group: str, name: str) -> object:
    """Load and return the callable behind an entry point ``name`` in ``group``."""
    try:
        eps = discover(group)
    except PluginConflictError:
        raise
    ep = eps.get(name)
    if ep is None:
        available = ", ".join(sorted(eps)) or "(none)"
        raise ConfigError(
            f"no {group} plugin named {name!r}; available: {available}. "
            "Install the package that provides it; if this is a source checkout, "
            "run `uv sync` so entry points are registered"
        )
    dist = _entry_dist_name(ep)
    try:
        return ep.load()
    except ImportError as exc:
        raise ConfigError(
            f"{group} '{name}' from {dist} failed to import: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def list_plugin_entries(
    group: str,
) -> tuple[list[tuple[str, EntryPoint]], list[str]]:
    """List entry points and any conflict error lines (without importing factories)."""
    errors: list[str] = []
    try:
        eps = discover(group)
    except PluginConflictError as exc:
        return [], [str(exc)]
    rows = sorted((name, ep) for name, ep in eps.items())
    return rows, errors


def build_plugin_context(
    settings: object,
    *,
    user_resolver: object | None = None,
) -> PluginContext:
    from keystone_mcp.config import Settings

    if not isinstance(settings, Settings):
        raise TypeError("settings must be keystone_mcp.config.Settings")
    return PluginContext(
        base_url=settings.base_url,
        deployment_profile=settings.deployment_profile,
        http_timeout_seconds=10.0,
        settings=settings,
        user_resolver=user_resolver,
    )
