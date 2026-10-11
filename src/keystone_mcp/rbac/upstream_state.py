"""Upstream catalog availability, as consumed by the RBAC policy gate (P06).

Kept separate from :mod:`keystone_mcp.rbac.loader` and
:mod:`keystone_mcp.router.upstream` so that ``router.upstream`` can build a
:class:`UpstreamCatalogState` without creating an import cycle: ``rbac.loader``
already imports from ``router.registry``, so ``router`` code cannot import
``rbac.loader`` back; it can safely import this leaf module instead.
"""

from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass

#: Characters that start a glob metacharacter in an allow pattern.
_GLOB_METACHARACTERS = frozenset("*?[")


@dataclass(frozen=True, slots=True)
class UpstreamCatalogState:
    """Snapshot of registered upstream namespaces and which ones are down.

    ``namespaces`` is every namespace currently registered with the
    :class:`~keystone_mcp.router.upstream.UpstreamRegistry` (a disabled
    upstream is never registered, so it is never a member here).
    ``unavailable`` is the subset whose last discovery or refresh attempt
    failed (including "never discovered yet").
    ``unpublishable`` is the set of fully-published names (``<namespace>_<tool>``)
    that the upstream currently offers but that could not be turned into a
    FastMCP tool (e.g. a schema with a parameter named ``from``). Unlike
    ``unavailable``, the owning namespace here is reachable; only this one
    tool is missing from the live catalog.
    """

    namespaces: frozenset[str]
    unavailable: frozenset[str]
    unpublishable: frozenset[str] = frozenset()


#: Supplies the current upstream state on demand (called at validation time,
#: never cached, so it always reflects the latest discovery/refresh outcome).
UpstreamCatalogStateProvider = Callable[[], UpstreamCatalogState]


def pattern_head(pattern: str) -> str:
    """Portion of an allow pattern before its first glob metacharacter.

    A pattern with no glob metacharacter is its own head in full.
    """
    for index, char in enumerate(pattern):
        if char in _GLOB_METACHARACTERS:
            return pattern[:index]
    return pattern


def pattern_owner(pattern: str, namespaces: Collection[str]) -> str | None:
    """The namespace an allow pattern belongs to, or ``None`` if it has none.

    The owner is the longest registered namespace ``N`` such that the
    pattern's head starts with ``N + "_"``. "Longest" so that, when both
    ``billing`` and ``billing_admin`` are registered, ``billing_admin_*``
    belongs to ``billing_admin`` rather than ``billing``. A pattern whose
    head has no such namespace prefix (for example a glob that starts at
    position 0, like ``*_search``, or a head with no trailing ``_`` boundary,
    like ``doc*`` against namespace ``docs``) has no owner.
    """
    head = pattern_head(pattern)
    owner: str | None = None
    for namespace in namespaces:
        prefix = namespace + "_"
        if head.startswith(prefix) and (owner is None or len(namespace) > len(owner)):
            owner = namespace
    return owner
