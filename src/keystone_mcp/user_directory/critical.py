"""Critical tools: role resolution must be synchronous (allow cache bypassed).

The critical set is the union of two sources:

* ``CORE_CRITICAL_PATTERNS`` — platform primitives registered by the core
  catalog (user administration). A stale allow decision on these is a
  privilege or data-exposure risk.
* ``critical_tools`` in the active RBAC policy file — per-deployment additions.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from fnmatch import fnmatch

#: Always critical: registered by the core catalog, never customer tools.
CORE_CRITICAL_PATTERNS: tuple[str, ...] = ("users_*", "service_accounts_*")


def is_critical_tool(tool_name: str, policy_patterns: Iterable[str] = ()) -> bool:
    """Return True when the tool must resolve roles synchronously."""
    if _matches(tool_name, CORE_CRITICAL_PATTERNS):
        return True
    return _matches(tool_name, tuple(policy_patterns))


class CriticalToolMatcher:
    """Reusable matcher over the core built-ins plus policy patterns."""

    __slots__ = ("_patterns",)

    def __init__(self, policy_patterns: Iterable[str] = ()) -> None:
        self._patterns: tuple[str, ...] = CORE_CRITICAL_PATTERNS + tuple(policy_patterns)

    @property
    def patterns(self) -> tuple[str, ...]:
        return self._patterns

    def matches(self, tool_name: str) -> bool:
        return _matches(tool_name, self._patterns)


def _matches(tool_name: str, patterns: Sequence[str]) -> bool:
    return any(pattern == "*" or fnmatch(tool_name, pattern) for pattern in patterns)
