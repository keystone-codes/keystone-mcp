"""Optional base classes for login provider plugins.

Inheriting these classes is not required. They provide no-op ``warm_up`` and
``aclose``, default ``interactive`` as ``True``, and will gain defaults for
future optional login protocols before 2.0.
"""

from __future__ import annotations


class LoginProviderBase:
    """Optional convenience base for ``LoginProvider`` implementations."""

    @property
    def interactive(self) -> bool:
        return True

    async def warm_up(self) -> None:
        return None

    async def aclose(self) -> None:
        return None


class RedirectLoginProviderBase(LoginProviderBase):
    """Optional base for ``RedirectLoginProvider`` implementations."""


class FormLoginProviderBase(LoginProviderBase):
    """Optional base for ``FormLoginProvider`` implementations."""
