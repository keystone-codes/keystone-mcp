"""Optional base classes for user-directory plugins.

Inheriting these classes is not required. They provide no-op defaults for
``ping`` and ``aclose``, an empty default ``capabilities``, and will gain
default implementations for future optional protocols before 2.0.
"""

from __future__ import annotations


class UserDirectoryBase:
    """Optional convenience base for ``UserDirectory`` implementations."""

    @property
    def capabilities(self) -> frozenset[str]:
        return frozenset()

    async def ping(self) -> None:
        return None

    async def aclose(self) -> None:
        return None


class UserDirectoryAdminBase(UserDirectoryBase):
    """Optional base for directories that declare the ``admin`` capability."""


class ServiceAccountDirectoryBase(UserDirectoryBase):
    """Optional base for directories that declare ``service_accounts``."""


class ApiKeyDirectoryBase(UserDirectoryBase):
    """Optional base for directories that declare ``api_keys``."""


class UserDeletionDirectoryBase(UserDirectoryBase):
    """Optional base for directories that declare the ``delete`` capability."""
