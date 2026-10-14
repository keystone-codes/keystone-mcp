"""Contract tests for ``InMemoryUserDirectory``."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest

from keystone_mcp.contract_tests import (
    AdminDirectoryContract,
    DeletionDirectoryContract,
    ServiceAccountDirectoryContract,
    seed_contract_dataset,
)
from keystone_mcp.user_directory.memory import InMemoryUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory


@pytest.fixture
def keystone_directory_factory() -> Callable[[], Awaitable[UserDirectory]]:
    async def factory() -> UserDirectory:
        directory = InMemoryUserDirectory()
        await seed_contract_dataset(directory)
        return directory

    return factory


@pytest.mark.keystone_contract_lenient(reason="in-memory directory cannot be unavailable")
class TestMemoryDirectory(
    AdminDirectoryContract,
    ServiceAccountDirectoryContract,
    DeletionDirectoryContract,
):
    pass
