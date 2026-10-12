"""Contract tests for ``InMemoryUserDirectory``."""

from __future__ import annotations

pytest_plugins = ["keystone_mcp.contract_tests"]

from collections.abc import Awaitable, Callable

import pytest

from keystone_mcp.contract_tests import (
    AdminDirectoryContract,
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


class TestMemoryDirectory(AdminDirectoryContract, ServiceAccountDirectoryContract):
    pass
