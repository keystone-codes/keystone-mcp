"""Postgres contract tests for the built-in ``local`` users directory."""

from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest

from keystone_mcp.contract_tests import (
    AdminDirectoryContract,
    ApiKeyDirectoryContract,
    ServiceAccountDirectoryContract,
    seed_contract_dataset,
)
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory
from keystone_mcp.user_directory.revision import InMemoryRevisionReader
from keystone_mcp.users.revision import InProcessRevisionWriter
from keystone_mcp.users.store import UsersStore
from support.users_db import postgres_engine  # noqa: F401 -- fixture import

pytest_plugins = ["keystone_mcp.contract_tests"]


@pytest.fixture
def keystone_directory_factory(postgres_engine) -> Callable[[], Awaitable[UserDirectory]]:  # noqa: F811
    counter = 0

    async def factory() -> UserDirectory:
        nonlocal counter
        counter += 1
        revision = InMemoryRevisionReader()
        store = UsersStore(postgres_engine, revision=InProcessRevisionWriter(revision.bump))
        directory = LocalUserDirectory(store)
        await seed_contract_dataset(directory)
        return directory

    return factory


class TestLocalPostgres(
    AdminDirectoryContract, ServiceAccountDirectoryContract, ApiKeyDirectoryContract
):
    pass
