"""Contract tests for the built-in ``local`` users directory."""

from __future__ import annotations

import shutil
from collections.abc import Awaitable, Callable

import pytest

from keystone_mcp.contract_tests import (
    AdminDirectoryContract,
    ApiKeyDirectoryContract,
    IdentityBindingDirectoryContract,
    ServiceAccountDirectoryContract,
    seed_contract_dataset,
)
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory
from support.users_store import make_users_store


def _sqlite_factory(tmp_path) -> Callable[[], Awaitable[UserDirectory]]:
    counter = 0

    async def factory() -> UserDirectory:
        nonlocal counter
        counter += 1
        root = tmp_path / f"local-{counter}"
        root.mkdir(parents=True, exist_ok=True)
        store, _revision = await make_users_store(root)
        directory = LocalUserDirectory(store)
        await seed_contract_dataset(directory)
        return directory

    return factory


@pytest.fixture
def keystone_directory_factory(tmp_path) -> Callable[[], Awaitable[UserDirectory]]:
    return _sqlite_factory(tmp_path)


@pytest.fixture
def keystone_unavailable_directory_factory(tmp_path) -> Callable[[], Awaitable[UserDirectory]]:
    async def factory() -> UserDirectory:
        root = tmp_path / "local-unavailable"
        root.mkdir(parents=True, exist_ok=True)
        store, _revision = await make_users_store(root)
        directory = LocalUserDirectory(store)
        await seed_contract_dataset(directory)
        store.dispose()
        shutil.rmtree(root)
        return directory

    return factory


class TestLocalSqlite(
    AdminDirectoryContract,
    ServiceAccountDirectoryContract,
    ApiKeyDirectoryContract,
    IdentityBindingDirectoryContract,
):
    pass
