"""Contract tests for ``HttpUserDirectory``."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path

import httpx
import pytest

from keystone_mcp.contract_tests import AdminDirectoryContract, seed_contract_dataset
from keystone_mcp.user_directory.http import HttpUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory
from support.fake_users_service import build_fake_users_service
from support.users_store import make_users_store

pytest_plugins = ["keystone_mcp.contract_tests"]

TOKEN = "contract-test-token"


@pytest.fixture
def keystone_directory_factory(tmp_path: Path) -> Callable[[], Awaitable[UserDirectory]]:
    counter = 0

    async def factory() -> UserDirectory:
        nonlocal counter
        counter += 1
        directory_path = tmp_path / f"http-{counter}"
        directory_path.mkdir(parents=True, exist_ok=True)
        store, _revision = await make_users_store(directory_path)
        app = build_fake_users_service(store, token=TOKEN)
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://fake-users.test",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        directory = HttpUserDirectory(
            base_url="http://fake-users.test",
            service_token=TOKEN,
            timeout_seconds=5.0,
            client=client,
        )
        await seed_contract_dataset(directory)
        return directory

    return factory


@pytest.fixture
def keystone_unavailable_directory_factory() -> Callable[[], Awaitable[UserDirectory]]:
    async def factory() -> UserDirectory:
        return HttpUserDirectory(
            base_url="http://127.0.0.1:1",
            service_token=TOKEN,
            timeout_seconds=0.5,
        )

    return factory


class TestHttpDirectory(AdminDirectoryContract):
    pass
