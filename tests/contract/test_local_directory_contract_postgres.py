"""Postgres contract tests for the built-in ``local`` users directory."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import pytest

from keystone_mcp.contract_tests import (
    AdminDirectoryChecks06,
    AdminDirectoryContract,
    ApiKeyDirectoryChecks06,
    ApiKeyDirectoryContract,
    DeletionDirectoryContract,
    IdentityBindingDirectoryContract,
    ServiceAccountDirectoryChecks06,
    ServiceAccountDirectoryContract,
    UserDirectoryChecks06,
    seed_contract_dataset,
)
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.protocol import UserDirectory
from keystone_mcp.user_directory.revision import InMemoryRevisionReader
from keystone_mcp.users import models as users_models
from keystone_mcp.users import service as users_service
from keystone_mcp.users.revision import InProcessRevisionWriter
from keystone_mcp.users.store import UsersStore
from support.users_db import postgres_engine  # noqa: F401 -- fixture import


@pytest.fixture
def _revision_holder() -> dict[str, InMemoryRevisionReader]:
    return {}


@pytest.fixture
def keystone_directory_factory(
    postgres_engine,  # noqa: F811
    _revision_holder: dict[str, InMemoryRevisionReader],
) -> Callable[[], Awaitable[UserDirectory]]:
    counter = 0

    async def factory() -> UserDirectory:
        nonlocal counter
        counter += 1
        revision = InMemoryRevisionReader()
        _revision_holder["revision"] = revision
        store = UsersStore(postgres_engine, revision=InProcessRevisionWriter(revision.bump))
        directory = LocalUserDirectory(store)
        await seed_contract_dataset(directory)
        return directory

    return factory


@pytest.fixture
def keystone_revision_probe(
    _revision_holder: dict[str, InMemoryRevisionReader],
) -> Callable[[], Awaitable[int]]:
    async def probe() -> int:
        revision = _revision_holder.get("revision")
        if revision is None:
            raise RuntimeError("keystone_directory_factory must run before keystone_revision_probe")
        return await revision.current()

    return probe


@pytest.fixture
def keystone_advance_clock(monkeypatch) -> Callable[[float], None]:
    anchor = datetime(2026, 6, 1, 12, 0, 0, tzinfo=UTC)
    offset = 0.0

    def advance(seconds: float) -> None:
        nonlocal offset
        offset += seconds

    def fake_utcnow() -> datetime:
        return anchor + timedelta(seconds=offset)

    monkeypatch.setattr(users_models, "utcnow", fake_utcnow)
    monkeypatch.setattr(users_service, "utcnow", fake_utcnow)
    return advance


@pytest.fixture
def keystone_unavailable_directory_factory(
    postgres_engine,  # noqa: F811
) -> Callable[[], Awaitable[UserDirectory]]:
    async def factory() -> UserDirectory:
        revision = InMemoryRevisionReader()
        store = UsersStore(postgres_engine, revision=InProcessRevisionWriter(revision.bump))
        directory = LocalUserDirectory(store)
        await seed_contract_dataset(directory)
        store.dispose()
        return directory

    return factory


class TestLocalPostgres(
    AdminDirectoryContract,
    AdminDirectoryChecks06,
    UserDirectoryChecks06,
    ServiceAccountDirectoryContract,
    ServiceAccountDirectoryChecks06,
    ApiKeyDirectoryContract,
    ApiKeyDirectoryChecks06,
    IdentityBindingDirectoryContract,
    DeletionDirectoryContract,
):
    pass
