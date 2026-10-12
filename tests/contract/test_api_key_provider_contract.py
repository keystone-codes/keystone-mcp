"""Contract tests for ``ApiKeyLoginProvider``."""

from __future__ import annotations

import pytest

from keystone_mcp.contract_tests import (
    FormLoginProviderContract,
    FormProviderCase,
    seed_contract_dataset,
)
from keystone_mcp.login.api_key import ApiKeyLoginProvider
from keystone_mcp.login.protocol import FormLoginProvider
from keystone_mcp.user_directory.cache import ApiKeyVerificationCache, ResolutionCache
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.resolver import CachedUserDirectoryResolver
from keystone_mcp.user_directory.revision import InMemoryRevisionReader
from support.users_store import make_users_store

pytest_plugins = ["keystone_mcp.contract_tests"]


@pytest.fixture
def keystone_form_provider_case(tmp_path) -> FormProviderCase:
    valid_form = {"email": "bob@example.com", "api_token": ""}
    counter = 0

    async def factory() -> FormLoginProvider:
        nonlocal counter
        counter += 1
        root = tmp_path / f"api-key-{counter}"
        root.mkdir(parents=True, exist_ok=True)
        store, _revision = await make_users_store(root)
        directory = LocalUserDirectory(store)
        await seed_contract_dataset(directory)
        issued = await directory.issue_api_key(
            subject="bob@example.com",
            label="contract",
            expires_in_days=None,
            actor="alice@example.com",
        )
        valid_form["api_token"] = issued.key
        revision_reader = InMemoryRevisionReader()
        resolver = CachedUserDirectoryResolver(
            directory,
            revision_reader=revision_reader,
            cache=ResolutionCache(allow_ttl_seconds=60.0, deny_ttl_seconds=30.0),
            circuit_breaker=CircuitBreaker(failure_threshold=3, recovery_seconds=30.0),
            api_key_cache=ApiKeyVerificationCache(allow_ttl_seconds=60.0, deny_ttl_seconds=30.0),
        )
        return ApiKeyLoginProvider(resolver=resolver, resolve_directory_keys=True)

    return FormProviderCase(
        factory=factory,
        valid_form=valid_form,
        expected_email="bob@example.com",
        invalid_forms=(
            {"email": "bob@example.com", "api_token": "wrong-token"},
            {"email": "alice@example.com", "api_token": "also-wrong"},
        ),
    )


class TestApiKeyLoginProvider(FormLoginProviderContract):
    pass
