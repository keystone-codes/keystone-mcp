"""Tests for the fail-closed user-directory resolver."""

from __future__ import annotations

import time

import httpx
import pytest

from keystone_mcp.config import Settings
from keystone_mcp.user_directory import (
    UserDirectoryUnavailableError,
    build_in_memory_user_directory_resolver,
    build_user_directory_resolver,
    is_critical_tool,
)
from keystone_mcp.user_directory.cache import ApiKeyVerificationCache, ResolutionCache
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker
from keystone_mcp.user_directory.http import HttpUserDirectory
from keystone_mcp.user_directory.memory import InMemoryUserDirectoryBackend
from keystone_mcp.user_directory.models import UserResolveResult
from keystone_mcp.user_directory.resolver import CachedUserDirectoryResolver
from keystone_mcp.user_directory.revision import InMemoryRevisionReader, RedisRevisionReader


class _FakeRedis:
    def __init__(
        self,
        *,
        value: str | None = None,
        error: Exception | None = None,
    ) -> None:
        self._value = value
        self._error = error
        self.closed = False

    async def get(self, key: str) -> str | None:
        if self._error is not None:
            raise self._error
        return self._value

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("users_list", True),
        ("users_block", True),
        ("reports_read", False),
        ("documents_write", False),
        ("ledger_commit", False),
    ],
)
def test_core_critical_tools_need_no_policy(tool_name: str, expected: bool) -> None:
    assert is_critical_tool(tool_name) is expected


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("ledger_commit", True),
        ("ledger_read", True),
        ("users_list", True),
        ("reports_read", False),
    ],
)
def test_policy_patterns_extend_critical_tools(tool_name: str, expected: bool) -> None:
    assert is_critical_tool(tool_name, ("ledger_*",)) is expected


@pytest.mark.asyncio
async def test_resolve_known_user_returns_roles_and_block_state() -> None:
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed("operator@example.com", roles=("operator", "analyst"))

    result = await resolver.resolve("operator@example.com")

    assert result.exists is True
    assert result.roles == ("operator", "analyst")
    assert result.is_blocked is False
    assert result.from_cache is False


@pytest.mark.asyncio
async def test_resolve_unknown_user() -> None:
    resolver, _, _ = build_in_memory_user_directory_resolver()

    result = await resolver.resolve("missing@example.com")

    assert result.exists is False
    assert result.roles == ()
    assert result.is_blocked is False


@pytest.mark.asyncio
async def test_resolve_blocked_user() -> None:
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed("blocked@example.com", roles=("operator",), is_blocked=True)

    result = await resolver.resolve("blocked@example.com")

    assert result.exists is True
    assert result.is_blocked is True


@pytest.mark.asyncio
async def test_fail_closed_on_unavailable_backend() -> None:
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.unavailable = True

    with pytest.raises(UserDirectoryUnavailableError) as exc_info:
        await resolver.resolve("user@example.com")

    assert exc_info.value.code == "catalog_unavailable"


@pytest.mark.asyncio
async def test_fail_closed_on_timeout() -> None:
    transport = httpx.MockTransport(
        lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("timed out"))
    )
    client = httpx.AsyncClient(
        transport=transport,
        base_url="http://users.test",
        headers={"Authorization": "Bearer token"},
    )
    backend = HttpUserDirectory(
        base_url="http://users.test",
        service_token="token",
        timeout_seconds=1.0,
        client=client,
    )
    resolver = CachedUserDirectoryResolver(
        backend,
        revision_reader=InMemoryRevisionReader(),
        cache=ResolutionCache(allow_ttl_seconds=60, deny_ttl_seconds=30),
        circuit_breaker=CircuitBreaker(failure_threshold=5, recovery_seconds=30),
        api_key_cache=ApiKeyVerificationCache(allow_ttl_seconds=60, deny_ttl_seconds=30),
    )

    with pytest.raises(UserDirectoryUnavailableError) as exc_info:
        await resolver.resolve("user@example.com")

    assert exc_info.value.code == "catalog_timeout"
    await resolver.aclose()


@pytest.mark.asyncio
async def test_fail_closed_when_circuit_open() -> None:
    resolver, backend, _ = build_in_memory_user_directory_resolver(
        failure_threshold=1,
        recovery_seconds=60,
    )
    backend.unavailable = True

    with pytest.raises(UserDirectoryUnavailableError):
        await resolver.resolve("user@example.com")

    backend.unavailable = False
    backend.seed("user@example.com", roles=("operator",))

    with pytest.raises(UserDirectoryUnavailableError) as exc_info:
        await resolver.resolve("user@example.com")

    assert exc_info.value.code == "circuit_open"


@pytest.mark.asyncio
async def test_unavailable_error_is_distinct_from_missing_user() -> None:
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.unavailable = True

    with pytest.raises(UserDirectoryUnavailableError):
        await resolver.resolve("user@example.com")

    backend.unavailable = False
    result = await resolver.resolve("user@example.com")
    assert isinstance(result, UserResolveResult)
    assert result.exists is False


@pytest.mark.asyncio
async def test_separate_allow_and_deny_ttl() -> None:
    resolver, backend, _ = build_in_memory_user_directory_resolver(
        allow_ttl_seconds=60,
        deny_ttl_seconds=0.05,
    )
    backend.seed("allowed@example.com", roles=("operator",))

    first_allow = await resolver.resolve("allowed@example.com")
    second_allow = await resolver.resolve("allowed@example.com")
    assert first_allow.from_cache is False
    assert second_allow.from_cache is True

    await resolver.resolve("denied@example.com")
    time.sleep(0.06)
    refreshed_deny = await resolver.resolve("denied@example.com")
    assert refreshed_deny.from_cache is False


@pytest.mark.asyncio
async def test_revision_bump_invalidates_cache() -> None:
    resolver, backend, revision = build_in_memory_user_directory_resolver()
    backend.seed("user@example.com", roles=("operator",))

    first = await resolver.resolve("user@example.com")
    cached = await resolver.resolve("user@example.com")
    assert first.from_cache is False
    assert cached.from_cache is True

    revision.bump()
    backend.set_roles("user@example.com", ("analyst",))
    refreshed = await resolver.resolve("user@example.com")
    assert refreshed.from_cache is False
    assert refreshed.roles == ("analyst",)


@pytest.mark.asyncio
async def test_critical_bypasses_allow_cache() -> None:
    resolver, backend, _ = build_in_memory_user_directory_resolver()
    backend.seed("user@example.com", roles=("operator",))

    await resolver.resolve("user@example.com")
    cached = await resolver.resolve("user@example.com")
    assert cached.from_cache is True

    backend.set_roles("user@example.com", ("analyst",))
    critical = await resolver.resolve("user@example.com", critical=True)
    assert critical.from_cache is False
    assert critical.roles == ("analyst",)


@pytest.mark.asyncio
async def test_http_backend_parses_contract_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/users/resolve"
        assert request.headers["Authorization"] == "Bearer secret"
        return httpx.Response(
            200,
            json={"exists": True, "roles": ["operator"], "is_blocked": False},
        )

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://users.test",
        headers={"Authorization": "Bearer secret"},
    )
    backend = HttpUserDirectory(
        base_url="http://users.test",
        service_token="secret",
        timeout_seconds=2.0,
        client=client,
    )

    result = await backend.resolve_user("user@example.com")
    assert result.exists is True
    assert result.roles == ("operator",)
    await backend.aclose()


def test_build_resolver_from_settings(monkeypatch) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_URL", "http://mcp-users:8080")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_TOKEN", "token")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_CACHE_ALLOW_TTL_SECONDS", "120")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_SERVICE_TIMEOUT_SECONDS", "5")
    settings = Settings()
    resolver = build_user_directory_resolver(
        settings,
        revision_reader=InMemoryRevisionReader(),
    )
    assert isinstance(resolver, CachedUserDirectoryResolver)
    assert settings.users_cache_allow_ttl_seconds == 120
    assert settings.users_service_timeout_seconds == 5.0


@pytest.mark.asyncio
async def test_block_change_visible_after_revision_without_restart() -> None:
    resolver, backend, revision = build_in_memory_user_directory_resolver()
    backend.seed("user@example.com", roles=("operator",))

    allowed = await resolver.resolve("user@example.com")
    assert allowed.is_blocked is False

    backend.block("user@example.com")
    revision.bump()
    blocked = await resolver.resolve("user@example.com")
    assert blocked.is_blocked is True
    assert blocked.from_cache is False


@pytest.mark.asyncio
async def test_circuit_recovers_after_success() -> None:
    resolver, backend, _ = build_in_memory_user_directory_resolver(
        failure_threshold=1,
        recovery_seconds=0.01,
    )
    backend.unavailable = True
    with pytest.raises(UserDirectoryUnavailableError):
        await resolver.resolve("user@example.com")

    time.sleep(0.02)
    backend.unavailable = False
    backend.seed("user@example.com", roles=("operator",))
    recovered = await resolver.resolve("user@example.com")
    assert recovered.exists is True


@pytest.mark.asyncio
async def test_redis_revision_reader_maps_connection_errors() -> None:
    from redis.exceptions import ConnectionError

    reader = RedisRevisionReader(
        _FakeRedis(error=ConnectionError("redis down")),
        key="km:users:revision",
    )

    with pytest.raises(UserDirectoryUnavailableError) as exc_info:
        await reader.current()

    assert exc_info.value.code == "revision_unavailable"
    await reader.aclose()


@pytest.mark.asyncio
async def test_redis_revision_reader_rejects_non_numeric_value() -> None:
    reader = RedisRevisionReader(
        _FakeRedis(value="not-a-number"),
        key="km:users:revision",
    )

    with pytest.raises(UserDirectoryUnavailableError) as exc_info:
        await reader.current()

    assert exc_info.value.code == "revision_unavailable"
    await reader.aclose()


@pytest.mark.asyncio
async def test_resolver_propagates_revision_unavailable() -> None:
    from redis.exceptions import ConnectionError

    backend = InMemoryUserDirectoryBackend()
    backend.seed("user@example.com", roles=("operator",))
    resolver = CachedUserDirectoryResolver(
        backend,
        revision_reader=RedisRevisionReader(
            _FakeRedis(error=ConnectionError("redis down")),
            key="km:users:revision",
        ),
        cache=ResolutionCache(allow_ttl_seconds=60, deny_ttl_seconds=30),
        circuit_breaker=CircuitBreaker(failure_threshold=5, recovery_seconds=30),
        api_key_cache=ApiKeyVerificationCache(allow_ttl_seconds=60, deny_ttl_seconds=30),
    )

    with pytest.raises(UserDirectoryUnavailableError) as exc_info:
        await resolver.resolve("user@example.com")

    assert exc_info.value.code == "revision_unavailable"
    await resolver.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [401, 500])
async def test_http_backend_maps_error_status_to_unavailable(status_code: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, text="error")

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://users.test",
        headers={"Authorization": "Bearer secret"},
    )
    backend = HttpUserDirectory(
        base_url="http://users.test",
        service_token="secret",
        timeout_seconds=2.0,
        client=client,
    )

    with pytest.raises(UserDirectoryUnavailableError) as exc_info:
        await backend.resolve_user("user@example.com")

    assert exc_info.value.code == "catalog_unavailable"
    await backend.aclose()


@pytest.mark.asyncio
async def test_http_backend_maps_invalid_json_to_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not-json")

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://users.test",
        headers={"Authorization": "Bearer secret"},
    )
    backend = HttpUserDirectory(
        base_url="http://users.test",
        service_token="secret",
        timeout_seconds=2.0,
        client=client,
    )

    with pytest.raises(UserDirectoryUnavailableError) as exc_info:
        await backend.resolve_user("user@example.com")

    assert exc_info.value.code == "catalog_unavailable"
    await backend.aclose()


@pytest.mark.asyncio
async def test_http_backend_maps_invalid_payload_shape_to_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"exists": True, "roles": "operator"})

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://users.test",
        headers={"Authorization": "Bearer secret"},
    )
    backend = HttpUserDirectory(
        base_url="http://users.test",
        service_token="secret",
        timeout_seconds=2.0,
        client=client,
    )

    with pytest.raises(UserDirectoryUnavailableError) as exc_info:
        await backend.resolve_user("user@example.com")

    assert exc_info.value.code == "catalog_unavailable"
    await backend.aclose()


@pytest.mark.asyncio
async def test_factory_closes_owned_redis_client() -> None:
    reader = RedisRevisionReader(
        _FakeRedis(value="1"),
        key="km:users:revision",
        owns_client=True,
    )
    await reader.aclose()
    assert reader._client.closed is True
