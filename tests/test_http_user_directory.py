"""``HttpUserDirectory`` against the fake HTTP users directory contract.

Every operation is checked against :class:`LocalUserDirectory` acting on an
identical, separately-seeded store: both directories must agree on the
resulting :class:`UserRecord` (ignoring timestamps, which naturally differ
between two independent writes). Error-code normalization (HTTP users error-code normalization) and
the timeout/connection-error mapping get their own tests.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from keystone_mcp.user_directory.cache import ApiKeyVerificationCache, ResolutionCache
from keystone_mcp.user_directory.circuit_breaker import CircuitBreaker
from keystone_mcp.user_directory.errors import (
    DirectoryTimeoutError,
    UserDirectoryUnavailableError,
    UsersError,
    UsersStoreUnavailableError,
)
from keystone_mcp.user_directory.http import (
    HttpUserDirectory,
    reset_directory_response_issue_warnings,
)
from keystone_mcp.user_directory.local import LocalUserDirectory
from keystone_mcp.user_directory.resolver import CachedUserDirectoryResolver
from keystone_mcp.user_directory.revision import InMemoryRevisionReader
from support.fake_users_service import build_fake_users_service
from support.users_store import make_users_store

TOKEN = "test-service-token"
ACTOR = "admin@example.com"


def _directory_with_handler(handler) -> HttpUserDirectory:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://fake-users.test",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    return HttpUserDirectory(
        base_url="http://fake-users.test", service_token=TOKEN, timeout_seconds=1.0, client=client
    )


async def _make_http_directory(tmp_path: Path, name: str) -> HttpUserDirectory:
    directory_path = tmp_path / name
    directory_path.mkdir(parents=True, exist_ok=True)
    store, _revision = await make_users_store(directory_path)
    app = build_fake_users_service(store, token=TOKEN)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://fake-users.test",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    return HttpUserDirectory(
        base_url="http://fake-users.test",
        service_token=TOKEN,
        timeout_seconds=5.0,
        client=client,
    )


async def _make_local_directory(tmp_path: Path, name: str) -> LocalUserDirectory:
    directory_path = tmp_path / name
    directory_path.mkdir(parents=True, exist_ok=True)
    store, _revision = await make_users_store(directory_path)
    return LocalUserDirectory(store)


def _without_timestamps(payload: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in payload.items() if k not in ("created_at", "updated_at")}


@pytest.fixture
async def directories(tmp_path: Path) -> tuple[HttpUserDirectory, LocalUserDirectory]:
    http_directory = await _make_http_directory(tmp_path, "http")
    local_directory = await _make_local_directory(tmp_path, "local")
    yield http_directory, local_directory
    await http_directory.aclose()
    await local_directory.aclose()


@pytest.mark.asyncio
async def test_create_user_matches_local(directories) -> None:
    http_directory, local_directory = directories
    http_result = await http_directory.create_user(
        email="new@example.com", full_name="New", roles=["operator"], note="hi", actor=ACTOR
    )
    local_result = await local_directory.create_user(
        email="new@example.com", full_name="New", roles=["operator"], note="hi", actor=ACTOR
    )
    assert _without_timestamps(http_result.user.to_dict()) == _without_timestamps(
        local_result.user.to_dict()
    )
    assert http_result.changed is True
    assert local_result.changed is True


@pytest.mark.asyncio
async def test_update_user_matches_local(directories) -> None:
    http_directory, local_directory = directories
    for directory in (http_directory, local_directory):
        await directory.create_user(
            email="user@example.com", full_name="Old", roles=[], note=None, actor=ACTOR
        )
    http_result = await http_directory.update_user(
        email="user@example.com", full_name="New Name", note=None, actor=ACTOR
    )
    local_result = await local_directory.update_user(
        email="user@example.com", full_name="New Name", note=None, actor=ACTOR
    )
    assert _without_timestamps(http_result.user.to_dict()) == _without_timestamps(
        local_result.user.to_dict()
    )


@pytest.mark.asyncio
async def test_set_blocked_matches_local(directories) -> None:
    http_directory, local_directory = directories
    for directory in (http_directory, local_directory):
        await directory.create_user(
            email="user@example.com", full_name="User", roles=[], note=None, actor=ACTOR
        )
    http_result = await http_directory.set_blocked(
        email="user@example.com", blocked=True, actor=ACTOR
    )
    local_result = await local_directory.set_blocked(
        email="user@example.com", blocked=True, actor=ACTOR
    )
    assert _without_timestamps(http_result.user.to_dict()) == _without_timestamps(
        local_result.user.to_dict()
    )
    assert http_result.user.is_blocked is True


@pytest.mark.asyncio
async def test_replace_roles_matches_local(directories) -> None:
    http_directory, local_directory = directories
    for directory in (http_directory, local_directory):
        await directory.create_user(
            email="user@example.com", full_name="User", roles=["member"], note=None, actor=ACTOR
        )
    http_result = await http_directory.replace_roles(
        email="user@example.com", roles=["operator", "analyst"], actor=ACTOR
    )
    local_result = await local_directory.replace_roles(
        email="user@example.com", roles=["operator", "analyst"], actor=ACTOR
    )
    assert _without_timestamps(http_result.user.to_dict()) == _without_timestamps(
        local_result.user.to_dict()
    )


@pytest.mark.asyncio
async def test_grant_role_matches_local(directories) -> None:
    http_directory, local_directory = directories
    for directory in (http_directory, local_directory):
        await directory.create_user(
            email="user@example.com", full_name="User", roles=[], note=None, actor=ACTOR
        )
    http_result = await http_directory.grant_role(
        email="user@example.com", role="operator", actor=ACTOR
    )
    local_result = await local_directory.grant_role(
        email="user@example.com", role="operator", actor=ACTOR
    )
    assert _without_timestamps(http_result.user.to_dict()) == _without_timestamps(
        local_result.user.to_dict()
    )


@pytest.mark.asyncio
async def test_revoke_role_matches_local(directories) -> None:
    http_directory, local_directory = directories
    for directory in (http_directory, local_directory):
        await directory.create_user(
            email="user@example.com",
            full_name="User",
            roles=["operator", "analyst"],
            note=None,
            actor=ACTOR,
        )
    http_result = await http_directory.revoke_role(
        email="user@example.com", role="operator", actor=ACTOR
    )
    local_result = await local_directory.revoke_role(
        email="user@example.com", role="operator", actor=ACTOR
    )
    assert _without_timestamps(http_result.user.to_dict()) == _without_timestamps(
        local_result.user.to_dict()
    )


@pytest.mark.asyncio
async def test_list_users_matches_local(directories) -> None:
    http_directory, local_directory = directories
    for directory in (http_directory, local_directory):
        await directory.create_user(
            email="a@example.com", full_name="A", roles=["operator"], note=None, actor=ACTOR
        )
        await directory.create_user(
            email="b@example.com", full_name="B", roles=["analyst"], note=None, actor=ACTOR
        )
    http_rows = [_without_timestamps(r.to_dict()) for r in await http_directory.list_users()]
    local_rows = [_without_timestamps(r.to_dict()) for r in await local_directory.list_users()]
    assert http_rows == local_rows


@pytest.mark.asyncio
async def test_resolve_user_matches_local(directories) -> None:
    http_directory, local_directory = directories
    for directory in (http_directory, local_directory):
        await directory.create_user(
            email="user@example.com", full_name="User", roles=["operator"], note=None, actor=ACTOR
        )
    http_result = await http_directory.resolve_user("user@example.com")
    local_result = await local_directory.resolve_user("user@example.com")
    assert http_result.exists == local_result.exists
    assert http_result.roles == local_result.roles
    assert http_result.is_blocked == local_result.is_blocked


@pytest.mark.asyncio
async def test_invalid_role_code_is_normalized(directories) -> None:
    """The fake service reports ``invalid_role`` (its own legacy code, S3);

    HttpUserDirectory must normalize it to the skill's ``validation_error``.
    An all-whitespace role name is the one shape ``check_role_name`` rejects
    on format alone (role names otherwise have no character restrictions).
    """
    http_directory, _local_directory = directories
    await http_directory.create_user(
        email="user@example.com", full_name="User", roles=[], note=None, actor=ACTOR
    )
    with pytest.raises(UsersError) as exc_info:
        await http_directory.grant_role(email="user@example.com", role="   ", actor=ACTOR)
    assert exc_info.value.code == "validation_error"


@pytest.mark.asyncio
async def test_user_already_exists_is_normalized(directories) -> None:
    """The fake service reports ``user_already_exists`` (legacy code, S3);

    HttpUserDirectory must normalize it to the skill's ``conflict``.
    """
    http_directory, _local_directory = directories
    await http_directory.create_user(
        email="dup@example.com", full_name="Dup", roles=[], note=None, actor=ACTOR
    )
    with pytest.raises(UsersError) as exc_info:
        await http_directory.create_user(
            email="dup@example.com", full_name="Dup", roles=[], note=None, actor=ACTOR
        )
    assert exc_info.value.code == "conflict"


@pytest.mark.asyncio
async def test_timeout_is_service_timeout() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out")

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://fake-users.test",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    directory = HttpUserDirectory(
        base_url="http://fake-users.test", service_token=TOKEN, timeout_seconds=1.0, client=client
    )
    with pytest.raises(DirectoryTimeoutError) as exc_info:
        await directory.list_users()
    assert exc_info.value.code == "service_timeout"
    await directory.aclose()


@pytest.mark.asyncio
async def test_connection_error_is_service_unavailable() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://fake-users.test",
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    directory = HttpUserDirectory(
        base_url="http://fake-users.test", service_token=TOKEN, timeout_seconds=1.0, client=client
    )
    with pytest.raises(UsersStoreUnavailableError) as exc_info:
        await directory.list_users()
    assert exc_info.value.code == "service_unavailable"
    await directory.aclose()


# ── Malformed response bodies: must become UsersError, not a bare parsing
# exception, so UsersAdminAdapter's error envelope (and audit write) still
# fires even though the service already applied the mutation. ──────────────


@pytest.mark.asyncio
async def test_empty_success_body_is_service_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"")

    directory = _directory_with_handler(handler)
    with pytest.raises(UsersError) as exc_info:
        await directory.create_user(
            email="new@example.com", full_name="New", roles=[], note=None, actor=ACTOR
        )
    assert exc_info.value.code == "service_error"
    await directory.aclose()


@pytest.mark.asyncio
async def test_non_json_success_body_is_service_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json", headers={"content-type": "text/plain"})

    directory = _directory_with_handler(handler)
    with pytest.raises(UsersError) as exc_info:
        await directory.create_user(
            email="new@example.com", full_name="New", roles=[], note=None, actor=ACTOR
        )
    assert exc_info.value.code == "service_error"
    await directory.aclose()


@pytest.mark.asyncio
async def test_record_missing_created_at_is_service_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "email": "new@example.com",
                "full_name": "New",
                "roles": [],
                "is_blocked": False,
                # "created_at" missing entirely.
                "updated_at": "2026-01-01T00:00:00Z",
                "created_by": ACTOR,
                "note": None,
            },
        )

    directory = _directory_with_handler(handler)
    with pytest.raises(UsersError) as exc_info:
        await directory.create_user(
            email="new@example.com", full_name="New", roles=[], note=None, actor=ACTOR
        )
    assert exc_info.value.code == "service_error"
    await directory.aclose()


@pytest.mark.asyncio
async def test_malformed_list_body_is_service_error() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    directory = _directory_with_handler(handler)
    with pytest.raises(UsersError) as exc_info:
        await directory.list_users()
    assert exc_info.value.code == "service_error"
    await directory.aclose()


@pytest.mark.asyncio
async def test_naive_timestamp_is_anchored_to_utc_not_host_timezone() -> None:
    """A service that omits the UTC offset must not have its wall-clock time

    shifted by the host's own local timezone: ``to_dict()`` calls
    ``astimezone(UTC)``, which is a no-op once the naive value is already
    tagged ``UTC`` here, but would otherwise silently shift it.
    """

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "email": "new@example.com",
                "full_name": "New",
                "roles": [],
                "is_blocked": False,
                "created_at": "2026-01-01T12:00:00",  # no offset
                "updated_at": "2026-01-01T12:00:00",
                "created_by": ACTOR,
                "note": None,
            },
        )

    directory = _directory_with_handler(handler)
    result = await directory.create_user(
        email="new@example.com", full_name="New", roles=[], note=None, actor=ACTOR
    )
    assert result.user.created_at == datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    assert result.user.to_dict()["created_at"] == "2026-01-01T12:00:00Z"
    await directory.aclose()


@pytest.mark.asyncio
async def test_list_users_is_blocked_none_requests_all() -> None:
    """``is_blocked=None`` means "no filter" on the local directory's own

    store; the HTTP directory used to silently turn it into ``False``
    (blocked users dropped) instead of passing "all" through.
    """
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"users": [], "total": 0})

    directory = _directory_with_handler(handler)
    await directory.list_users(is_blocked=None)
    assert "is_blocked" not in captured["params"]
    await directory.aclose()


def _metric_value(field: str, issue: str) -> float | None:
    from prometheus_client import REGISTRY

    return REGISTRY.get_sample_value(
        "keystone_mcp_users_directory_response_issues_total",
        {"field": field, "issue": issue},
    )


@pytest.mark.asyncio
async def test_resolve_exists_string_is_unavailable() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"exists": "false", "roles": ["administrator"], "is_blocked": False},
        )

    directory = _directory_with_handler(handler)
    with pytest.raises(UserDirectoryUnavailableError) as exc_info:
        await directory.resolve_user("user@example.com")
    assert exc_info.value.code == "catalog_unavailable"
    await directory.aclose()


@pytest.mark.asyncio
async def test_resolve_missing_exists_is_unavailable() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"roles": [], "is_blocked": False})

    directory = _directory_with_handler(handler)
    with pytest.raises(UserDirectoryUnavailableError):
        await directory.resolve_user("user@example.com")
    await directory.aclose()


@pytest.mark.asyncio
async def test_resolve_exists_integer_is_accepted_with_warning(caplog) -> None:
    reset_directory_response_issue_warnings()
    before = _metric_value("exists", "integer") or 0.0

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"exists": 1, "roles": ["member"], "is_blocked": 0})

    directory = _directory_with_handler(handler)
    with caplog.at_level("WARNING", logger="keystone_mcp.user_directory.http"):
        first = await directory.resolve_user("user@example.com")
        second = await directory.resolve_user("user@example.com")
    assert first.exists is True
    assert first.is_blocked is False
    assert second.exists is True
    integer_warnings = [
        r.message
        for r in caplog.records
        if r.levelname == "WARNING" and "exists is integer" in r.message
    ]
    assert len(integer_warnings) == 1
    after = _metric_value("exists", "integer") or 0.0
    assert after - before == 2.0
    await directory.aclose()


@pytest.mark.asyncio
async def test_resolve_missing_is_blocked_warns_once(caplog) -> None:
    reset_directory_response_issue_warnings()
    before = _metric_value("is_blocked", "missing") or 0.0

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"exists": True, "roles": ["member"]})

    directory = _directory_with_handler(handler)
    with caplog.at_level("WARNING", logger="keystone_mcp.user_directory.http"):
        first = await directory.resolve_user("user@example.com")
        await directory.resolve_user("user@example.com")
    assert first.is_blocked is False
    missing_warnings = [
        r.message
        for r in caplog.records
        if r.levelname == "WARNING" and "is_blocked is missing" in r.message
    ]
    assert len(missing_warnings) == 1
    after = _metric_value("is_blocked", "missing") or 0.0
    assert after - before == 2.0
    await directory.aclose()


@pytest.mark.asyncio
async def test_resolve_roles_with_null_is_unavailable() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"exists": True, "roles": [None], "is_blocked": False})

    directory = _directory_with_handler(handler)
    with pytest.raises(UserDirectoryUnavailableError):
        await directory.resolve_user("user@example.com")
    await directory.aclose()


@pytest.mark.asyncio
async def test_resolve_subject_type_read_and_checked() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"exists": True, "roles": ["member"], "is_blocked": False})

    directory = _directory_with_handler(handler)
    human = await directory.resolve_user("user@example.com")
    assert human.subject_type == "human"

    def service_mismatch(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "exists": True,
                "roles": ["member"],
                "is_blocked": False,
                "subject_type": "service",
            },
        )

    bad = _directory_with_handler(service_mismatch)
    with pytest.raises(UserDirectoryUnavailableError):
        await bad.resolve_user("user@example.com")
    await bad.aclose()
    await directory.aclose()


@pytest.mark.asyncio
async def test_resolve_invalid_responses_trip_circuit_breaker() -> None:
    reset_directory_response_issue_warnings()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"exists": "false", "roles": [], "is_blocked": False})

    directory = _directory_with_handler(handler)
    resolver = CachedUserDirectoryResolver(
        directory,
        revision_reader=InMemoryRevisionReader(),
        cache=ResolutionCache(allow_ttl_seconds=60, deny_ttl_seconds=30),
        circuit_breaker=CircuitBreaker(failure_threshold=2, recovery_seconds=30),
        api_key_cache=ApiKeyVerificationCache(allow_ttl_seconds=60, deny_ttl_seconds=30),
    )
    for _ in range(2):
        with pytest.raises(UserDirectoryUnavailableError) as exc_info:
            await resolver.resolve("user@example.com")
        assert exc_info.value.code == "catalog_unavailable"
    with pytest.raises(UserDirectoryUnavailableError) as exc_info:
        await resolver.resolve("user@example.com")
    assert exc_info.value.code == "circuit_open"
    await resolver.aclose()
    await directory.aclose()
