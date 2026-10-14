"""Tests for ``keystone-mcp users grant-admin`` and ``keystone-mcp users import``.

The users database is always an isolated SQLite file in ``tmp_path``; Redis is
left unset (``NullRevisionWriter``) for every test except the two that check
the revision bump explicitly, which skip if ``KEYSTONE_MCP_REDIS_URL`` is not
set in the environment running the suite.

``configure_logging`` (called by ``keystone_mcp.cli.main`` before dispatch) is
replaced with a no-op in every test here: it clears and replaces the root
logger's handlers, which would otherwise remove pytest's own ``caplog``
handler the moment a command runs (see ``test_cli_env_file.py`` for the same
pattern applied to settings instead of logging).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from keystone_mcp import cli
from keystone_mcp.cli import main
from keystone_mcp.users import cli as users_cli
from keystone_mcp.users import service
from keystone_mcp.users.db import create_users_engine, make_session_factory, session_scope
from keystone_mcp.users.importer import fetch_source_users
from keystone_mcp.users.migrate import upgrade_to_head
from keystone_mcp.users.records import UserRecord
from keystone_mcp.users.revision import NullRevisionWriter
from keystone_mcp.users.store import UsersStore
from support.test_env import redis_key_prefix, require_redis_url, users_revision_key

_POLICY_YAML = """\
version: "1.0.0"
default_deny: true
roles:
  administrator:
    description: "Full access."
    allow:
      - "*"
  member:
    description: "Everyday access."
    allow:
      - some_tool
"""


@pytest.fixture(autouse=True)
def _quiet_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep ``caplog`` working across a ``cli.main`` call (see module docstring)."""
    monkeypatch.setattr(cli, "configure_logging", lambda settings: None)


@pytest.fixture(autouse=True)
def _no_redis_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default every test to ``NullRevisionWriter``; opt back in explicitly."""
    monkeypatch.delenv("KEYSTONE_MCP_REDIS_URL", raising=False)


def _write_policy(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(_POLICY_YAML, encoding="utf-8")
    return path


def _seed_user(
    db_path: Path,
    *,
    email: str,
    full_name: str = "Someone",
    roles: list[str] | None = None,
    is_blocked: bool = False,
) -> None:
    """Write a user directly through the service layer, bypassing the CLI."""
    engine = create_users_engine(f"sqlite:///{db_path}")
    upgrade_to_head(engine)
    factory = make_session_factory(engine)
    with session_scope(factory) as session:
        service.create_user(
            session,
            email=email,
            full_name=full_name,
            roles=roles or [],
            note=None,
            created_by=None,
            allowed_roles=None,
        )
        if is_blocked:
            service.set_blocked(session, email=email, blocked=True, actor_email="system:test-setup")
    engine.dispose()


def _list_users(db_url: str) -> list[UserRecord]:
    async def _run() -> list[UserRecord]:
        store = UsersStore(create_users_engine(db_url), revision=NullRevisionWriter())
        try:
            return await store.list_users(is_blocked=None)
        finally:
            store.dispose()

    return asyncio.run(_run())


def _user_payload(
    email: str,
    full_name: str,
    roles: list[str],
    is_blocked: bool,
    *,
    note: str | None = None,
    created_by: str | None = None,
    created_at: str | None = None,
    updated_at: str | None = None,
) -> dict:
    return {
        "email": email,
        "full_name": full_name,
        "roles": roles,
        "is_blocked": is_blocked,
        "note": note,
        "created_by": created_by,
        "created_at": created_at,
        "updated_at": updated_at,
    }


def _transport_for(unblocked: list[dict], blocked: list[dict]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        is_blocked = request.url.params.get("is_blocked")
        users = blocked if is_blocked == "true" else unblocked
        return httpx.Response(200, json={"users": users, "total": len(users)})

    return httpx.MockTransport(handler)


def _error_transport(status_code: int, *, code: str | None = None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        body = {"detail": "nope"}
        if code is not None:
            body["code"] = code
        return httpx.Response(status_code, json=body)

    return httpx.MockTransport(handler)


# --- grant-admin -----------------------------------------------------------


def test_grant_admin_creates_user_on_empty_database(tmp_path: Path, monkeypatch, capsys) -> None:
    db_url = f"sqlite:///{tmp_path}/keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)

    # The database does not exist yet: grant-admin requires --create (see
    # test_grant_admin_refuses_new_database_without_create below) precisely
    # so that running it from the wrong working directory does not silently
    # create and write into an unrelated database.
    exit_code = main(["users", "grant-admin", "--email", "Root@Example.com", "--create"])

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "Created administrator: root@example.com"

    users = _list_users(db_url)
    assert len(users) == 1
    assert users[0].email == "root@example.com"
    assert users[0].roles == ("administrator",)
    assert users[0].is_blocked is False


def test_grant_admin_refuses_new_database_without_create(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    db_path = tmp_path / "keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{db_path}")

    exit_code = main(["users", "grant-admin", "--email", "root@example.com"])

    assert exit_code == 1
    err = capsys.readouterr().err
    # Must not also claim a database "will be created" right before refusing
    # to create one -- that reads as a contradiction. The refusal names the
    # path and the flag that would allow it instead.
    assert "will be created" not in err
    assert str(db_path) in err
    assert "--create" in err
    # Refused before anything was written: no database file appeared.
    assert not db_path.exists()


def test_grant_admin_prints_absolute_sqlite_path(tmp_path: Path, monkeypatch, capsys) -> None:
    """A relative KEYSTONE_MCP_USERS_DB_URL must resolve against the real cwd.

    Simulates the exact risk this fixes: the command is run from a directory
    other than the server's own, with the *same* relative URL the server
    uses. The printed path must show where it actually resolves to (inside
    ``other_cwd``), not the server's directory, so the mismatch is obvious
    before anything is written.
    """
    server_cwd = tmp_path / "server"
    other_cwd = tmp_path / "elsewhere"
    server_cwd.mkdir()
    other_cwd.mkdir()
    monkeypatch.chdir(other_cwd)
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", "sqlite:///./keystone-users.db")

    exit_code = main(["users", "grant-admin", "--email", "root@example.com", "--create"])

    assert exit_code == 0
    err = capsys.readouterr().err
    expected_path = (other_cwd / "keystone-users.db").resolve()
    assert f"Users directory: sqlite:///{expected_path}" in err
    assert expected_path.is_file()
    assert not (server_cwd / "keystone-users.db").exists()


def test_grant_admin_restores_blocked_and_demoted_admin(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    db_path = tmp_path / "keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{db_path}")
    _seed_user(db_path, email="admin@example.com", roles=[], is_blocked=True)

    exit_code = main(["users", "grant-admin", "--email", "admin@example.com"])
    assert exit_code == 0
    assert (
        capsys.readouterr().out.strip() == "Granted administrator and unblocked: admin@example.com"
    )

    exit_code = main(["users", "grant-admin", "--email", "admin@example.com"])
    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "Administrator already active: admin@example.com"


def test_grant_admin_refuses_http_backend(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{tmp_path}/keystone-users.db")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_BACKEND", "http")

    exit_code = main(["users", "grant-admin", "--email", "admin@example.com"])

    assert exit_code == 1
    assert "KEYSTONE_MCP_USERS_BACKEND=local" in capsys.readouterr().err


def test_grant_admin_rejects_bad_email(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{tmp_path}/keystone-users.db")

    exit_code = main(["users", "grant-admin", "--email", "not-an-email", "--create"])

    assert exit_code == 1


def test_grant_admin_prints_redacted_target(monkeypatch, capsys) -> None:
    monkeypatch.setenv(
        "KEYSTONE_MCP_USERS_DB_URL",
        "postgresql+psycopg://user:secret@127.0.0.1:1/testdb",
    )

    exit_code = main(["users", "grant-admin", "--email", "admin@example.com"])

    assert exit_code == 3
    err = capsys.readouterr().err
    assert "secret" not in err
    assert "Users directory: postgresql+psycopg://user:***@127.0.0.1:1/testdb" in err


def test_grant_admin_bumps_revision_with_redis(tmp_path: Path, monkeypatch, capsys) -> None:
    redis_url = require_redis_url()

    from redis.asyncio import Redis

    key = users_revision_key("cli-grant")
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{tmp_path}/keystone-users.db")
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", redis_url)
    monkeypatch.setenv("KEYSTONE_MCP_USERS_REDIS_REVISION_KEY", key)

    exit_code = main(["users", "grant-admin", "--email", "admin@example.com", "--create"])
    assert exit_code == 0

    async def _read() -> str | None:
        client = Redis.from_url(redis_url, decode_responses=True)
        try:
            return await client.get(key)
        finally:
            await client.aclose()

    assert asyncio.run(_read()) == "1"


# --- import: fetch_source_users (direct, no CLI) ----------------------------


def test_fetch_sends_bearer_and_both_filters() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"users": [], "total": 0})

    users = fetch_source_users(
        "http://source.example", "t0k", transport=httpx.MockTransport(handler)
    )

    assert users == []
    assert len(seen) == 2
    assert seen[0].url.params["is_blocked"] == "false"
    assert seen[1].url.params["is_blocked"] == "true"
    assert seen[0].headers["authorization"] == "Bearer t0k"
    assert seen[1].headers["authorization"] == "Bearer t0k"


# --- import: via the CLI -----------------------------------------------------


def test_import_creates_users_with_roles_and_block_state(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    db_url = f"sqlite:///{tmp_path}/keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    policy_path = _write_policy(tmp_path)

    unblocked = [
        _user_payload(
            "member@example.com",
            "Member Person",
            ["member"],
            False,
            created_at="2026-07-24T12:00:00Z",
            updated_at="2026-07-24T12:00:00Z",
        ),
        _user_payload("admin@example.com", "Admin Person", ["administrator"], False),
    ]
    blocked = [_user_payload("blocked@example.com", "Blocked Person", ["member"], True)]
    transport = _transport_for(unblocked, blocked)
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
        ]
    )

    assert exit_code == 0
    out = capsys.readouterr().out.strip()
    assert out == (
        "created=3 updated=0 unchanged=0 skipped_roles=0 skipped_invalid=0 admin_or_block_changes=0 revoked_sessions=0"
    )

    users = {u.email: u for u in _list_users(db_url)}
    assert set(users) == {"member@example.com", "admin@example.com", "blocked@example.com"}
    assert users["member@example.com"].roles == ("member",)
    assert users["member@example.com"].created_at == datetime(2026, 7, 24, 12, 0, 0, tzinfo=UTC)
    assert users["admin@example.com"].roles == ("administrator",)
    assert users["blocked@example.com"].is_blocked is True


def test_import_skips_roles_outside_policy_and_logs(
    tmp_path: Path, monkeypatch, capsys, caplog: pytest.LogCaptureFixture
) -> None:
    db_url = f"sqlite:///{tmp_path}/keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    policy_path = _write_policy(tmp_path)

    unblocked = [_user_payload("analyst@example.com", "Analyst", ["analyst"], False)]
    transport = _transport_for(unblocked, [])
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    with caplog.at_level(logging.WARNING, logger="keystone_mcp.users.cli"):
        exit_code = main(
            [
                "users",
                "import",
                "--from-url",
                "http://source.example",
                "--token",
                "t0k",
                "--policy",
                str(policy_path),
            ]
        )

    assert exit_code == 0
    err = capsys.readouterr().err
    assert "skipped role 'analyst' for analyst@example.com: not in policy" in err
    assert any(
        record.message == "role not in policy; skipped"
        and getattr(record, "role", None) == "analyst"
        for record in caplog.records
    )

    users = {u.email: u for u in _list_users(db_url)}
    assert users["analyst@example.com"].roles == ()


def test_import_is_idempotent(tmp_path: Path, monkeypatch, capsys) -> None:
    redis_url = require_redis_url()

    from redis.asyncio import Redis

    key = users_revision_key("cli-import")
    db_url = f"sqlite:///{tmp_path}/keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", redis_url)
    monkeypatch.setenv("KEYSTONE_MCP_USERS_REDIS_REVISION_KEY", key)
    policy_path = _write_policy(tmp_path)

    unblocked = [_user_payload("member@example.com", "Member", ["member"], False)]
    transport = _transport_for(unblocked, [])
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    argv = [
        "users",
        "import",
        "--from-url",
        "http://source.example",
        "--token",
        "t0k",
        "--policy",
        str(policy_path),
    ]

    assert main(argv) == 0
    assert capsys.readouterr().out.strip() == (
        "created=1 updated=0 unchanged=0 skipped_roles=0 skipped_invalid=0 admin_or_block_changes=0 revoked_sessions=0"
    )

    async def _read() -> str | None:
        client = Redis.from_url(redis_url, decode_responses=True)
        try:
            return await client.get(key)
        finally:
            await client.aclose()

    assert asyncio.run(_read()) == "1"

    assert main(argv) == 0
    assert capsys.readouterr().out.strip() == (
        "created=0 updated=0 unchanged=1 skipped_roles=0 skipped_invalid=0 admin_or_block_changes=0 revoked_sessions=0"
    )
    assert asyncio.run(_read()) == "1"


def test_import_source_wins_on_existing_user(tmp_path: Path, monkeypatch, capsys) -> None:
    db_path = tmp_path / "keystone-users.db"
    db_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    policy_path = _write_policy(tmp_path)
    _seed_user(db_path, email="person@example.com", full_name="Local Name", roles=["member"])

    unblocked = [
        _user_payload("person@example.com", "Source Name", ["administrator"], False),
    ]
    transport = _transport_for(unblocked, [])
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
        ]
    )

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == (
        "created=0 updated=1 unchanged=0 skipped_roles=0 skipped_invalid=0 admin_or_block_changes=1 revoked_sessions=0"
    )

    users = {u.email: u for u in _list_users(db_url)}
    assert users["person@example.com"].full_name == "Source Name"
    assert users["person@example.com"].roles == ("administrator",)


def test_import_writes_trimmed_full_name_and_created_by(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """The value written must be the same one validation checked.

    ``validate_imported_user`` checks ``full_name.strip()`` against the
    1-255 rule, but ``upsert_imported_user`` used to write the raw,
    untrimmed ``imported.full_name`` -- so a record with leading/trailing
    whitespace could pass validation (stripped length is fine) yet still
    write a value Postgres's own ``VARCHAR(255)`` would reject if the
    padding pushed it over the limit, and in every case stored whitespace
    validation deliberately disallows. Same for ``created_by``: an
    untrimmed or over-320-character value from the source must be trimmed
    before it is written, both when the user is created and when an
    existing one is updated.
    """
    db_path = tmp_path / "keystone-users.db"
    db_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    policy_path = _write_policy(tmp_path)
    _seed_user(db_path, email="existing@example.com", full_name="Old Name", roles=["member"])

    unblocked = [
        _user_payload(
            "new@example.com",
            "  Padded New Name  ",
            ["member"],
            False,
            created_by="  ldap-sync  ",
        ),
        _user_payload(
            "existing@example.com",
            "  Padded Existing Name  ",
            ["member"],
            False,
        ),
    ]
    transport = _transport_for(unblocked, [])
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
        ]
    )

    assert exit_code == 0
    users = {u.email: u for u in _list_users(db_url)}
    assert users["new@example.com"].full_name == "Padded New Name"
    assert users["new@example.com"].created_by == "ldap-sync"
    assert users["existing@example.com"].full_name == "Padded Existing Name"


def test_import_rejects_overlong_created_by_without_crashing(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Mirrors the existing over-255-character ``full_name`` check: an
    over-320-character ``created_by`` (the column is ``String(320)``) must
    be reported as an invalid record, not reach ``session.flush()`` and
    turn into a generic database failure (a ``DataError`` on PostgreSQL;
    SQLite would silently accept it, since it does not enforce column
    length -- validating here means both backends behave the same way)."""
    db_url = f"sqlite:///{tmp_path}/keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    policy_path = _write_policy(tmp_path)

    unblocked = [
        _user_payload("good@example.com", "Good Person", ["member"], False),
        _user_payload(
            "badcreatedby@example.com",
            "Bad CreatedBy",
            ["member"],
            False,
            created_by="x" * 321,
        ),
    ]
    transport = _transport_for(unblocked, [])
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == (
        "created=1 updated=0 unchanged=0 skipped_roles=0 skipped_invalid=1 admin_or_block_changes=0 revoked_sessions=0"
    )
    assert "badcreatedby@example.com" in captured.err
    assert "created_by" in captured.err

    users = {u.email: u for u in _list_users(db_url)}
    assert set(users) == {"good@example.com"}


def test_import_leaves_local_only_users_untouched(tmp_path: Path, monkeypatch, capsys) -> None:
    db_path = tmp_path / "keystone-users.db"
    db_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    policy_path = _write_policy(tmp_path)
    _seed_user(db_path, email="local-only@example.com", full_name="Local Only", roles=["member"])

    unblocked = [_user_payload("from-source@example.com", "Source Person", ["member"], False)]
    transport = _transport_for(unblocked, [])
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
        ]
    )

    assert exit_code == 0
    users = {u.email: u for u in _list_users(db_url)}
    assert users["local-only@example.com"].full_name == "Local Only"
    assert users["local-only@example.com"].roles == ("member",)
    assert "from-source@example.com" in users


def test_import_dry_run_writes_nothing(tmp_path: Path, monkeypatch, capsys) -> None:
    db_url = f"sqlite:///{tmp_path}/keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    policy_path = _write_policy(tmp_path)

    unblocked = [_user_payload("member@example.com", "Member", ["member"], False)]
    transport = _transport_for(unblocked, [])
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
            "--dry-run",
        ]
    )

    assert exit_code == 0
    out = capsys.readouterr().out.strip()
    assert out == (
        "created=1 updated=0 unchanged=0 skipped_roles=0 "
        "skipped_invalid=0 admin_or_block_changes=0 revoked_sessions=0 (dry run, nothing written)"
    )
    assert _list_users(db_url) == []


def test_import_source_401_exits_2_without_token_in_output(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{tmp_path}/keystone-users.db")
    policy_path = _write_policy(tmp_path)
    transport = _error_transport(401, code="unauthorized")
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "s3cr3t-t0k3n",
            "--policy",
            str(policy_path),
        ]
    )

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "s3cr3t-t0k3n" not in captured.out
    assert "s3cr3t-t0k3n" not in captured.err


def test_import_malformed_payload_exits_2(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{tmp_path}/keystone-users.db")
    policy_path = _write_policy(tmp_path)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"users": [{"email": "missing-fields@example.com"}]})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
        ]
    )

    assert exit_code == 2


def test_import_requires_policy(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{tmp_path}/keystone-users.db")
    monkeypatch.delenv("KEYSTONE_MCP_RBAC_POLICY_PATH", raising=False)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
        ]
    )

    assert exit_code == 1
    assert "--policy" in capsys.readouterr().err


def test_import_warns_when_no_active_administrator(tmp_path: Path, monkeypatch, capsys) -> None:
    db_url = f"sqlite:///{tmp_path}/keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    policy_path = _write_policy(tmp_path)

    unblocked = [_user_payload("member@example.com", "Member", ["member"], False)]
    transport = _transport_for(unblocked, [])
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
        ]
    )

    assert exit_code == 0
    err = capsys.readouterr().err
    assert "no active administrator after import" in err
    assert "users grant-admin" in err


def test_import_skips_invalid_records_and_still_writes_the_rest(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """One bad source record must not abort the whole batch.

    Before this fix, a malformed record (bad email, an over-255-character
    full_name, or a malformed role) raised mid-transaction and turned the
    entire import into a generic "database is unavailable" failure with exit
    code 3 — on SQLite as much as on PostgreSQL, since the length check now
    happens in Python before any row is written. Here, three bad records
    (one per kind of problem) are mixed in with one good one; the good one
    must land, and each bad one must be named and explained without aborting
    anything.
    """
    db_url = f"sqlite:///{tmp_path}/keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    # A custom policy: the over-length role below must be *in* the policy, or
    # it is dropped as "not in policy" before its format is ever checked (a
    # role the policy does not recognize is simply not written — see
    # upsert_imported_user), which would test skipped_roles, not skipped_invalid.
    bad_role_name = "z" * 65  # one over MAX_ROLE_LENGTH (64)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "version: '1.0.0'\n"
        "default_deny: true\n"
        "roles:\n"
        "  administrator:\n"
        "    allow: ['*']\n"
        "  member:\n"
        "    allow: [some_tool]\n"
        f"  {bad_role_name}:\n"
        "    allow: [some_tool]\n",
        encoding="utf-8",
    )

    unblocked = [
        _user_payload("good@example.com", "Good Person", ["member"], False),
        _user_payload("not-an-email", "Bad Email", ["member"], False),
        _user_payload("longname@example.com", "x" * 256, ["member"], False),
        _user_payload("badrole@example.com", "Bad Role", [bad_role_name], False),
    ]
    transport = _transport_for(unblocked, [])
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    out = captured.out.strip()
    err = captured.err
    assert out == (
        "created=1 updated=0 unchanged=0 skipped_roles=0 skipped_invalid=3 admin_or_block_changes=0 revoked_sessions=0"
    )
    assert "not-an-email" in err
    assert "longname@example.com" in err
    assert "badrole@example.com" in err
    # The over-length full_name itself is never echoed back (only the field
    # name and the 1-255 rule); a role name is not a secret, so it may appear.
    assert "x" * 256 not in err

    users = {u.email: u for u in _list_users(db_url)}
    assert set(users) == {"good@example.com"}


def test_import_dry_run_reports_admin_or_block_changes(tmp_path: Path, monkeypatch, capsys) -> None:
    """``--dry-run`` must surface a re-run's one real risk before it happens:

    the source overwriting a block or an `administrator` grant/revoke made
    locally since the last import (see upsert_imported_user's docstring).
    """
    db_path = tmp_path / "keystone-users.db"
    db_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    policy_path = _write_policy(tmp_path)
    # Locally: blocked, and not an administrator.
    _seed_user(db_path, email="person@example.com", roles=[], is_blocked=True)

    # Source: unblocked, and an administrator — re-importing would lift the
    # local block and (re)grant administrator.
    unblocked = [_user_payload("person@example.com", "Person", ["administrator"], False)]
    transport = _transport_for(unblocked, [])
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
            "--dry-run",
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    out = captured.out.strip()
    err = captured.err
    assert "admin_or_block_changes=1 revoked_sessions=0" in out
    assert "administrator" in err
    assert "block" in err

    # Dry run: the local state is untouched.
    users = {u.email: u for u in _list_users(db_url)}
    assert users["person@example.com"].is_blocked is True
    assert users["person@example.com"].roles == ()


def test_import_reblocking_a_locally_unblocked_user_counts_as_change(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """``admin_or_block_changes`` previously only caught a block being
    *lifted* by a re-import. The opposite direction is just as surprising: a
    person was imported blocked, an administrator unblocked them locally via
    ``users_unblock``, and the source still reports them as blocked -- a
    re-import re-applies that block and this must show up in the count."""
    db_path = tmp_path / "keystone-users.db"
    db_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    policy_path = _write_policy(tmp_path)
    # Locally: unblocked (an administrator lifted the block after the first import).
    _seed_user(db_path, email="person@example.com", roles=["member"], is_blocked=False)

    # Source: still reports this person as blocked.
    blocked = [_user_payload("person@example.com", "Person", ["member"], True)]
    transport = _transport_for([], blocked)
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == (
        "created=0 updated=1 unchanged=0 skipped_roles=0 skipped_invalid=0 admin_or_block_changes=1 revoked_sessions=0"
    )
    assert "block" in captured.err

    users = {u.email: u for u in _list_users(db_url)}
    assert users["person@example.com"].is_blocked is True


def test_import_revoking_a_locally_granted_role_counts_as_change(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """A role granted locally (through ``users_grant_role``) that the source

    does not report is silently dropped on every re-import (source wins);
    that must count toward ``admin_or_block_changes`` even when it is not
    ``administrator`` and no block state changes."""
    db_path = tmp_path / "keystone-users.db"
    db_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        "version: '1.0.0'\n"
        "default_deny: true\n"
        "roles:\n"
        "  administrator:\n"
        "    allow: ['*']\n"
        "  member:\n"
        "    allow: [some_tool]\n"
        "  billing:\n"
        "    allow: [some_tool]\n",
        encoding="utf-8",
    )
    # Locally: "billing" was granted by hand, in addition to "member" from
    # the first import.
    _seed_user(db_path, email="person@example.com", roles=["member", "billing"])

    # Source only ever reported "member".
    unblocked = [_user_payload("person@example.com", "Person", ["member"], False)]
    transport = _transport_for(unblocked, [])
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
        ]
    )

    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == (
        "created=0 updated=1 unchanged=0 skipped_roles=0 skipped_invalid=0 admin_or_block_changes=1 revoked_sessions=0"
    )
    assert "role" in captured.err

    users = {u.email: u for u in _list_users(db_url)}
    assert users["person@example.com"].roles == ("member",)


def test_import_on_fresh_database_warns_but_does_not_require_create(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Unlike grant-admin, import's normal first use is a brand-new database.

    It must still warn (so an operator pointed at the wrong
    KEYSTONE_MCP_USERS_DB_URL notices), but never require --create: that flag
    does not even exist on this subcommand.
    """
    db_path = tmp_path / "keystone-users.db"
    db_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    policy_path = _write_policy(tmp_path)
    assert not db_path.exists()

    unblocked = [_user_payload("member@example.com", "Member", ["member"], False)]
    transport = _transport_for(unblocked, [])
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
        ]
    )

    assert exit_code == 0
    err = capsys.readouterr().err
    assert "will be created" in err
    assert db_path.is_file()


# --- block / unblock / logout ----------------------------------------------


def _seed_oauth_pair(redis_url: str, *, email: str) -> tuple[str, str]:
    """Write one access+refresh pair for *email* into Redis; return (at, rt)."""
    import time

    from mcp.server.auth.provider import AccessToken, RefreshToken

    from keystone_mcp.auth.oauth_store import RedisOAuthStore

    store = RedisOAuthStore(
        redis_url,
        key_prefix=redis_key_prefix("oauth"),
        client_ttl_seconds=5000,
        refresh_ttl_seconds=3000,
        access_ttl_seconds=3600,
    )

    async def _run() -> tuple[str, str]:
        now = int(time.time())
        at = f"km_at_{uuid.uuid4().hex}"
        rt = f"km_rt_{uuid.uuid4().hex}"
        try:
            await store.put_access_token(
                AccessToken(
                    token=at,
                    client_id="cli-test-client",
                    scopes=[],
                    expires_at=now + 3600,
                    subject=email,
                    claims={"iat": now},
                )
            )
            await store.put_refresh_token(
                RefreshToken(
                    token=rt,
                    client_id="cli-test-client",
                    scopes=[],
                    expires_at=now + 3000,
                    subject=email,
                )
            )
            return at, rt
        finally:
            await store.aclose()

    return asyncio.run(_run())


def test_cli_block_revokes_sessions(tmp_path: Path, monkeypatch, capsys) -> None:
    redis_url = require_redis_url()

    db_url = f"sqlite:///{tmp_path}/keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", redis_url)
    _seed_user(db_path=tmp_path / "keystone-users.db", email="victim@example.com", roles=["member"])
    _seed_oauth_pair(redis_url, email="victim@example.com")

    exit_code = main(["users", "block", "--email", "victim@example.com"])

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "Blocked victim@example.com; revoked 2 token(s)"
    users = {u.email: u for u in _list_users(db_url)}
    assert users["victim@example.com"].is_blocked is True


def test_cli_block_without_redis_still_blocks(tmp_path: Path, monkeypatch, capsys) -> None:
    db_url = f"sqlite:///{tmp_path}/keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    _seed_user(db_path=tmp_path / "keystone-users.db", email="victim@example.com", roles=["member"])

    exit_code = main(["users", "block", "--email", "victim@example.com"])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "Blocked victim@example.com; revoked 0 token(s)"
    assert "sessions not revoked: KEYSTONE_MCP_REDIS_URL is not set" in captured.err
    users = {u.email: u for u in _list_users(db_url)}
    assert users["victim@example.com"].is_blocked is True


def test_cli_logout_without_redis_fails(tmp_path: Path, monkeypatch, capsys) -> None:
    db_url = f"sqlite:///{tmp_path}/keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)

    exit_code = main(["users", "logout", "--email", "anyone@example.com"])

    assert exit_code == 1
    assert "KEYSTONE_MCP_REDIS_URL is not set" in capsys.readouterr().err


def test_cli_unblock(tmp_path: Path, monkeypatch, capsys) -> None:
    db_path = tmp_path / "keystone-users.db"
    db_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    _seed_user(
        db_path,
        email="victim@example.com",
        roles=["member"],
        is_blocked=True,
    )

    exit_code = main(["users", "unblock", "--email", "victim@example.com"])

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "Unblocked victim@example.com"
    users = {u.email: u for u in _list_users(db_url)}
    assert users["victim@example.com"].is_blocked is False


def test_cli_block_last_admin_refused(tmp_path: Path, monkeypatch, capsys) -> None:
    db_path = tmp_path / "keystone-users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{db_path}")
    _seed_user(db_path, email="sole@example.com", roles=["administrator"])

    exit_code = main(["users", "block", "--email", "sole@example.com"])

    assert exit_code == 1
    assert "last active administrator" in capsys.readouterr().err.lower()


def test_import_block_revokes_sessions(tmp_path: Path, monkeypatch, capsys) -> None:
    redis_url = require_redis_url()

    db_path = tmp_path / "keystone-users.db"
    db_url = f"sqlite:///{db_path}"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", db_url)
    monkeypatch.setenv("KEYSTONE_MCP_REDIS_URL", redis_url)
    policy_path = _write_policy(tmp_path)
    _seed_user(db_path, email="person@example.com", roles=["member"], is_blocked=False)
    _seed_oauth_pair(redis_url, email="person@example.com")

    blocked = [_user_payload("person@example.com", "Person", ["member"], True)]
    transport = _transport_for([], blocked)
    monkeypatch.setattr(users_cli, "_source_transport", lambda: transport)

    exit_code = main(
        [
            "users",
            "import",
            "--from-url",
            "http://source.example",
            "--token",
            "t0k",
            "--policy",
            str(policy_path),
        ]
    )

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == (
        "created=0 updated=1 unchanged=0 skipped_roles=0 skipped_invalid=0 "
        "admin_or_block_changes=1 revoked_sessions=2"
    )


# --- grant-admin reads KEYSTONE_MCP_ENV_FILE (deferred by A06) --------------


def test_grant_admin_reads_users_db_url_from_env_file(tmp_path: Path, monkeypatch, capsys) -> None:
    """``users grant-admin`` must load ``.env`` first, same as every subcommand.

    Without this, a deployment relying on ``KEYSTONE_MCP_ENV_FILE`` to supply
    ``KEYSTONE_MCP_USERS_DB_URL`` would have ``grant-admin`` silently write to
    the SQLite default instead of the real database.
    """
    db_path = tmp_path / "from-env-file.db"
    env_file = tmp_path / "custom.env"
    env_file.write_text(f"KEYSTONE_MCP_USERS_DB_URL=sqlite:///{db_path}\n", encoding="utf-8")

    # The suite's autouse fixture points KEYSTONE_MCP_USERS_DB_URL at its own
    # tmp_path by default; remove it so the value in the env file can win.
    monkeypatch.delenv("KEYSTONE_MCP_USERS_DB_URL", raising=False)
    monkeypatch.setenv("KEYSTONE_MCP_ENV_FILE", str(env_file))

    exit_code = main(["users", "grant-admin", "--email", "admin@example.com", "--create"])

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "Created administrator: admin@example.com"
    assert db_path.is_file()

    users = _list_users(f"sqlite:///{db_path}")
    assert [u.email for u in users] == ["admin@example.com"]


def test_grant_admin_uses_full_admin_role_from_policy(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    db_path = tmp_path / "users.db"
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """\
version: "1"
default_deny: true
roles:
  owner: {allow: ["*"]}
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))

    exit_code = main(["users", "grant-admin", "--email", "x@example.com", "--create"])
    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "Created administrator: x@example.com (role 'owner')"
    users = _list_users(f"sqlite:///{db_path}")
    assert users[0].roles == ("owner",)


def test_grant_admin_keeps_administrator_when_present(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    db_path = tmp_path / "users.db"
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """\
version: "1"
default_deny: true
roles:
  administrator: {allow: ["users_list"]}
  owner: {allow: ["*"]}
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))

    exit_code = main(["users", "grant-admin", "--email", "x@example.com", "--create"])
    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "Created administrator: x@example.com"
    assert _list_users(f"sqlite:///{db_path}")[0].roles == ("administrator",)


def test_grant_admin_role_flag_must_be_full_admin(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    db_path = tmp_path / "users.db"
    policy = _write_policy(tmp_path)
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))

    exit_code = main(["users", "grant-admin", "--email", "x@example.com", "--role", "member"])
    assert exit_code == 1
    err = capsys.readouterr().err.strip()
    assert err.count("\n") == 0
    assert "member" in err


def test_grant_admin_ambiguous_policy_warns_and_keeps_old_result(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    db_path = tmp_path / "users.db"
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """\
version: "1"
default_deny: true
roles:
  owner: {allow: ["*"]}
  super: {allow: ["*"]}
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))

    exit_code = main(["users", "grant-admin", "--email", "x@example.com", "--create"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "administrator" in captured.err
    assert "owner" in captured.err and "super" in captured.err
    assert _list_users(f"sqlite:///{db_path}")[0].roles == ("administrator",)


def test_grant_admin_unreadable_policy_falls_back_to_administrator(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    db_path = tmp_path / "users.db"
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(tmp_path / "missing.yaml"))

    exit_code = main(["users", "grant-admin", "--email", "x@example.com", "--create"])
    assert exit_code == 0
    assert "cannot read the RBAC policy" in capsys.readouterr().err
    assert _list_users(f"sqlite:///{db_path}")[0].roles == ("administrator",)


def test_users_admins_lists_full_admins_roles_and_holders(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    db_path = tmp_path / "users.db"
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """\
version: "1"
default_deny: true
roles:
  administrator: {allow: ["*"]}
  owner: {allow: ["*"]}
  hr: {allow: ["users_*"]}
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    _seed_user(db_path, email="admin@example.com", roles=["administrator"])
    _seed_user(db_path, email="hr@example.com", roles=["hr"])

    exit_code = main(["users", "admins"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "admin@example.com" in out
    assert "hr" in out

    exit_code = main(["users", "admins", "--json"])
    assert exit_code == 0
    import json

    payload = json.loads(capsys.readouterr().out)
    assert "admin@example.com" in payload["full_administrators"]


def test_users_admins_exit_1_without_active_full_admin(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    db_path = tmp_path / "users.db"
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """\
version: "1"
default_deny: true
roles:
  owner: {allow: ["*"]}
  member: {allow: ["docs_read"]}
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("KEYSTONE_MCP_USERS_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("KEYSTONE_MCP_RBAC_POLICY_PATH", str(policy))
    _seed_user(db_path, email="admin@example.com", roles=["owner"], is_blocked=True)

    exit_code = main(["users", "admins"])
    assert exit_code == 1
    assert "no active full administrator" in capsys.readouterr().err
