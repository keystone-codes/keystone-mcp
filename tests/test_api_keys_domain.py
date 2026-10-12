"""Domain rules for API keys in the built-in users directory."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from keystone_mcp.user_directory.types import parse_api_key
from keystone_mcp.users import service
from keystone_mcp.users.db import create_users_engine, make_session_factory, session_scope
from keystone_mcp.users.errors import InvalidUserFieldError, UserNotFoundError
from keystone_mcp.users.migrate import upgrade_to_head
from keystone_mcp.users.models import ApiKeyRow
from support.users_db import sqlite_url


@pytest.fixture
def session_factory(tmp_path):
    engine = create_users_engine(sqlite_url(tmp_path))
    upgrade_to_head(engine)
    factory = make_session_factory(engine)
    with session_scope(factory) as session:
        service.create_user(
            session,
            email="human@example.com",
            full_name="Human",
            roles=["member"],
            note=None,
            created_by="test",
            allowed_roles=None,
        )
        service.create_service_account(
            session,
            name="ci",
            description=None,
            roles=["member"],
            created_by="test",
        )
    yield factory
    engine.dispose()


def test_issue_and_verify_stores_only_hash(session_factory) -> None:
    with session_scope(session_factory) as session:
        row, key = service.issue_api_key(
            session,
            subject="human@example.com",
            label="laptop",
            expires_in_days=90,
            created_by="admin@example.com",
        )
    assert parse_api_key(key) is not None
    assert key not in row.secret_hash
    with session_scope(session_factory) as session:
        stored = session.get(ApiKeyRow, row.key_id)
        assert stored is not None
        assert stored.secret_hash != key
        assert key.split("_", 2)[-1] not in stored.secret_hash
        verified = service.verify_api_key(session, key)
        assert verified is not None
        assert verified.subject == "human@example.com"


def test_verify_rejects_bad_secret_and_revoked(session_factory) -> None:
    with session_scope(session_factory) as session:
        row, key = service.issue_api_key(
            session,
            subject="svc:ci",
            label=None,
            expires_in_days=None,
            created_by="system:cli",
        )
        key_id, secret = parse_api_key(key)  # type: ignore[misc]
        bad = f"ksk_{key_id}_{secret}x"
        assert service.verify_api_key(session, bad) is None
        service.revoke_api_key(session, key_id=row.key_id, actor="admin")
        assert service.verify_api_key(session, key) is None


def test_expired_key_is_rejected(session_factory) -> None:
    with session_scope(session_factory) as session:
        row, key = service.issue_api_key(
            session,
            subject="human@example.com",
            label=None,
            expires_in_days=1,
            created_by="admin",
        )
        stored = session.get(ApiKeyRow, row.key_id)
        assert stored is not None
        stored.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        session.flush()
        assert service.verify_api_key(session, key) is None


def test_issue_validation_errors(session_factory) -> None:
    with session_scope(session_factory) as session:
        with pytest.raises(UserNotFoundError):
            service.issue_api_key(
                session,
                subject="missing@example.com",
                label=None,
                expires_in_days=90,
                created_by="admin",
            )
        with pytest.raises(InvalidUserFieldError):
            service.issue_api_key(
                session,
                subject="human@example.com",
                label=None,
                expires_in_days=0,
                created_by="admin",
            )
