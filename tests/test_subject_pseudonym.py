"""Salted subject pseudonyms in ordinary logs."""

from __future__ import annotations

import ast
import logging
from pathlib import Path

import pytest

from keystone_mcp.auth.login_pending_store import InMemoryLoginPendingStore
from keystone_mcp.auth.oauth_store import InMemoryOAuthStore
from keystone_mcp.auth.sessions import SessionRevoker
from keystone_mcp.observability.subject import (
    configure_subject_salt,
    hash_subject,
    subject_pseudonym,
)
from keystone_mcp.user_directory.types import service_subject


def test_no_unsalted_hash_subject_calls() -> None:
    root = Path(__file__).resolve().parents[1] / "src"
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name != "hash_subject":
                continue
            if not any(kw.arg == "salt" for kw in node.keywords):
                offenders.append(f"{path.relative_to(root)}:{node.lineno}")
    assert offenders == []


def test_hash_subject_requires_salt_keyword() -> None:
    with pytest.raises(TypeError):
        hash_subject("a@b.c")  # type: ignore[call-arg]


def test_service_subject_pseudonym() -> None:
    configure_subject_salt("pepper")
    svc = service_subject("ci")
    pseudonym = subject_pseudonym(svc)
    assert pseudonym == hash_subject(svc, salt="pepper")
    assert svc not in (pseudonym or "")


@pytest.mark.asyncio
async def test_session_revocation_log_uses_salted_pseudonym(
    caplog: pytest.LogCaptureFixture,
) -> None:
    salt = "s" * 32
    configure_subject_salt(salt)
    email = "victim@example.com"
    revoker = SessionRevoker(InMemoryOAuthStore(), InMemoryLoginPendingStore())
    caplog.set_level(logging.INFO, logger="keystone_mcp.auth.sessions")
    await revoker.revoke_subject(email)
    unsalted = hash_subject(email, salt="")
    salted = hash_subject(email, salt=salt)
    joined = caplog.text
    assert salted in joined
    assert unsalted not in joined
