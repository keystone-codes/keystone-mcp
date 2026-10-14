"""Deterministic task_id and canonical argument serialization."""

from __future__ import annotations

import pytest

from keystone_mcp.identity import VerifiedIdentity, canonical, make_task_id
from keystone_mcp.observability.subject import hash_subject

ID = VerifiedIdentity(email="u@example.com")


def test_canonical_is_order_independent():
    a = canonical({"b": 1, "a": 2, "nested": {"y": 1, "x": 2}})
    b = canonical({"a": 2, "nested": {"x": 2, "y": 1}, "b": 1})
    assert a == b


def test_canonical_empty():
    assert canonical(None) == "{}"
    assert canonical({}) == "{}"


def test_task_id_is_deterministic():
    t1 = make_task_id(ID, "register_project", {"code": "X", "name": "Y"})
    t2 = make_task_id(ID, "register_project", {"name": "Y", "code": "X"})
    assert t1 == t2
    assert t1.startswith("t_")


def test_task_id_varies_by_identity_tool_and_args():
    base = make_task_id(ID, "register_project", {"code": "X"})
    other_user = make_task_id(
        VerifiedIdentity(email="v@example.com"), "register_project", {"code": "X"}
    )
    other_tool = make_task_id(ID, "update_project", {"code": "X"})
    other_args = make_task_id(ID, "register_project", {"code": "Z"})
    assert len({base, other_user, other_tool, other_args}) == 4


def test_task_id_varies_by_namespace():
    base = make_task_id(ID, "get_item_history", {"item_id": "402"})
    namespaced = make_task_id(
        ID,
        "get_item_history",
        {"item_id": "402"},
        namespace="analytics",
    )
    assert base != namespaced


def test_idempotency_token_forks_task_id():
    a = make_task_id(ID, "register_project", {"code": "X"})
    b = make_task_id(ID, "register_project", {"code": "X"}, idempotency_token="retry-2")
    assert a != b


def test_human_subject_keeps_task_id_and_hash():
    email = "a@b.c"
    expected_task = make_task_id(VerifiedIdentity(email=email), "register_project", {"code": "X"})
    expected_hash = hash_subject(email, salt="")
    legacy = VerifiedIdentity(email=email)
    explicit = VerifiedIdentity(email)
    assert make_task_id(legacy, "register_project", {"code": "X"}) == expected_task
    assert make_task_id(explicit, "register_project", {"code": "X"}) == expected_task
    assert hash_subject(legacy.subject, salt="") == expected_hash
    assert hash_subject(explicit.subject, salt="") == expected_hash


def test_service_identity_has_no_email():
    svc = VerifiedIdentity("svc:ci")
    assert svc.email is None
    assert svc.subject_type == "service"


def test_subject_and_email_together_is_type_error():
    with pytest.raises(TypeError):
        VerifiedIdentity(subject="a@b.c", email="a@b.c")
