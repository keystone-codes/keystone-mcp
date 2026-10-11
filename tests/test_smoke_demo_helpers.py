"""Unit tests for scripts/smoke_demo.py's pure argument-building helper.

The script is not a package module (it is a standalone CLI meant to run
against a live server with ``uv run python scripts/smoke_demo.py``), so it is
loaded here via ``importlib`` instead of a normal import.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "smoke_demo.py"


def _load_smoke_demo():
    spec = importlib.util.spec_from_file_location("smoke_demo", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


smoke_demo = _load_smoke_demo()
build_minimal_args = smoke_demo.build_minimal_args


def test_build_minimal_args_fills_only_required_properties() -> None:
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"},
            "filter": {"type": "object"},
        },
        "required": ["query", "filter"],
    }
    assert build_minimal_args(schema) == {"query": "smoke", "filter": {}}


def test_build_minimal_args_schema_without_required_is_empty() -> None:
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
        },
    }
    assert build_minimal_args(schema) == {}


def test_build_minimal_args_none_schema_is_empty() -> None:
    assert build_minimal_args(None) == {}
    assert build_minimal_args({}) == {}


def test_build_minimal_args_boolean_number_and_array_types() -> None:
    schema = {
        "type": "object",
        "properties": {
            "active": {"type": "boolean"},
            "amount": {"type": "number"},
            "tags": {"type": "array"},
        },
        "required": ["active", "amount", "tags"],
    }
    assert build_minimal_args(schema) == {"active": True, "amount": 1.0, "tags": []}


def test_build_minimal_args_required_enum_uses_first_value() -> None:
    # Matches examples/hello-upstream's "search" tool: a required "filter"
    # property with an enum, which the plain string placeholder would fail
    # schema validation against.
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "filter": {"type": "string", "enum": ["all", "mine"]},
        },
        "required": ["query", "filter"],
    }
    assert build_minimal_args(schema) == {"query": "smoke", "filter": "all"}


def test_build_minimal_args_mixed_types_all_required() -> None:
    schema = {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "count": {"type": "integer"},
            "ratio": {"type": "number"},
            "enabled": {"type": "boolean"},
            "items": {"type": "array"},
            "meta": {"type": "object"},
        },
        "required": ["name", "count", "ratio", "enabled", "items", "meta"],
    }
    assert build_minimal_args(schema) == {
        "name": "smoke",
        "count": 1,
        "ratio": 1.0,
        "enabled": True,
        "items": [],
        "meta": {},
    }
