"""Meta-tests: checklist coverage and consistency."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import yaml

CHECKLIST = Path(__file__).with_name("checklist.yaml")
REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_items() -> list[dict]:
    return yaml.safe_load(CHECKLIST.read_text(encoding="utf-8"))


def _test_names_in_file(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
            "test_"
        ):
            names.add(node.name)
    return names


def _test_id_exists(test_id: str) -> bool:
    rel, _, func = test_id.partition("::")
    path = REPO_ROOT / rel
    if not path.is_file():
        return False
    if "[" in func:
        base = func.split("[", 1)[0]
        return base in _test_names_in_file(path)
    return func in _test_names_in_file(path)


def _security_xfail_reasons() -> dict[str, str]:
    reasons: dict[str, str] = {}
    for path in (REPO_ROOT / "tests" / "security").glob("test_*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                func = dec.func
                if isinstance(func, ast.Attribute) and func.attr == "xfail":
                    reason = ""
                    for kw in dec.keywords:
                        if kw.arg == "reason" and isinstance(kw.value, ast.Constant):
                            reason = str(kw.value.value)
                    test_id = f"tests/security/{path.name}::{node.name}"
                    reasons[test_id] = reason
    return reasons


@pytest.mark.security
def test_every_checklist_item_has_security_test() -> None:
    for item in _load_items():
        sec = [t for t in item["tests"] if t.startswith("tests/security/")]
        assert sec, f"{item['id']} has no tests/security/ entry"


@pytest.mark.security
def test_checklist_test_ids_exist() -> None:
    missing = []
    for item in _load_items():
        for test_id in item["tests"]:
            if not _test_id_exists(test_id):
                missing.append(f"{item['id']}: {test_id}")
    assert not missing, "Missing tests:\n" + "\n".join(missing)


@pytest.mark.security
def test_open_items_have_strict_xfail() -> None:
    xfails = _security_xfail_reasons()
    for item in _load_items():
        if item["status"] != "open":
            continue
        assert item.get("finding"), f"{item['id']} open without finding"
        sec_tests = [t for t in item["tests"] if t.startswith("tests/security/")]
        assert any(t in xfails for t in sec_tests), f"{item['id']} open without xfail security test"


@pytest.mark.security
def test_accepted_risk_has_note() -> None:
    for item in _load_items():
        if item["status"] == "accepted_risk":
            assert item.get("note"), f"{item['id']} accepted_risk without note"
