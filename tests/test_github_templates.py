"""GitHub issue templates stay parseable and include required bug-report fields."""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
BUG_REPORT = REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml"


def _field(body: list[dict], field_id: str) -> dict:
    for block in body:
        if block.get("id") == field_id:
            return block
    raise AssertionError(f"field {field_id!r} not found")


def test_bug_report_parses_and_requires_client_fields():
    data = yaml.safe_load(BUG_REPORT.read_text(encoding="utf-8"))
    body = data["body"]

    client = _field(body, "client")
    assert client["type"] == "dropdown"
    assert client["validations"]["required"] is True

    client_version = _field(body, "client_version")
    assert client_version["type"] == "input"
    assert client_version["validations"]["required"] is True
