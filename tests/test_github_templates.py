"""GitHub issue templates stay parseable and include required bug-report fields."""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = REPO_ROOT / ".github" / "ISSUE_TEMPLATE"
BUG_REPORT = TEMPLATE_DIR / "bug_report.yml"
FEATURE_REQUEST = TEMPLATE_DIR / "feature_request.yml"
UPGRADE_REPORT = TEMPLATE_DIR / "upgrade_report.yml"


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

    upgraded = _field(body, "upgraded_recently")
    assert upgraded["type"] == "input"
    assert upgraded["validations"]["required"] is False


def test_upgrade_report_parses_and_requires_version_fields():
    data = yaml.safe_load(UPGRADE_REPORT.read_text(encoding="utf-8"))
    assert data["labels"] == ["upgrade"]
    body = data["body"]

    upgraded_from = _field(body, "upgraded_from")
    assert upgraded_from["attributes"]["label"] == "Upgraded from"
    assert upgraded_from["validations"]["required"] is True

    upgraded_to = _field(body, "upgraded_to")
    assert upgraded_to["attributes"]["label"] == "Upgraded to"
    assert upgraded_to["validations"]["required"] is True


def test_feature_request_includes_compatibility_question():
    data = yaml.safe_load(FEATURE_REQUEST.read_text(encoding="utf-8"))
    body = data["body"]

    impact = _field(body, "compatibility_impact")
    assert impact["type"] == "dropdown"
    assert impact["validations"]["required"] is True
    label = impact["attributes"]["label"]
    assert "compatibility.md" in label
    options = impact["attributes"]["options"]
    assert "No, it only adds" in options
    assert "Yes, it changes or removes" in options
    description = impact["attributes"]["description"]
    assert "compatibility.md" in description
