"""RBAC catalog registry CLI (offline fixtures, no network)."""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

import pytest

from keystone_mcp.cli import main
from keystone_mcp.rbac.catalog import format_live_published_names

TEST_POLICY = """\
version: "3.0.0"
default_deny: true
roles:
  administrator:
    description: admin
    allow: ["*"]
  editor:
    description: editor
    allow:
      - documents_*
      - reports_*
      - ledger_read
      - demo_upload
      - demo_download
  viewer:
    description: viewer
    allow:
      - documents_read
      - reports_read
      - demo_download
"""

SNAPSHOT_YAML = """\
active: ["documents_read", "documents_write"]
reserved: []
wip: []
"""


@pytest.fixture
def policy_path(tmp_path: Path) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(TEST_POLICY, encoding="utf-8")
    return path


@pytest.fixture
def snapshot_path(tmp_path: Path) -> Path:
    path = tmp_path / "snapshot.yaml"
    path.write_text(SNAPSHOT_YAML, encoding="utf-8")
    return path


def _live_file(tmp_path: Path, names: tuple[str, ...]) -> Path:
    path = tmp_path / "live.txt"
    path.write_text(format_live_published_names(names), encoding="utf-8")
    return path


LIVE_OK = (
    "demo_upload",
    "demo_download",
    "documents_read",
    "documents_write",
    "reports_read",
    "reports_write",
    "ledger_read",
)


def test_catalog_validate_success(policy_path: Path, tmp_path: Path):
    live = _live_file(tmp_path, LIVE_OK)
    assert (
        main(
            [
                "catalog",
                "validate",
                "--policy",
                str(policy_path),
                "--live-file",
                str(live),
            ]
        )
        == 0
    )


def test_catalog_validate_with_snapshot(policy_path: Path, snapshot_path: Path, tmp_path: Path):
    live = _live_file(
        tmp_path,
        (
            "demo_upload",
            "demo_download",
            "reports_read",
            "reports_write",
            "ledger_read",
        ),
    )
    assert (
        main(
            [
                "catalog",
                "validate",
                "--policy",
                str(policy_path),
                "--snapshot",
                str(snapshot_path),
                "--live-file",
                str(live),
            ]
        )
        == 0
    )


def test_catalog_validate_unmatched_allow_exits_1(policy_path: Path, tmp_path: Path):
    broken = tmp_path / "broken-policy.yaml"
    broken.write_text(TEST_POLICY.replace("documents_*", "docments_*", 1), encoding="utf-8")
    live = _live_file(tmp_path, LIVE_OK)
    assert (
        main(
            [
                "catalog",
                "validate",
                "--policy",
                str(broken),
                "--live-file",
                str(live),
            ]
        )
        == 1
    )


def test_catalog_validate_duplicate_live_names_exits_1(policy_path: Path, tmp_path: Path):
    live = _live_file(tmp_path, ("reports_read", "reports_read"))
    assert (
        main(
            [
                "catalog",
                "validate",
                "--policy",
                str(policy_path),
                "--live-file",
                str(live),
            ]
        )
        == 1
    )


def test_catalog_validate_strict_unreachable_exits_1(tmp_path: Path):
    narrow_policy = tmp_path / "narrow.yaml"
    narrow_policy.write_text(
        """\
version: "0.1"
default_deny: true
roles:
  viewer:
    allow: ["reports_read"]
""",
        encoding="utf-8",
    )
    live = _live_file(tmp_path, ("reports_read", "ledger_commit"))
    assert (
        main(
            [
                "catalog",
                "validate",
                "--policy",
                str(narrow_policy),
                "--live-file",
                str(live),
                "--strict-unreachable",
            ]
        )
        == 1
    )


def test_catalog_validate_live_url_rejects_file_scheme(policy_path: Path):
    assert (
        main(
            [
                "catalog",
                "validate",
                "--policy",
                str(policy_path),
                "--live-url",
                "file:///etc/passwd",
            ]
        )
        == 1
    )


def test_catalog_validate_live_url_rejects_non_loopback(policy_path: Path):
    assert (
        main(
            [
                "catalog",
                "validate",
                "--policy",
                str(policy_path),
                "--live-url",
                "http://169.254.169.254/internal/live-published-names",
            ]
        )
        == 1
    )


def test_catalog_validate_live_url_failure_exits_3(
    policy_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def _fail(_url: str, timeout: float = 10.0):
        raise OSError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", _fail)
    assert (
        main(
            [
                "catalog",
                "validate",
                "--policy",
                str(policy_path),
                "--live-url",
                "http://127.0.0.1:9/internal/live-published-names",
            ]
        )
        == 3
    )


def test_catalog_diff_prints_summary(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    broken = tmp_path / "broken-policy.yaml"
    broken.write_text(
        """\
version: "0.1"
default_deny: true
roles:
  editor:
    allow: ["docments_*", "reports_read"]
  viewer:
    allow: ["reports_read"]
""",
        encoding="utf-8",
    )
    live = _live_file(tmp_path, ("reports_read", "ledger_commit"))
    assert (
        main(
            [
                "catalog",
                "diff",
                "--policy",
                str(broken),
                "--live-file",
                str(live),
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "Only in live (unreachable by any role):" in out
    assert "ledger_commit" in out
    assert "Unmatched allow patterns:" in out
    assert "editor:docments_*" in out


def test_catalog_export_active_tier(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    live = _live_file(tmp_path, ("beta_tool", "alpha_tool", "alpha_tool"))
    assert main(["catalog", "export", "--live-file", str(live)]) == 0
    out = capsys.readouterr().out
    assert "active:" in out
    assert "- alpha_tool" in out
    assert "- beta_tool" in out


# --- `catalog validate --json` (issue #8) --------------------------------------------


def _run_json(argv: list[str]) -> tuple[int, dict]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        exit_code = main(argv)
    return exit_code, json.loads(out.getvalue())


def test_catalog_validate_json_success(policy_path: Path, tmp_path: Path):
    live = _live_file(tmp_path, LIVE_OK)
    exit_code, payload = _run_json(
        [
            "catalog",
            "validate",
            "--policy",
            str(policy_path),
            "--live-file",
            str(live),
            "--json",
        ]
    )
    assert exit_code == 0
    assert payload == {
        "schema_version": 1,
        "ok": True,
        "unmatched_allow_patterns": [],
        "unreachable_tools": [],
        "duplicate_live_names": [],
        "problems": [],
    }


def test_catalog_validate_json_unmatched_allow_pattern(policy_path: Path, tmp_path: Path):
    broken = tmp_path / "broken-policy.yaml"
    broken.write_text(TEST_POLICY.replace("documents_*", "docments_*", 1), encoding="utf-8")
    live = _live_file(tmp_path, LIVE_OK)
    exit_code, payload = _run_json(
        [
            "catalog",
            "validate",
            "--policy",
            str(broken),
            "--live-file",
            str(live),
            "--json",
        ]
    )
    assert exit_code == 1
    assert payload["ok"] is False
    assert payload["schema_version"] == 1
    assert "editor:docments_*" in payload["unmatched_allow_patterns"]
    assert payload["duplicate_live_names"] == []
    assert len(payload["problems"]) == 1
    problem = payload["problems"][0]
    assert problem["code"] == "policy_invalid"
    assert problem["entry"] is None
    assert problem["field"] is None
    assert "editor:docments_*" in problem["message"]


def test_catalog_validate_json_duplicate_live_names(policy_path: Path, tmp_path: Path):
    live = _live_file(tmp_path, ("reports_read", "reports_read"))
    exit_code, payload = _run_json(
        [
            "catalog",
            "validate",
            "--policy",
            str(policy_path),
            "--live-file",
            str(live),
            "--json",
        ]
    )
    assert exit_code == 1
    assert payload["ok"] is False
    assert payload["duplicate_live_names"] == ["reports_read"]
    assert payload["problems"][0]["code"] == "duplicate_live_name"


def test_catalog_validate_json_strict_unreachable(tmp_path: Path):
    narrow_policy = tmp_path / "narrow.yaml"
    narrow_policy.write_text(
        """\
version: "0.1"
default_deny: true
roles:
  viewer:
    allow: ["reports_read"]
""",
        encoding="utf-8",
    )
    live = _live_file(tmp_path, ("reports_read", "ledger_commit"))
    exit_code, payload = _run_json(
        [
            "catalog",
            "validate",
            "--policy",
            str(narrow_policy),
            "--live-file",
            str(live),
            "--strict-unreachable",
            "--json",
        ]
    )
    assert exit_code == 1
    assert payload["ok"] is False
    assert payload["unreachable_tools"] == ["ledger_commit"]
    assert payload["unmatched_allow_patterns"] == []
    assert payload["problems"][0]["code"] == "unreachable_tools_strict"


def test_catalog_validate_json_unreachable_tools_present_without_strict(tmp_path: Path):
    """unreachable_tools is always reported, even when it does not fail the run."""
    narrow_policy = tmp_path / "narrow.yaml"
    narrow_policy.write_text(
        """\
version: "0.1"
default_deny: true
roles:
  viewer:
    allow: ["reports_read"]
""",
        encoding="utf-8",
    )
    live = _live_file(tmp_path, ("reports_read", "no_role_can_reach_this"))
    exit_code, payload = _run_json(
        [
            "catalog",
            "validate",
            "--policy",
            str(narrow_policy),
            "--live-file",
            str(live),
            "--json",
        ]
    )
    assert exit_code == 0
    assert payload["ok"] is True
    assert payload["unreachable_tools"] == ["no_role_can_reach_this"]
    assert payload["problems"] == []


def test_catalog_validate_json_live_url_unreachable(
    policy_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def _fail(_url: str, timeout: float = 10.0):
        raise OSError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", _fail)
    exit_code, payload = _run_json(
        [
            "catalog",
            "validate",
            "--policy",
            str(policy_path),
            "--live-url",
            "http://127.0.0.1:9/internal/live-published-names",
            "--json",
        ]
    )
    assert exit_code == 3
    assert payload["ok"] is False
    assert payload["problems"][0]["code"] == "live_url_unreachable"


def test_catalog_validate_text_mode_unaffected_by_json_support(policy_path: Path, tmp_path: Path):
    """Adding --json must not change a single character of the default text output."""
    broken = tmp_path / "broken-policy.yaml"
    broken.write_text(TEST_POLICY.replace("documents_*", "docments_*", 1), encoding="utf-8")
    live = _live_file(tmp_path, LIVE_OK)
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        exit_code = main(
            [
                "catalog",
                "validate",
                "--policy",
                str(broken),
                "--live-file",
                str(live),
            ]
        )
    assert exit_code == 1
    assert out.getvalue() == ""
    assert "editor:docments_*" in err.getvalue()
