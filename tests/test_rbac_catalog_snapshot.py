"""Optional catalog snapshot file: parsing, tiers and settings wiring."""

from __future__ import annotations

from pathlib import Path

import pytest

from keystone_mcp.config import Settings
from keystone_mcp.rbac.catalog_snapshot import (
    EMPTY_CATALOG_SNAPSHOT,
    CatalogSnapshotError,
    load_catalog_snapshot,
    load_catalog_snapshot_for_settings,
)

_EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "catalog-snapshot.example.yaml"

FULL_SNAPSHOT = """
active: ["reports_read", "reports_write"]
reserved: ["documents_purge"]
wip: ["reports_approve_run"]
"""


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "snapshot.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_all_tiers_load(tmp_path: Path):
    snapshot = load_catalog_snapshot(_write(tmp_path, FULL_SNAPSHOT))
    assert snapshot.active == frozenset({"reports_read", "reports_write"})
    assert snapshot.reserved == frozenset({"documents_purge"})
    assert snapshot.wip == frozenset({"reports_approve_run"})
    assert snapshot.all_names == frozenset(
        {"reports_read", "reports_write", "documents_purge", "reports_approve_run"}
    )
    assert snapshot.is_empty is False


def test_missing_sections_default_to_empty(tmp_path: Path):
    snapshot = load_catalog_snapshot(_write(tmp_path, 'active: ["reports_read"]\n'))
    assert snapshot.reserved == frozenset()
    assert snapshot.wip == frozenset()


def test_empty_file_is_an_empty_snapshot(tmp_path: Path):
    snapshot = load_catalog_snapshot(_write(tmp_path, ""))
    assert snapshot.is_empty is True


def test_unknown_key_is_refused(tmp_path: Path):
    with pytest.raises(CatalogSnapshotError, match="unknown keys"):
        load_catalog_snapshot(_write(tmp_path, 'published: ["reports_read"]\n'))


def test_non_mapping_root_is_refused(tmp_path: Path):
    with pytest.raises(CatalogSnapshotError, match="must be a mapping"):
        load_catalog_snapshot(_write(tmp_path, "- reports_read\n"))


def test_non_list_section_is_refused(tmp_path: Path):
    with pytest.raises(CatalogSnapshotError, match="active must be a list"):
        load_catalog_snapshot(_write(tmp_path, "active: reports_read\n"))


def test_non_string_entry_is_refused(tmp_path: Path):
    with pytest.raises(CatalogSnapshotError, match="entries must be strings"):
        load_catalog_snapshot(_write(tmp_path, "active: [17]\n"))


def test_invalid_yaml_is_refused(tmp_path: Path):
    with pytest.raises(CatalogSnapshotError, match="invalid YAML"):
        load_catalog_snapshot(_write(tmp_path, "active: [unclosed\n"))


def test_missing_file_is_refused(tmp_path: Path):
    with pytest.raises(CatalogSnapshotError, match="unreadable"):
        load_catalog_snapshot(tmp_path / "nope.yaml")


def test_unset_setting_yields_the_empty_snapshot():
    settings = Settings(base_url="http://localhost:8080")
    assert settings.rbac_catalog_snapshot_path == ""
    assert load_catalog_snapshot_for_settings(settings) is EMPTY_CATALOG_SNAPSHOT


def test_configured_setting_is_loaded(tmp_path: Path):
    path = _write(tmp_path, FULL_SNAPSHOT)
    settings = Settings(base_url="http://localhost:8080", rbac_catalog_snapshot_path=str(path))
    snapshot = load_catalog_snapshot_for_settings(settings)
    assert snapshot.source_path == path
    assert "reports_read" in snapshot.active


def test_shipped_example_snapshot_parses():
    snapshot = load_catalog_snapshot(_EXAMPLE)
    assert snapshot.active
    assert snapshot.reserved
    assert snapshot.wip
