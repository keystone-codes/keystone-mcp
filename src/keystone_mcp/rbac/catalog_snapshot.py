"""Optional catalog snapshot file: names a deployment declares but may not mount.

The router validates allow patterns against the tools it actually discovered.
A deployment that names tools in policy before the upstream publishes them
(or that runs a deployment mounting only part of its catalog) supplies a snapshot
file so those allow rows are still checked instead of silently accepted:

.. code-block:: yaml

    active: ["reports_read"]      # known live in the reference deployment
    reserved: ["ledger_commit"]   # named in policy before publication
    wip: ["reports_approve_run"]  # work in progress

All three sections are optional. No snapshot file means all three are empty.
The path comes from ``KEYSTONE_MCP_RBAC_CATALOG_SNAPSHOT``
(``Settings.rbac_catalog_snapshot_path``); an empty value means "no snapshot".
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from keystone_mcp.config import Settings

SNAPSHOT_SECTIONS: frozenset[str] = frozenset({"active", "reserved", "wip"})


class CatalogSnapshotError(ValueError):
    """Raised when a catalog snapshot file cannot be parsed or is malformed."""


@dataclass(frozen=True, slots=True)
class CatalogSnapshot:
    """Declared tool-name tiers for policy validation."""

    active: frozenset[str] = frozenset()
    reserved: frozenset[str] = frozenset()
    wip: frozenset[str] = frozenset()
    source_path: Path | None = None

    @property
    def is_empty(self) -> bool:
        return not (self.active or self.reserved or self.wip)

    @property
    def all_names(self) -> frozenset[str]:
        return self.active | self.reserved | self.wip


EMPTY_CATALOG_SNAPSHOT = CatalogSnapshot()


def load_catalog_snapshot(path: Path | str) -> CatalogSnapshot:
    """Load a snapshot file. Unknown keys and non-string entries are refused."""
    snapshot_path = Path(path)
    try:
        raw = snapshot_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CatalogSnapshotError(f"catalog snapshot unreadable: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise CatalogSnapshotError(f"invalid YAML in catalog snapshot: {exc}") from exc
    if data is None:
        return CatalogSnapshot(source_path=snapshot_path)
    if not isinstance(data, dict):
        raise CatalogSnapshotError("catalog snapshot root must be a mapping")
    unknown = sorted(set(map(str, data)) - SNAPSHOT_SECTIONS)
    if unknown:
        raise CatalogSnapshotError(
            "unknown keys in catalog snapshot: "
            + ", ".join(unknown)
            + f" (allowed: {', '.join(sorted(SNAPSHOT_SECTIONS))})"
        )
    return CatalogSnapshot(
        active=_names(data.get("active"), "active"),
        reserved=_names(data.get("reserved"), "reserved"),
        wip=_names(data.get("wip"), "wip"),
        source_path=snapshot_path,
    )


def load_catalog_snapshot_for_settings(settings: Settings) -> CatalogSnapshot:
    """Load the configured snapshot, or the empty snapshot when unset."""
    configured = settings.rbac_catalog_snapshot_path.strip()
    if not configured:
        return EMPTY_CATALOG_SNAPSHOT
    return load_catalog_snapshot(configured)


def _names(raw: Any, section: str) -> frozenset[str]:
    if raw is None:
        return frozenset()
    if not isinstance(raw, list):
        raise CatalogSnapshotError(f"catalog snapshot {section} must be a list when present")
    names: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            raise CatalogSnapshotError(
                f"catalog snapshot {section} entries must be strings, got {type(item).__name__}"
            )
        text = item.strip()
        if text:
            names.add(text)
    return frozenset(names)
