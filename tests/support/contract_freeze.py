"""Pure helpers for contract freeze comparisons (baseline vs current snapshots)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

_SNAPSHOT_HEADER = re.compile(r"^#\s+section=")
_ATTR_PAIR = re.compile(r"(\w+)=(\S+)")


@dataclass(frozen=True, slots=True)
class Finding:
    kind: str
    key: str
    anchor: str
    before: str
    after: str


def parse_attrs(raw: str) -> dict[str, str]:
    if not raw:
        return {}
    out: dict[str, str] = {}
    for match in _ATTR_PAIR.finditer(raw):
        out[match.group(1)] = match.group(2)
    return out


def format_attrs(attrs: dict[str, str]) -> str:
    if not attrs:
        return ""
    return " ".join(f"{key}={attrs[key]}" for key in sorted(attrs))


def load_snapshot(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            key, attrs = line.split("\t", 1)
        else:
            key, attrs = line, ""
        rows[key] = attrs
    return rows


def project_major(pyproject_text: str) -> int:
    match = re.search(r'^version\s*=\s*"(\d+)\.', pyproject_text, re.MULTILINE)
    if not match:
        raise ValueError("could not parse project version from pyproject.toml")
    return int(match.group(1))


def changelog_current_sections(text: str, version: str) -> dict[str, str]:
    """Collect ### subsection bodies from [Unreleased] and [version]."""
    sections: dict[str, list[str]] = {}
    active: str | None = None
    in_target = False
    version_heading = f"## [{version}]"
    for line in text.splitlines():
        if line.startswith("## "):
            in_target = line.startswith("## [Unreleased]") or line == version_heading
            active = None
            continue
        if not in_target:
            continue
        if line.startswith("### "):
            active = line.removeprefix("### ").strip()
            sections.setdefault(active, [])
            continue
        if active is not None:
            sections[active].append(line)
    return {name: "\n".join(lines) for name, lines in sections.items()}


def _attrs_relaxed(before: dict[str, str], after: dict[str, str]) -> bool:
    if before == after:
        return True
    merged = dict(before)
    if before.get("required") == "yes" and after.get("required") == "no":
        merged["required"] = "no"
    if before.get("nullable") == "no" and after.get("nullable") == "yes":
        merged["nullable"] = "yes"
    for key, value in after.items():
        if key in ("required", "nullable"):
            continue
        if merged.get(key) != value:
            return False
    return merged.get("required") == after.get("required") and merged.get("nullable") == after.get(
        "nullable"
    )


def _is_protocol_class(key: str, base: dict[str, str]) -> bool:
    attrs = parse_attrs(base.get(key, ""))
    return attrs.get("kind") == "protocol"


def _class_key_for_member(member_key: str) -> str | None:
    if "(" in member_key:
        return member_key.split("(", 1)[0]
    if "." in member_key:
        parts = member_key.rsplit(".", 1)
        if len(parts) == 2:
            return parts[0]
    return None


def _tool_name_for_arg(arg_key: str) -> str:
    if "(" in arg_key:
        return arg_key.split("(", 1)[0]
    return arg_key


def findings(section: str, base: dict[str, str], current: dict[str, str]) -> list[Finding]:
    from support.contract_snapshot import anchor

    out: list[Finding] = []
    base_keys = set(base)
    current_keys = set(current)

    for key in sorted(base_keys - current_keys):
        out.append(
            Finding(
                kind="removed",
                key=key,
                anchor=anchor(section, key),
                before=base[key],
                after="",
            )
        )

    for key in sorted(base_keys & current_keys):
        if not _attrs_relaxed(parse_attrs(base[key]), parse_attrs(current[key])):
            out.append(
                Finding(
                    kind="changed",
                    key=key,
                    anchor=anchor(section, key),
                    before=base[key],
                    after=current[key],
                )
            )

    protocol_classes = {
        key for key, raw in base.items() if parse_attrs(raw).get("kind") == "protocol"
    }

    for key in sorted(current_keys - base_keys):
        kind = "addition"
        if section == "protocols":
            for class_key in protocol_classes:
                if key.startswith(f"{class_key}.") and key != class_key:
                    kind = "breaking_addition"
                    break
            if kind == "addition" and "(" in key:
                attrs = parse_attrs(current[key])
                member = key.split("(", 1)[0]
                if attrs.get("required") == "yes" and member in base_keys:
                    kind = "breaking_addition"
        elif section == "builtin-tools" and "(" in key:
            attrs = parse_attrs(current[key])
            if attrs.get("required") == "yes":
                tool = _tool_name_for_arg(key)
                if tool in base_keys:
                    kind = "breaking_addition"
        out.append(
            Finding(
                kind=kind,
                key=key,
                anchor=anchor(section, key),
                before="",
                after=current[key],
            )
        )

    return out


def _anchor_in_section(anchor: str, section_text: str) -> bool:
    return anchor in section_text


def violations(
    finding_list: list[Finding],
    major: int,
    sections: dict[str, str],
) -> list[Finding]:
    removed_text = sections.get("Removed", "")
    changed_text = sections.get("Changed", "")
    security_text = sections.get("Security", "")
    migration_text = sections.get("Migration", "")

    bad: list[Finding] = []
    for item in finding_list:
        if item.kind == "addition":
            continue
        if major >= 2:
            if item.kind == "removed":
                if _anchor_in_section(item.anchor, removed_text):
                    continue
            elif item.kind in ("changed", "breaking_addition"):
                if _anchor_in_section(item.anchor, changed_text):
                    continue
            bad.append(item)
            continue

        if item.kind == "removed" or item.kind == "breaking_addition":
            bad.append(item)
            continue
        if item.kind == "changed":
            if _anchor_in_section(item.anchor, security_text) and _anchor_in_section(
                item.anchor, migration_text
            ):
                continue
            bad.append(item)
    return bad
