"""Parse a generated per-tool matrix markdown file as an independent oracle.

Role columns are read from the table header, so the parser has no built-in
role names.
"""

from __future__ import annotations

import re
from pathlib import Path

_HEADER_RE = re.compile(r"^\|\s*Tool\s*\|\s*Disp\.\s*\|(?P<roles>.+)\|\s*$")
_ROW_RE = re.compile(r"^\|\s*`(?P<tool>[^`]+)`\s*\|(?P<cells>.+)\|\s*$")


def parse_committed_per_tool_matrix(path: Path) -> dict[str, dict[str, bool]]:
    """Return ``{tool_name: {role: allowed}}`` from a generated matrix file."""
    roles: list[str] = []
    decisions: dict[str, dict[str, bool]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        header = _HEADER_RE.match(line)
        if header is not None:
            roles = [cell.strip() for cell in header.group("roles").split("|") if cell.strip()]
            continue
        row = _ROW_RE.match(line)
        if row is None or not roles:
            continue
        cells = [cell.strip() for cell in row.group("cells").split("|")]
        verdicts = cells[1 : 1 + len(roles)]
        if len(verdicts) != len(roles) or any(v not in ("allow", "deny") for v in verdicts):
            continue
        decisions[row.group("tool")] = dict(
            zip(roles, [v == "allow" for v in verdicts], strict=True)
        )
    if not decisions:
        raise ValueError(f"no matrix rows parsed from {path}")
    return decisions


def doc_roles(doc: dict[str, dict[str, bool]]) -> tuple[str, ...]:
    """Role columns present in the parsed document."""
    for row in doc.values():
        return tuple(row)
    return ()


def doc_allows(doc: dict[str, dict[str, bool]], role: str, tool: str) -> bool:
    row = doc.get(tool)
    if row is None:
        raise KeyError(f"tool {tool!r} missing from committed matrix doc")
    if role not in row:
        raise KeyError(f"role {role!r} missing for tool {tool!r}")
    return row[role]
