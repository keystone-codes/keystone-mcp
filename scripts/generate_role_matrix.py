#!/usr/bin/env python3
"""Regenerate a per-tool role matrix markdown file from an RBAC policy.

Tool names come from the optional catalog snapshot plus every literal
(glob-free) name the policy mentions; globs cannot be expanded without a
catalog.

    python scripts/generate_role_matrix.py \
        --policy config/rbac-policy.yaml \
        --snapshot examples/catalog-snapshot.example.yaml \
        --output docs/rbac-role-matrix-per-tool.md
"""

from __future__ import annotations

import argparse
from pathlib import Path

from keystone_mcp.rbac.catalog_snapshot import (
    EMPTY_CATALOG_SNAPSHOT,
    load_catalog_snapshot,
)
from keystone_mcp.rbac.matrix_doc import (
    generate_per_tool_matrix_markdown,
    policy_tool_universe,
)
from keystone_mcp.rbac.policy import load_policy_file

_REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = _REPO_ROOT / "config" / "rbac-policy.yaml"
DEFAULT_OUTPUT = _REPO_ROOT / "docs" / "rbac-role-matrix-per-tool.md"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_POLICY,
        help="RBAC policy file (default: config/rbac-policy.yaml)",
    )
    parser.add_argument(
        "--snapshot",
        type=Path,
        default=None,
        help="Optional catalog snapshot file naming active/reserved/wip tools",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Markdown file to write (default: docs/rbac-role-matrix-per-tool.md)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    policy = load_policy_file(args.policy)
    snapshot = load_catalog_snapshot(args.snapshot) if args.snapshot else EMPTY_CATALOG_SNAPSHOT
    tool_names = policy_tool_universe(policy, snapshot)
    markdown = generate_per_tool_matrix_markdown(policy, tool_names)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(markdown, encoding="utf-8")
    print(f"Wrote {args.output} ({len(tool_names)} tools)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
