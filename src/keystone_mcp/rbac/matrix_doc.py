"""Per-tool role matrix generation from a policy file plus an optional snapshot."""

from __future__ import annotations

from collections.abc import Iterable

from keystone_mcp.rbac.catalog_snapshot import EMPTY_CATALOG_SNAPSHOT, CatalogSnapshot
from keystone_mcp.rbac.policy import RbacPolicy


def tool_disposition(tool_name: str, policy: RbacPolicy) -> str:
    """Disposition label for a tool, from the policy's ``tool_dispositions``.

    Entries are evaluated in file order; the first matching label wins. Tools
    that match nothing get :data:`keystone_mcp.rbac.policy.FALLBACK_DISPOSITION`.
    """
    return policy.disposition(tool_name)


def policy_tool_universe(
    policy: RbacPolicy,
    snapshot: CatalogSnapshot = EMPTY_CATALOG_SNAPSHOT,
    *,
    extra_tool_names: Iterable[str] = (),
) -> frozenset[str]:
    """Tool names a matrix can be rendered for.

    Globs cannot be expanded without a catalog, so the universe is the snapshot
    tiers, every literal (glob-free) name the policy mentions, and any extra
    names the caller supplies.
    """
    return snapshot.all_names | policy.literal_allow_names() | frozenset(extra_tool_names)


def generate_per_tool_matrix_markdown(
    policy: RbacPolicy,
    tool_names: frozenset[str],
    *,
    title: str = "Per-tool role matrix (generated)",
) -> str:
    """Render a role x tool x disposition table from policy and catalog."""
    roles = sorted(policy.role_names)
    lines = [
        f"# {title}",
        "",
        "Auto-generated from the RBAC policy file and the optional catalog snapshot.",
        "Regenerate: `python scripts/generate_role_matrix.py`.",
        "",
        f"Policy version: `{policy.version}`.",
        "",
        "| Tool | Disp. | " + " | ".join(roles) + " |",
        "|------|-------|" + "|".join(["---"] * len(roles)) + "|",
    ]
    for tool in sorted(tool_names):
        disp = tool_disposition(tool, policy)
        cells = ["allow" if policy.allows_role(role, tool) else "deny" for role in roles]
        lines.append(f"| `{tool}` | {disp} | " + " | ".join(cells) + " |")
    lines.append("")
    return "\n".join(lines)
