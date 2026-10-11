"""Shared helpers for RBAC conformance tests.

The fixture policy and catalog snapshot live next to this module in
``data/``; both use fictional tool names, so nothing here encodes a
deployment's catalog.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from fastmcp import FastMCP

from keystone_mcp.adapters.stub import StubAdapter
from keystone_mcp.config import Settings
from keystone_mcp.observability.service import RbacObservability
from keystone_mcp.rbac.catalog_snapshot import load_catalog_snapshot
from keystone_mcp.rbac.loader import RbacPolicyManager
from keystone_mcp.rbac.policy import RbacPolicy, load_policy_file
from keystone_mcp.router.engine import RouterEngine
from keystone_mcp.router.rbac_middleware import RbacDecision, RbacMiddleware
from keystone_mcp.router.registry import RouterRegistry
from keystone_mcp.user_directory import build_in_memory_user_directory_resolver

_DATA = Path(__file__).resolve().parent / "data"
CONFORMANCE_POLICY_PATH = _DATA / "conformance-policy.yaml"
CONFORMANCE_SNAPSHOT_PATH = _DATA / "conformance-snapshot.yaml"

CONFORMANCE_EMAIL = "conformance@example.com"

#: Single roles plus representative multi-role unions.
CONFORMANCE_ROLE_SETS: tuple[tuple[str, ...], ...] = (
    ("administrator",),
    ("editor",),
    ("reviewer",),
    ("viewer",),
    ("editor", "reviewer"),
    ("editor", "viewer"),
)


def conformance_policy() -> RbacPolicy:
    return load_policy_file(CONFORMANCE_POLICY_PATH)


def conformance_snapshot():
    return load_catalog_snapshot(CONFORMANCE_SNAPSHOT_PATH)


def live_tool_names() -> frozenset[str]:
    """Names the fixture deployment actually mounts."""
    return conformance_snapshot().active


def conformance_tool_names() -> frozenset[str]:
    """Live names plus the reserved/WIP names the policy references."""
    snapshot = conformance_snapshot()
    return snapshot.all_names


@dataclass
class ConformanceHarness:
    """Middleware + registry wired for matrix conformance checks."""

    middleware: RbacMiddleware
    policy: RbacPolicy
    backend: object
    catalog: frozenset[str]


def expected_visible_tools(
    policy: RbacPolicy,
    roles: Iterable[str],
    catalog: Iterable[str],
) -> frozenset[str]:
    role_set = frozenset(roles)
    return frozenset(tool for tool in catalog if policy.allows(role_set, tool))


def iter_policy_coherence_cases(
    policy: RbacPolicy,
    catalog: Iterable[str],
    role_sets: Sequence[tuple[str, ...]] = CONFORMANCE_ROLE_SETS,
) -> list[tuple[tuple[str, ...], str, bool]]:
    """Expand role x tool expectations from the loaded policy (wiring coherence)."""
    tools = tuple(sorted(catalog))
    cases: list[tuple[tuple[str, ...], str, bool]] = []
    for role_set in role_sets:
        roles = frozenset(role_set)
        for tool in tools:
            cases.append((role_set, tool, policy.allows(roles, tool)))
    return cases


def role_set_label(role_set: tuple[str, ...]) -> str:
    return "+".join(role_set) if role_set else "no_roles"


def conformance_settings(
    *,
    policy_path: Path | None = None,
    snapshot_path: Path | None = CONFORMANCE_SNAPSHOT_PATH,
) -> Settings:
    return Settings(
        base_url="http://localhost:8080",
        rbac_mode="enforce",
        rbac_policy_path=str(policy_path or CONFORMANCE_POLICY_PATH),
        rbac_catalog_snapshot_path=str(snapshot_path) if snapshot_path else "",
        users_service_url="http://users:8000",
        users_service_token="token",
        redis_url="redis://localhost:6379/0",
    )


def build_conformance_harness(
    *,
    roles: tuple[str, ...],
    email: str = CONFORMANCE_EMAIL,
    policy_path: Path | None = None,
    snapshot_path: Path | None = CONFORMANCE_SNAPSHOT_PATH,
    is_blocked: bool = False,
    directory_unavailable: bool = False,
    load_policy_into_manager: bool = True,
    live_tools: frozenset[str] | None = None,
    catalog: frozenset[str] | None = None,
    observability: RbacObservability | None = None,
) -> ConformanceHarness:
    """Build RbacMiddleware over the fixture policy and a mounted tool catalog."""
    resolved_policy_path = policy_path or CONFORMANCE_POLICY_PATH
    tool_catalog = catalog if catalog is not None else conformance_tool_names()
    mounted = live_tools if live_tools is not None else live_tool_names()
    settings = conformance_settings(
        policy_path=resolved_policy_path,
        snapshot_path=snapshot_path,
    )
    resolver, backend, _revision = build_in_memory_user_directory_resolver()
    backend.unavailable = directory_unavailable
    backend.seed(email, roles=roles, is_blocked=is_blocked)
    registry = RouterRegistry(RouterEngine(settings), FastMCP("conformance-host"))
    for tool_name in sorted(mounted):
        registry.add_route(tool_name, StubAdapter(), mode="live")
    manager = RbacPolicyManager(settings)
    if load_policy_into_manager:
        manager.load_initial(registry)
    if observability is None and settings.rbac_audit_enabled:
        observability = RbacObservability(settings, policy_manager=manager)
    middleware = RbacMiddleware(
        manager,
        resolver,
        observability=observability,
    )
    return ConformanceHarness(
        middleware=middleware,
        policy=load_policy_file(resolved_policy_path),
        backend=backend,
        catalog=tool_catalog,
    )


class DecisionRecorder:
    """Capture middleware RBAC decisions for negative/reason assertions.

    Fragile: monkey-patches ``RbacMiddleware._record_decision``. Prefer wiring
    ``RbacObservability`` (public ``record_authz_decision`` hook) when audit is on.
    """

    def __init__(self) -> None:
        self.decisions: list[tuple[str, RbacDecision]] = []

    def attach(self, middleware: RbacMiddleware) -> None:
        original = middleware._record_decision

        def _capture(decision: RbacDecision, *, operation: str) -> None:
            self.decisions.append((operation, decision))
            original(decision, operation=operation)

        middleware._record_decision = _capture  # type: ignore[method-assign]

    @property
    def last(self) -> RbacDecision | None:
        if not self.decisions:
            return None
        return self.decisions[-1][1]


def render_conformance_report(
    policy: RbacPolicy,
    catalog: Iterable[str],
    role_sets: Sequence[tuple[str, ...]] = CONFORMANCE_ROLE_SETS,
) -> str:
    """Human-readable role x tool matrix for acceptance (fact == policy oracle)."""
    tools = sorted(catalog)
    lines = [
        "# RBAC conformance matrix (generated)",
        "",
        f"Source: policy `{policy.version}` x fixture catalog.",
        "Policy-coherence rows mirror `policy.allows()`; the golden cases are the",
        "independent oracle.",
        "",
        "| Role set | Tool | Expected |",
        "| --- | --- | --- |",
    ]
    for role_set in role_sets:
        label = role_set_label(role_set)
        roles = frozenset(role_set)
        for tool in tools:
            allowed = policy.allows(roles, tool)
            lines.append(f"| `{label}` | `{tool}` | {'allow' if allowed else 'deny'} |")
    lines.append("")
    lines.append(f"Roles covered: {len(role_sets)}; tools: {len(tools)}.")
    return "\n".join(lines)
