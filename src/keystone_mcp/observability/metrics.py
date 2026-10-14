"""Prometheus counters and histograms for RBAC authorization events."""

from __future__ import annotations

from typing import TYPE_CHECKING

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

from keystone_mcp.observability.tool_call_labels import (
    ClientIdLabelLimiter,
    resolve_tool_call_metric_labels,
)

if TYPE_CHECKING:
    from keystone_mcp.router.rbac_middleware import RbacDenialReason

_DECISION = Counter(
    "keystone_mcp_rbac_decisions_total",
    "RBAC authorization decisions",
    ["decision", "reason", "tool_family", "operation"],
)
_TOOL_CALL_LABELS = (
    "tool_family",
    "namespace",
    "tool",
    "auth_method",
    "oauth_client_id",
)
_TOOL_CALL_ATTEMPTS = Counter(
    "keystone_mcp_tool_call_attempts_total",
    "MCP call_tool attempts entering the middleware stack",
    list(_TOOL_CALL_LABELS),
)
_TOOL_INVOCATIONS = Counter(
    "keystone_mcp_tool_invocations_total",
    "MCP call_tool invocations that reached the handler",
    [*list(_TOOL_CALL_LABELS), "outcome"],
)
_TOOL_INVOCATION_SECONDS = Histogram(
    "keystone_mcp_tool_invocation_seconds",
    "MCP call_tool handler latency",
    [*list(_TOOL_CALL_LABELS), "outcome"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)
_DIRECTORY_RESOLVE = Counter(
    "keystone_mcp_rbac_directory_resolve_total",
    "User-directory resolve outcomes",
    ["outcome"],
)
_POLICY_RELOAD = Counter(
    "keystone_mcp_rbac_policy_reload_total",
    "RBAC policy load/reload attempts",
    ["success"],
)
_USERS_MUTATION = Counter(
    "keystone_mcp_users_mutation_total",
    "users_* administrative mutations",
    ["operation", "outcome"],
)
_POLICY_MUTATION = Counter(
    "keystone_mcp_policy_mutation_total",
    "policy_* administrative mutations",
    ["operation", "outcome"],
)
_CATALOG_REFRESH = Counter(
    "keystone_mcp_catalog_refresh_total",
    "Upstream catalog reconciliation outcomes",
    ["outcome"],
)
_CATALOG_CHANGES = Counter(
    "keystone_mcp_catalog_refresh_changes_total",
    "Tools added or removed by catalog reconciliation",
    ["direction"],
)
_LIST_CHANGED_SESSIONS = Counter(
    "keystone_mcp_list_changed_sessions_total",
    "Sessions notified that a list of tools/prompts/resources changed",
    ["kind"],
)
_DIRECTORY_RESPONSE_ISSUES = Counter(
    "keystone_mcp_users_directory_response_issues_total",
    "Lenient parsing of HTTP users directory resolve responses",
    ["field", "issue"],
)
_RESOLVE_LATENCY = Histogram(
    "keystone_mcp_rbac_directory_resolve_seconds",
    "User-directory resolve latency",
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 3.0),
)
_UPSTREAM_AVAILABLE = Gauge(
    "keystone_mcp_upstream_available",
    "1 when the last discovery or refresh of the upstream succeeded, else 0",
    ["namespace"],
)
_UPSTREAM_PROCESS_RESTARTS = Counter(
    "keystone_mcp_upstream_process_restarts_total",
    "Restarts of stdio upstream processes",
    ["namespace"],
)
_UPSTREAM_ELICITATIONS = Counter(
    "keystone_mcp_upstream_elicitations_total",
    "Upstream elicitation rounds forwarded to the Keystone client",
    ["namespace", "action"],
)
_OAUTH_CLIENT_REGISTRATIONS = Counter(
    "keystone_mcp_oauth_client_registrations_total",
    "Dynamic client registration (POST /register) outcomes",
    ["outcome"],
)
_OAUTH_CLIENTS = Gauge(
    "keystone_mcp_oauth_clients",
    "Live (non-expired) registered OAuth clients, as seen by this replica",
)
_ADMIN_REFUSALS = Counter(
    "keystone_mcp_admin_refusals_total",
    "Administration tool calls refused by a built-in rule (not by the policy file)",
    ["operation", "reason"],
)


class RbacMetrics:
    """Thin wrapper around prometheus_client counters for RBAC events."""

    def __init__(
        self,
        *,
        enabled: bool,
        tool_name_mode: str = "full",
        oauth_client_id_limit: int = 50,
    ) -> None:
        self._enabled = enabled
        self._tool_name_mode = tool_name_mode
        self._client_id_limiter = ClientIdLabelLimiter(oauth_client_id_limit)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def record_decision(
        self,
        *,
        allowed: bool,
        reason: RbacDenialReason | None,
        tool_family_label: str,
        operation: str,
    ) -> None:
        if not self._enabled:
            return
        decision = "allow" if allowed else "deny"
        reason_label = reason.value if reason is not None else "none"
        _DECISION.labels(
            decision=decision,
            reason=reason_label,
            tool_family=tool_family_label,
            operation=operation,
        ).inc()

    def _tool_call_labels(self, tool_name: str, *, known: bool = True) -> dict[str, str]:
        labels = resolve_tool_call_metric_labels(
            tool_name,
            tool_name_mode=self._tool_name_mode,
            known=known,
        ).as_dict()
        labels["oauth_client_id"] = self._client_id_limiter.label(labels["oauth_client_id"])
        return labels

    def record_tool_call_attempt(self, *, tool_name: str, known: bool = True) -> None:
        if not self._enabled:
            return
        _TOOL_CALL_ATTEMPTS.labels(**self._tool_call_labels(tool_name, known=known)).inc()

    def record_tool_invocation(
        self,
        *,
        tool_name: str,
        outcome: str,
        duration_seconds: float,
        known: bool = True,
    ) -> None:
        if not self._enabled:
            return
        labels = {**self._tool_call_labels(tool_name, known=known), "outcome": outcome}
        _TOOL_INVOCATIONS.labels(**labels).inc()
        _TOOL_INVOCATION_SECONDS.labels(**labels).observe(duration_seconds)

    def record_directory_resolve(
        self,
        *,
        outcome: str,
        duration_seconds: float | None = None,
    ) -> None:
        if not self._enabled:
            return
        _DIRECTORY_RESOLVE.labels(outcome=outcome).inc()
        if duration_seconds is not None:
            _RESOLVE_LATENCY.observe(duration_seconds)

    def record_policy_reload(self, *, success: bool) -> None:
        if not self._enabled:
            return
        _POLICY_RELOAD.labels(success="true" if success else "false").inc()

    def record_users_mutation(self, *, operation: str, outcome: str) -> None:
        if not self._enabled:
            return
        _USERS_MUTATION.labels(operation=operation, outcome=outcome).inc()

    def record_policy_mutation(self, *, operation: str, outcome: str) -> None:
        if not self._enabled:
            return
        _POLICY_MUTATION.labels(operation=operation, outcome=outcome).inc()

    def record_admin_refusal(self, *, operation: str, reason: str) -> None:
        """Record a built-in administration refusal.

        ``reason`` values include ``service_account``, ``management_role``, and
        ``delegation`` (future cards).
        """
        if not self._enabled:
            return
        _ADMIN_REFUSALS.labels(operation=operation, reason=reason).inc()

    def record_catalog_refresh(
        self,
        *,
        unchanged: bool = False,
        held: bool = False,
        applied: bool = False,
        added: int = 0,
        removed: int = 0,
    ) -> None:
        if not self._enabled:
            return
        if held:
            _CATALOG_REFRESH.labels(outcome="held").inc()
        elif applied:
            _CATALOG_REFRESH.labels(outcome="applied").inc()
        elif unchanged:
            _CATALOG_REFRESH.labels(outcome="unchanged").inc()
        if added:
            _CATALOG_CHANGES.labels(direction="added").inc(added)
        if removed:
            _CATALOG_CHANGES.labels(direction="removed").inc(removed)

    def record_list_changed(self, *, kind: str, sessions: int) -> None:
        if not self._enabled or sessions <= 0:
            return
        _LIST_CHANGED_SESSIONS.labels(kind=kind).inc(sessions)

    def set_upstream_available(self, *, namespace: str, available: bool) -> None:
        if not self._enabled:
            return
        _UPSTREAM_AVAILABLE.labels(namespace=namespace).set(1 if available else 0)

    def record_upstream_process_restart(self, *, namespace: str) -> None:
        if not self._enabled:
            return
        _UPSTREAM_PROCESS_RESTARTS.labels(namespace=namespace).inc()

    def record_upstream_elicitation(self, *, namespace: str, action: str) -> None:
        if not self._enabled:
            return
        _UPSTREAM_ELICITATIONS.labels(namespace=namespace, action=action).inc()

    def record_oauth_client_registration(self, *, outcome: str) -> None:
        if not self._enabled:
            return
        _OAUTH_CLIENT_REGISTRATIONS.labels(outcome=outcome).inc()

    def set_oauth_clients_gauge(self, count: int) -> None:
        if not self._enabled:
            return
        _OAUTH_CLIENTS.set(count)

    def scrape(self) -> tuple[bytes, str]:
        return generate_latest(), CONTENT_TYPE_LATEST


def record_upstream_elicitation(*, namespace: str, action: str) -> None:
    """Increment elicitation counter without an observability handle (proxy path)."""
    _UPSTREAM_ELICITATIONS.labels(namespace=namespace, action=action).inc()


def count_directory_response_issue(field: str, issue: str) -> None:
    """Count a lenient parse of an HTTP directory ``resolve`` response field."""
    _DIRECTORY_RESPONSE_ISSUES.labels(field=field, issue=issue).inc()
