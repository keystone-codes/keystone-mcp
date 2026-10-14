"""Low-cardinality labels for MCP call_tool Prometheus metrics."""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

from keystone_mcp.identity import resolve_verified_identity
from keystone_mcp.observability.tool_family import tool_family

_NONE_AUTH = "none"
_UNKNOWN = "unknown"
_OTHER = "other"

logger = logging.getLogger(__name__)

# Guards the "limit reached" log line so it is written at most once per
# process lifetime, regardless of how many ClientIdLabelLimiter instances
# (one per RbacMetrics / test) independently fold a client id into "other".
_limit_log_lock = threading.Lock()
_limit_logged = False


def _log_limit_reached_once(limit: int) -> None:
    global _limit_logged
    with _limit_log_lock:
        if _limit_logged:
            return
        _limit_logged = True
    logger.info(
        "metrics: oauth_client_id label limit %d reached; further clients are reported as 'other'",
        limit,
    )


class ClientIdLabelLimiter:
    """Caps the number of distinct `oauth_client_id` label values per process.

    The first `limit` distinct client ids seen by this instance keep their
    own label value for the lifetime of the process; every client id seen
    after that is reported as "other" so an unbounded stream of OAuth client
    registrations cannot create an unbounded number of Prometheus time
    series. `none` and `unknown` are passed through unchanged and never
    occupy a slot.
    """

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._lock = threading.Lock()
        self._seen: set[str] = set()

    def label(self, client_id: str) -> str:
        if client_id in (_NONE_AUTH, _UNKNOWN):
            return client_id
        with self._lock:
            if client_id in self._seen:
                return client_id
            if len(self._seen) < self._limit:
                self._seen.add(client_id)
                return client_id
        _log_limit_reached_once(self._limit)
        return _OTHER


@dataclass(frozen=True, slots=True)
class ToolCallMetricLabels:
    tool_family: str
    namespace: str
    tool: str
    auth_method: str
    oauth_client_id: str

    def as_dict(self) -> dict[str, str]:
        return {
            "tool_family": self.tool_family,
            "namespace": self.namespace,
            "tool": self.tool,
            "auth_method": self.auth_method,
            "oauth_client_id": self.oauth_client_id,
        }


def resolve_tool_call_metric_labels(
    tool_name: str,
    *,
    tool_name_mode: str,
    known: bool = True,
) -> ToolCallMetricLabels:
    """Build Prometheus labels for a call_tool attempt or invocation."""
    if not known:
        family = "unknown"
        tool_label = "unknown"
        namespace = "unknown"
    else:
        family = tool_family(tool_name)
        namespace = family
        if tool_name_mode == "coarse":
            tool_label = family
        else:
            tool_label = tool_name.strip() if tool_name else "_"

    identity = resolve_verified_identity()
    if identity is None:
        return ToolCallMetricLabels(
            tool_family=family,
            namespace=namespace,
            tool=tool_label,
            auth_method=_NONE_AUTH,
            oauth_client_id=_NONE_AUTH,
        )

    claims = identity.claims or {}
    auth_method = str(claims.get("auth_method") or _UNKNOWN).strip() or _UNKNOWN
    oauth_client_id = _resolve_oauth_client_id()
    return ToolCallMetricLabels(
        tool_family=family,
        namespace=namespace,
        tool=tool_label,
        auth_method=auth_method,
        oauth_client_id=oauth_client_id,
    )


def _resolve_oauth_client_id() -> str:
    try:
        from fastmcp.server.dependencies import get_access_token
    except Exception:
        return _UNKNOWN
    token = get_access_token()
    if token is None:
        return _UNKNOWN
    client_id = getattr(token, "client_id", None)
    if client_id is None and token.claims:
        client_id = token.claims.get("client_id")
    if not client_id:
        return _UNKNOWN
    return str(client_id)
