"""Operational RBAC policy loader: config path, live catalog gate, hot-reload."""

from __future__ import annotations

import hashlib
import logging
import threading
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from fnmatch import fnmatch
from pathlib import Path

from keystone_mcp.config import Settings
from keystone_mcp.rbac.catalog import collect_live_tool_names
from keystone_mcp.rbac.catalog_snapshot import (
    EMPTY_CATALOG_SNAPSHOT,
    CatalogSnapshot,
    CatalogSnapshotError,
    load_catalog_snapshot_for_settings,
)
from keystone_mcp.rbac.policy import (
    CatalogValidationResult,
    PolicyContractError,
    RbacPolicy,
    hash_policy_bytes,
    load_policy_file_with_hash,
    log_unreachable_tools,
    parse_policy_yaml,
    validate_policy_against_catalog,
)
from keystone_mcp.rbac.upstream_state import (
    UpstreamCatalogState,
    UpstreamCatalogStateProvider,
    pattern_owner,
)
from keystone_mcp.router.registry import RouterRegistry

logger = logging.getLogger(__name__)


class PolicyLoadError(RuntimeError):
    """Raised when the configured policy cannot be loaded or validated."""


def preflight_rbac_policy_file(settings: Settings) -> None:
    """Refuse startup before listening when the policy file cannot be read or parsed."""
    if not settings.rbac_enabled:
        return
    path_raw = settings.rbac_policy_path.strip()
    if not path_raw:
        return
    path = Path(path_raw)
    try:
        raw = path.read_bytes().decode("utf-8")
        parse_policy_yaml(raw, source_path=path)
    except PolicyContractError as exc:
        raise PolicyLoadError(str(exc)) from exc
    except OSError as exc:
        raise PolicyLoadError(str(exc)) from exc


@dataclass(frozen=True, slots=True)
class PolicyIdentity:
    """Observable identity of the active policy (consumed by the audit trail)."""

    version: str
    content_hash: str
    source_path: Path
    loaded_at: datetime


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """Validated in-memory policy plus audit identity.

    The policy object carries the human-identity and critical-tool patterns, so
    swapping this snapshot on hot-reload refreshes those gates too.
    """

    policy: RbacPolicy
    identity: PolicyIdentity


@dataclass(frozen=True, slots=True)
class PolicyReloadResult:
    """Outcome of a hot-reload attempt."""

    success: bool
    active: PolicySnapshot | None
    error: str | None = None


def assert_live_catalog_validation(
    policy: RbacPolicy,
    live_tool_names: Collection[str],
    *,
    catalog_snapshot: CatalogSnapshot = EMPTY_CATALOG_SNAPSHOT,
    upstream_state: UpstreamCatalogState | None = None,
) -> CatalogValidationResult:
    """Validate policy against the discovered live tool catalog (startup gate).

    Allow-pattern reachability is checked against the live names plus the
    optional catalog snapshot (``active | reserved | wip``). A deployment that
    has not mounted every declared upstream can still load its policy: the
    unmatched live names are not streamed, and those allow rows stay inert
    under ``default_deny``. A pattern that matches nothing anywhere still fails
    (typo, or a name missing from the snapshot) -- except the two cases
    :func:`split_unverified_allow_patterns` carves out as WARNINGs (P06, S4):
    a pattern owned by an upstream namespace that is currently unavailable,
    and ``*`` matching nothing because the whole pattern catalog is empty.

    Tools that no role can reach are logged as a WARNING, never refused.

    Multiplicity is collapsed to a set here on purpose: this gate answers
    coverage, not uniqueness (see
    :func:`keystone_mcp.rbac.catalog.assert_unique_live_published_names`).
    """
    live_set = frozenset(live_tool_names)
    result = validate_policy_against_catalog(
        policy,
        live_set | catalog_snapshot.active,
        reserved_tool_names=catalog_snapshot.reserved,
        wip_tool_names=catalog_snapshot.wip,
    )
    errors, unverified = split_unverified_allow_patterns(
        policy, result.unmatched_allow_patterns, upstream_state
    )
    if errors:
        raise PolicyContractError(
            "unmatched allow patterns (typo or missing catalog/WIP entry): " + ", ".join(errors)
        )
    _log_unverified_allow_patterns(unverified, upstream_state)
    log_unreachable_tools(result)
    return result


def split_unverified_allow_patterns(
    policy: RbacPolicy,
    unmatched: Sequence[str],
    state: UpstreamCatalogState | None,
) -> tuple[tuple[str, ...], dict[str, tuple[str, ...]]]:
    """Split ``"role:pattern"`` unmatched entries into errors and not-yet-verified.

    This is the single place the "unmatched allow pattern" reclassification
    rule lives (do not duplicate it in :func:`log_live_catalog_drift`). Three
    kinds of unmatched entry are downgraded from a hard error to a WARNING:

    - ``*`` can only end up unmatched when the whole pattern catalog is empty
      (see ``validate_policy_against_catalog``): that is an operational fact
      (nothing has been published yet), not a policy typo, so it is always
      logged and dropped, independent of ``state`` (S4 decision). This also
      covers ``keystone-mcp catalog validate``, which has no upstream state
      to pass (``state=None``).
    - any other pattern whose glob head is owned (see
      :func:`~keystone_mcp.rbac.upstream_state.pattern_owner`) by a registered
      namespace that ``state`` marks unavailable: it is checked against the
      live catalog once that namespace comes back up.
    - any other pattern that glob-matches one of ``state.unpublishable``'s
      names: the upstream namespace is reachable, but this one tool's schema
      could not be turned into a published tool (FX-proxy #1, e.g. a
      parameter named ``from``). It is checked again once that tool
      publishes (or dropped from ``unpublishable`` once the upstream stops
      offering it at all -- see ``SurfaceReconciler._apply_namespace_diff``).

    A pattern listed in ``policy.reserved_allow_patterns`` is never
    reclassified this way: it is checked against the catalog snapshot only,
    and upstream availability has no bearing on it. A pattern with no owning
    namespace at all (including a typo in the namespace part, like
    ``dosc_*``) stays a hard error too.

    ``state=None`` means "no upstream state available" (the pre-P06 world,
    and every caller that does not track upstreams): neither reclassification
    above applies, but the ``*``-on-empty-catalog one still does, since it
    needs no upstream state.
    """
    if not unmatched:
        return (), {}
    unmatched_set = set(unmatched)
    errors: list[str] = []
    unverified: dict[str, list[str]] = {}
    star_entries: list[str] = []
    namespaces = state.namespaces if state is not None else frozenset()
    unavailable = state.unavailable if state is not None else frozenset()
    unpublishable = state.unpublishable if state is not None else frozenset()
    for role in policy.roles:
        for pattern in role.allow_patterns:
            entry = f"{role.name}:{pattern}"
            if entry not in unmatched_set:
                continue
            if pattern == "*":
                star_entries.append(entry)
                continue
            if pattern in policy.reserved_allow_patterns:
                errors.append(entry)
                continue
            owner = pattern_owner(pattern, namespaces)
            if owner is not None and owner in unavailable:
                unverified.setdefault(owner, []).append(entry)
            elif owner is not None and any(fnmatch(name, pattern) for name in unpublishable):
                unverified.setdefault(owner, []).append(entry)
            else:
                errors.append(entry)
    if star_entries:
        logger.warning(
            "policy pattern * matched no tools: catalog is empty: %s",
            ", ".join(star_entries),
        )
    return tuple(errors), {ns: tuple(entries) for ns, entries in unverified.items()}


def _log_unverified_allow_patterns(
    unverified: dict[str, tuple[str, ...]],
    state: UpstreamCatalogState | None = None,
) -> None:
    """One WARNING per namespace, naming its unverified entries.

    The wording distinguishes a namespace that is entirely unavailable from
    one that is reachable but has an individual unpublishable tool (``state``
    decides which; a namespace's entries are never a mix of both in
    practice, since discovery for an unavailable namespace never runs far
    enough to mark anything unpublishable this cycle).
    """
    unavailable = state.unavailable if state is not None else frozenset()
    for namespace, entries in sorted(unverified.items()):
        if namespace in unavailable:
            logger.warning(
                "rbac allow patterns not verified: upstream namespace %s is unavailable: %s; "
                "they are checked when it comes up",
                namespace,
                ", ".join(entries),
            )
        else:
            logger.warning(
                "rbac allow patterns not verified: upstream namespace %s has a tool that "
                "could not be published: %s; they are checked once it publishes",
                namespace,
                ", ".join(entries),
            )


def policy_files_content_hashes(settings: Settings) -> tuple[str | None, str | None]:
    """SHA-256 hex digests of policy and catalog-snapshot file bytes (or None)."""
    policy_hash: str | None = None
    policy_path_raw = settings.rbac_policy_path.strip()
    if policy_path_raw:
        policy_path = Path(policy_path_raw)
        if policy_path.is_file():
            policy_hash = hashlib.sha256(policy_path.read_bytes()).hexdigest()

    snapshot_hash: str | None = None
    snapshot_path_raw = settings.rbac_catalog_snapshot_path.strip()
    if snapshot_path_raw:
        snapshot_path = Path(snapshot_path_raw)
        if snapshot_path.is_file():
            snapshot_hash = hashlib.sha256(snapshot_path.read_bytes()).hexdigest()
    return policy_hash, snapshot_hash


def live_catalog_names(
    policy_manager: RbacPolicyManager,
    registry: RouterRegistry,
) -> frozenset[str]:
    names = frozenset(collect_live_tool_names(registry))
    extra = policy_manager._extra_catalog_names
    if extra is None:
        return names
    return names | extra()


def delegation_catalog_names(
    policy_manager: RbacPolicyManager,
    registry: RouterRegistry,
) -> frozenset[str]:
    """Live tool names plus catalog snapshot names used for delegation checks."""
    snapshot = policy_manager.catalog_snapshot()
    return (
        live_catalog_names(policy_manager, registry)
        | snapshot.active
        | snapshot.reserved
        | snapshot.wip
    )


_live_catalog_names = live_catalog_names


def log_live_catalog_drift(
    policy_manager: RbacPolicyManager,
    registry: RouterRegistry,
) -> None:
    """Log allow-pattern drift against the current registry without refusing."""
    policy = policy_manager.active_policy
    if policy is None:
        return
    live_tools = _live_catalog_names(policy_manager, registry)
    snapshot = policy_manager.catalog_snapshot()
    result = validate_policy_against_catalog(
        policy,
        live_tools | snapshot.active,
        reserved_tool_names=snapshot.reserved,
        wip_tool_names=snapshot.wip,
    )
    upstream_state = policy_manager.upstream_catalog_state()
    errors, unverified = split_unverified_allow_patterns(
        policy, result.unmatched_allow_patterns, upstream_state
    )
    if errors:
        logger.error(
            "rbac policy has unmatched allow patterns after catalog change: %s",
            ", ".join(errors),
        )
    _log_unverified_allow_patterns(unverified, upstream_state)
    log_unreachable_tools(result)


class RbacPolicyManager:
    """Versioned policy loader with live-catalog validation and atomic hot-reload.

    Operational reload trigger: ``SIGHUP`` (see ``install_policy_reload_signal``).
    """

    def __init__(
        self,
        settings: Settings,
        *,
        upstream_catalog_state: UpstreamCatalogStateProvider | None = None,
        extra_catalog_names: Callable[[], frozenset[str]] | None = None,
        on_identity: Callable[[PolicyIdentity], None] | None = None,
    ) -> None:
        self._settings = settings
        self._lock = threading.Lock()
        self._snapshot: PolicySnapshot | None = None
        self._upstream_catalog_state_provider = upstream_catalog_state
        self._extra_catalog_names = extra_catalog_names
        self._on_identity = on_identity

    @property
    def snapshot(self) -> PolicySnapshot | None:
        with self._lock:
            return self._snapshot

    @property
    def identity(self) -> PolicyIdentity | None:
        with self._lock:
            return self._snapshot.identity if self._snapshot is not None else None

    @property
    def policy(self) -> RbacPolicy:
        snapshot = self.snapshot
        if snapshot is None:
            raise PolicyLoadError("RBAC policy has not been loaded")
        return snapshot.policy

    @property
    def active_policy(self) -> RbacPolicy | None:
        """The active policy, or None when none has been loaded (never raises)."""
        snapshot = self.snapshot
        return snapshot.policy if snapshot is not None else None

    def policy_path(self) -> Path:
        path = Path(self._settings.rbac_policy_path)
        if not path.is_file():
            raise PolicyLoadError(
                f"KEYSTONE_MCP_RBAC_POLICY_PATH does not exist or is not a file: {path}"
            )
        return path

    def catalog_snapshot(self) -> CatalogSnapshot:
        """Load the configured catalog snapshot (empty when unconfigured)."""
        try:
            return load_catalog_snapshot_for_settings(self._settings)
        except CatalogSnapshotError as exc:
            raise PolicyLoadError(
                f"KEYSTONE_MCP_RBAC_CATALOG_SNAPSHOT could not be loaded: {exc}"
            ) from exc

    def upstream_catalog_state(self) -> UpstreamCatalogState | None:
        """Current upstream namespace/availability snapshot, or None if untracked.

        ``None`` when this manager was built without ``upstream_catalog_state``
        (keeps 0.3.1 behaviour: every unmatched allow pattern is a hard error).
        """
        if self._upstream_catalog_state_provider is None:
            return None
        return self._upstream_catalog_state_provider()

    def load_initial(
        self,
        registry: RouterRegistry,
        *,
        discovery_counts: dict[str, int] | None = None,
    ) -> PolicySnapshot:
        """Load from config, validate against live catalog, activate."""
        snapshot = self._load_and_validate(registry)
        with self._lock:
            self._snapshot = snapshot
        self._emit_identity(snapshot.identity, discovery_counts=discovery_counts)
        return snapshot

    def reload(self, registry: RouterRegistry) -> PolicyReloadResult:
        """Hot-reload: swap on success, keep last valid snapshot on failure."""
        previous = self.snapshot
        last_error: str | None = None
        for _attempt in range(3):
            try:
                candidate = self._load_and_validate(registry)
            except (PolicyLoadError, PolicyContractError, OSError) as exc:
                logger.warning("rbac policy hot-reload rejected: %s", exc)
                return PolicyReloadResult(success=False, active=previous, error=str(exc))

            try:
                path = self.policy_path()
                on_disk_hash = hash_policy_bytes(path.read_bytes())
            except OSError as exc:
                logger.warning("rbac policy hot-reload rejected: %s", exc)
                return PolicyReloadResult(success=False, active=previous, error=str(exc))

            if on_disk_hash != candidate.identity.content_hash:
                last_error = "policy file kept changing during reload"
                continue

            with self._lock:
                self._snapshot = candidate
            self._emit_identity(candidate.identity)
            return PolicyReloadResult(success=True, active=candidate)

        logger.warning("rbac policy hot-reload rejected: %s", last_error)
        return PolicyReloadResult(
            success=False, active=previous, error=last_error or "reload failed"
        )

    def _load_and_validate(self, registry: RouterRegistry) -> PolicySnapshot:
        path = self.policy_path()
        policy, content_hash = load_policy_file_with_hash(path)
        live_tools = _live_catalog_names(self, registry)
        assert_live_catalog_validation(
            policy,
            live_tools,
            catalog_snapshot=self.catalog_snapshot(),
            upstream_state=self.upstream_catalog_state(),
        )
        identity = PolicyIdentity(
            version=policy.version,
            content_hash=content_hash,
            source_path=path,
            loaded_at=datetime.now(UTC),
        )
        return PolicySnapshot(policy=policy, identity=identity)

    def _emit_identity(
        self,
        identity: PolicyIdentity,
        *,
        discovery_counts: dict[str, int] | None = None,
    ) -> None:
        if discovery_counts is None:
            logger.info(
                "rbac policy active version=%s content_hash=%s path=%s",
                identity.version,
                identity.content_hash,
                identity.source_path,
            )
        else:
            logger.info(
                "rbac policy active version=%s content_hash=%s path=%s "
                "upstream_discovery_counts=%s",
                identity.version,
                identity.content_hash,
                identity.source_path,
                discovery_counts,
            )
        observer = self._on_identity
        if observer is None:
            return
        try:
            observer(identity)
        except Exception:
            logger.warning("rbac policy identity observer failed", exc_info=True)
