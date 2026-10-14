"""Periodic reconciliation of RBAC policy files and upstream tool catalogs."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from keystone_mcp.adapters.base import Pattern
from keystone_mcp.config import Settings, _upstream_security_policy
from keystone_mcp.observability.metrics import record_upstream_item_rejected
from keystone_mcp.rbac.loader import (
    log_live_catalog_drift,
    policy_files_content_hashes,
)
from keystone_mcp.router.catalog_fingerprint import tool_fingerprint
from keystone_mcp.router.stdio_process import UpstreamProcessUnavailableError
from keystone_mcp.router.upstream import (
    UpstreamListToolsError,
    UpstreamToolSpec,
    build_upstream_prompt_specs,
    build_upstream_resource_specs,
    build_upstream_template_specs,
    build_upstream_tool_specs,
)
from keystone_mcp.upstream_registry.load import load_upstream_registry_file
from keystone_mcp.upstream_registry.reload import (
    diff_upstream_registry,
    enabled_upstream_map,
    upstream_registry_file_hash,
    upstream_registry_info_hash,
)

if TYPE_CHECKING:
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.rbac.loader import RbacPolicyManager
    from keystone_mcp.rbac.policy_revision import PolicyRevisionWatcher
    from keystone_mcp.router.registry import RouterRegistry
    from keystone_mcp.router.upstream import UpstreamRegistry
    from keystone_mcp.surface.client_sessions import ClientSessionRegistry
    from keystone_mcp.user_directory.revision import RevisionReader

logger = logging.getLogger(__name__)

_JITTER_MAX_SECONDS = 15.0
_RESTART_DELAY_MIN_SECONDS = 5.0
_RESTART_DELAY_MAX_SECONDS = 300.0
_REFRESH_CONCURRENCY = 16
_REFRESH_BUDGET_MULTIPLIER = 5


@dataclass
class SurfaceReconciler:
    """Background tick: refresh upstream tools, then policy files when bytes change."""

    settings: Settings
    registry: RouterRegistry
    upstreams: UpstreamRegistry
    policy_manager: RbacPolicyManager | None
    observability: RbacObservability | None
    revision_reader: RevisionReader | None = None
    policy_revision_watcher: PolicyRevisionWatcher | None = None
    client_sessions: ClientSessionRegistry | None = None

    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _policy_reload_event: asyncio.Event = field(
        default_factory=asyncio.Event, init=False, repr=False
    )
    _registry_reload_event: asyncio.Event = field(
        default_factory=asyncio.Event, init=False, repr=False
    )
    _registry_hash: str | None = field(default=None, init=False, repr=False)
    _registry_rejected_hash: str | None = field(default=None, init=False, repr=False)
    _task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)
    _loop: asyncio.AbstractEventLoop | None = field(default=None, init=False, repr=False)

    _policy_hash: str | None = field(default=None, init=False, repr=False)
    _snapshot_hash: str | None = field(default=None, init=False, repr=False)
    _namespace_fingerprints: dict[str, dict[str, str]] = field(
        default_factory=dict, init=False, repr=False
    )
    _namespace_prompt_fingerprints: dict[str, dict[str, str]] = field(
        default_factory=dict, init=False, repr=False
    )
    _namespace_resource_fingerprints: dict[str, dict[str, str]] = field(
        default_factory=dict, init=False, repr=False
    )
    _namespace_template_fingerprints: dict[str, dict[str, str]] = field(
        default_factory=dict, init=False, repr=False
    )
    _empty_list_streak: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _empty_prompt_list_streak: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _empty_resource_list_streak: dict[str, int] = field(
        default_factory=dict, init=False, repr=False
    )
    _last_users_revision: int | None = field(default=None, init=False, repr=False)
    _namespace_refresh_tasks: dict[str, asyncio.Task[None]] = field(
        default_factory=dict, init=False, repr=False
    )

    def seed_snapshots(self) -> None:
        """Capture post-bootstrap state so the first tick is a no-op when unchanged."""
        self._policy_hash, self._snapshot_hash = policy_files_content_hashes(self.settings)
        self._registry_hash = upstream_registry_file_hash(self.settings)
        self._registry_rejected_hash = None
        if self.observability is not None:
            self.observability.set_upstream_registry_identity(
                content_hash=upstream_registry_info_hash(self._registry_hash)
            )
        self._namespace_fingerprints = {
            cfg.namespace: self._fingerprint_namespace(cfg.namespace)
            for cfg in self.upstreams._upstreams
        }
        self._namespace_prompt_fingerprints = {
            cfg.namespace: self._fingerprint_prompts_namespace(cfg.namespace)
            for cfg in self.upstreams._upstreams
        }
        self._namespace_resource_fingerprints = {
            cfg.namespace: self._fingerprint_resources_namespace(cfg.namespace)
            for cfg in self.upstreams._upstreams
        }
        self._namespace_template_fingerprints = {
            cfg.namespace: self._fingerprint_templates_namespace(cfg.namespace)
            for cfg in self.upstreams._upstreams
        }

    def request_policy_reload(self) -> bool:
        """Thread-safe hook for SIGHUP (sets an event read by the reconciler loop).

        Returns ``True`` when the background task is running and will pick up
        the event on its next wake-up. Returns ``False`` (and logs a WARNING)
        when the task is not running, so the caller can fall back to an
        inline reload instead of silently doing nothing.
        """
        if self._loop is None or self._task is None or self._task.done():
            logger.warning(
                "SIGHUP: surface reconciler is not running; reloading RBAC policy inline"
            )
            return False
        self._loop.call_soon_threadsafe(self._policy_reload_event.set)
        return True

    def request_registry_reload(self) -> bool:
        if self._loop is None:
            logger.warning(
                "SIGHUP: upstream registry reload needs the surface reconciler; "
                "set KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS > 0"
            )
            return False
        self._loop.call_soon_threadsafe(self._registry_reload_event.set)
        return True

    async def reload_registry_once(self) -> None:
        """Apply one forced upstream registry reload (SIGHUP without a refresh loop)."""
        async with self._lock:
            await self._maybe_reload_registry(force=True)

    def upstream_registry_hash(self) -> str | None:
        return upstream_registry_info_hash(self._registry_hash)

    async def start(self) -> None:
        interval = self.settings.refresh_interval_seconds
        self.upstreams.set_namespace_up_hook(self.refresh_namespace_soon)
        for cfg in self.upstreams._upstreams:
            if cfg.transport != "stdio":
                continue
            conn = self.upstreams.connection(cfg.namespace)
            from keystone_mcp.router.upstream_connection import StdioUpstreamConnection

            if not isinstance(conn, StdioUpstreamConnection):
                continue
            status = self.upstreams._status.get(cfg.namespace)
            if conn.process.state == "running" and (status is None or not status.catalog_known):
                self.refresh_namespace_soon(cfg.namespace)
        self._loop = asyncio.get_running_loop()
        self.seed_snapshots()
        if interval <= 0:
            return
        self._task = asyncio.create_task(self._supervise(interval), name="surface-reconciler")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def tick(self) -> None:
        """Run one reconciliation pass (used by the background loop and tests)."""
        if self._lock.locked():
            return
        async with self._lock:
            await self._tick_locked()

    async def _supervise(self, interval: int) -> None:
        """Keep ``_run_loop`` alive: restart it with backoff if it ever raises."""
        delay = _RESTART_DELAY_MIN_SECONDS
        while True:
            try:
                await self._run_loop(interval)
                return  # _run_loop never returns normally; stop if it does
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("surface reconciler loop crashed; restarting in %.0fs", delay)
                await asyncio.sleep(delay)
                delay = min(delay * 2, _RESTART_DELAY_MAX_SECONDS)

    async def _run_loop(self, interval: int) -> None:
        try:
            while True:
                jitter = random.uniform(0, min(_JITTER_MAX_SECONDS, interval / 4))
                wait_seconds = interval + jitter
                try:
                    await self._wait_for_reload_or_timeout(wait_seconds)
                except asyncio.TimeoutError:
                    pass
                # Do not clear the event here: ``_tick_locked`` reads
                # ``is_set()`` first and clears it itself (read-then-clear).
                # Clearing it here, before ``tick()`` runs, used to make
                # ``force_policy`` always False -- a SIGHUP woke this loop but
                # never forced a reload of an otherwise-unchanged policy file.
                try:
                    await self.tick()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception(
                        "surface reconciler tick failed; next attempt in %ss", interval
                    )
        except asyncio.CancelledError:
            raise

    async def _wait_for_reload_or_timeout(self, timeout: float) -> None:
        if self._policy_reload_event.is_set() or self._registry_reload_event.is_set():
            return
        policy_wait = asyncio.create_task(self._policy_reload_event.wait())
        registry_wait = asyncio.create_task(self._registry_reload_event.wait())
        try:
            done, pending = await asyncio.wait(
                {policy_wait, registry_wait},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                raise asyncio.TimeoutError
        finally:
            for task in (policy_wait, registry_wait):
                if not task.done():
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await task

    async def _tick_locked(self) -> None:
        force_policy = self._policy_reload_event.is_set()
        if force_policy:
            self._policy_reload_event.clear()
        force_registry = self._registry_reload_event.is_set()
        if force_registry:
            self._registry_reload_event.clear()

        registry_tools_changed = False
        registry_prompts_changed = False
        registry_resources_changed = False
        try:
            (
                registry_tools_changed,
                registry_prompts_changed,
                registry_resources_changed,
            ) = await self._maybe_reload_registry(force=force_registry)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("surface reconciler step %s failed", "maybe_reload_registry")

        if self.policy_revision_watcher is not None:
            try:
                await self.policy_revision_watcher.ensure_current(force=True)
            except Exception:
                logger.exception("surface reconciler step %s failed", "policy_revision")

        catalog_changed = False
        prompts_catalog_changed = False
        resources_catalog_changed = False
        try:
            (
                catalog_changed,
                prompts_catalog_changed,
                resources_catalog_changed,
            ) = await self._refresh_catalogs()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("surface reconciler step %s failed", "refresh_catalogs")

        policy_reloaded = False
        try:
            policy_reloaded = await self._maybe_reload_policy(force=force_policy)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("surface reconciler step %s failed", "maybe_reload_policy")

        users_revision_changed = False
        try:
            users_revision_changed = await self._observe_users_revision()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("surface reconciler step %s failed", "observe_users_revision")

        await self._broadcast_catalog_changes(
            catalog_changed=catalog_changed or registry_tools_changed,
            prompts_catalog_changed=prompts_catalog_changed or registry_prompts_changed,
            resources_catalog_changed=resources_catalog_changed or registry_resources_changed,
            policy_reloaded=policy_reloaded,
            users_revision_changed=users_revision_changed,
        )

    def refresh_namespace_soon(self, namespace: str) -> None:
        """Schedule a single-namespace catalog refresh (stdio process came up)."""
        existing = self._namespace_refresh_tasks.get(namespace)
        if existing is not None and not existing.done():
            return
        self._namespace_refresh_tasks[namespace] = asyncio.create_task(
            self._refresh_namespace_soon(namespace),
            name=f"surface-refresh-{namespace}",
        )

    async def _refresh_namespace_soon(self, namespace: str) -> None:
        from keystone_mcp.router.upstream import UpstreamConfig

        try:
            async with self._lock:
                cfg = next(
                    (c for c in self.upstreams._upstreams if c.namespace == namespace),
                    None,
                )
                if cfg is None:
                    return
                assert isinstance(cfg, UpstreamConfig)
                budget = self._refresh_budget_seconds(cfg)
                try:
                    (
                        catalog_changed,
                        prompts_catalog_changed,
                        resources_catalog_changed,
                    ) = await asyncio.wait_for(
                        self._refresh_namespace(cfg),
                        timeout=budget,
                    )
                except asyncio.TimeoutError:
                    self.upstreams.mark_unavailable(
                        namespace,
                        f"refresh timed out after {budget:g}s",
                    )
                    return
                await self._broadcast_catalog_changes(
                    catalog_changed=catalog_changed,
                    prompts_catalog_changed=prompts_catalog_changed,
                    resources_catalog_changed=resources_catalog_changed,
                    policy_reloaded=False,
                    users_revision_changed=False,
                )
        finally:
            self._namespace_refresh_tasks.pop(namespace, None)

    async def _broadcast_catalog_changes(
        self,
        *,
        catalog_changed: bool,
        prompts_catalog_changed: bool,
        resources_catalog_changed: bool,
        policy_reloaded: bool,
        users_revision_changed: bool,
    ) -> None:
        kinds: set[str] = set()
        if catalog_changed or policy_reloaded or users_revision_changed:
            kinds.add("tools")
        if prompts_catalog_changed:
            kinds.add("prompts")
        if resources_catalog_changed:
            kinds.add("resources")
        if kinds and self.client_sessions is not None:
            reached = await self.client_sessions.broadcast_list_changed(kinds)
            logger.info(
                "sent list_changed kinds=%s to %d session(s) (catalog=%s prompts=%s policy=%s users=%s)",
                sorted(kinds),
                reached,
                catalog_changed,
                prompts_catalog_changed,
                policy_reloaded,
                users_revision_changed,
            )
            if self.observability is not None:
                for kind in kinds:
                    self.observability.record_list_changed(kind=kind, sessions=reached)

    def _refresh_budget_seconds(self, cfg: object) -> float:
        from keystone_mcp.router.upstream import UpstreamConfig

        assert isinstance(cfg, UpstreamConfig)
        discovery_timeout = (
            cfg.discovery_timeout_seconds
            if cfg.discovery_timeout_seconds is not None
            else self.upstreams.discovery_timeout_seconds
        )
        return _REFRESH_BUDGET_MULTIPLIER * discovery_timeout

    async def _refresh_catalogs(self) -> tuple[bool, bool, bool]:
        """Refresh every namespace; return (tools, prompts, resources) changed flags."""
        if not self.upstreams._upstreams:
            return False, False, False

        semaphore = asyncio.Semaphore(_REFRESH_CONCURRENCY)

        async def refresh_one(cfg: object) -> tuple[bool, bool, bool]:
            from keystone_mcp.router.upstream import UpstreamConfig

            assert isinstance(cfg, UpstreamConfig)
            async with semaphore:
                budget = self._refresh_budget_seconds(cfg)
                try:
                    return await asyncio.wait_for(
                        self._refresh_namespace(cfg),
                        timeout=budget,
                    )
                except asyncio.TimeoutError:
                    self.upstreams.mark_unavailable(
                        cfg.namespace,
                        f"refresh timed out after {budget:g}s",
                    )
                    logger.warning(
                        "upstream refresh timed out namespace=%s after %gs; "
                        "keeping previous catalog",
                        cfg.namespace,
                        budget,
                    )
                    self._record_catalog_outcome(held=True)
                    return False, False, False
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self.upstreams.mark_unavailable(cfg.namespace, f"{type(exc).__name__}: {exc}")
                    logger.exception(
                        "upstream refresh crashed namespace=%s; keeping previous catalog",
                        cfg.namespace,
                    )
                    self._record_catalog_outcome(held=True)
                    return False, False, False

        results = await asyncio.gather(*(refresh_one(cfg) for cfg in self.upstreams._upstreams))
        tools_changed = False
        prompts_changed = False
        resources_changed = False
        for tc, pc, rc in results:
            tools_changed = tools_changed or tc
            prompts_changed = prompts_changed or pc
            resources_changed = resources_changed or rc
        return tools_changed, prompts_changed, resources_changed

    async def _refresh_namespace(self, cfg: object) -> tuple[bool, bool, bool]:
        """Refresh one namespace's tool, prompt and resource catalogs."""
        from keystone_mcp.router.upstream import UpstreamConfig

        assert isinstance(cfg, UpstreamConfig)
        namespace = cfg.namespace
        previous = self._namespace_fingerprints.get(namespace, {})

        try:
            catalog = await self.upstreams.read_catalog(cfg)
        except UpstreamProcessUnavailableError as exc:
            self.upstreams.mark_unavailable(namespace, str(exc))
            logger.warning(
                "upstream refresh failed namespace=%s: %s; keeping previous catalog",
                namespace,
                exc,
            )
            self._record_catalog_outcome(held=True)
            return False, False, False
        except UpstreamListToolsError as exc:
            self.upstreams.mark_unavailable(namespace, str(exc))
            logger.warning(
                "upstream refresh failed namespace=%s: %s; keeping previous catalog",
                namespace,
                exc,
            )
            self._record_catalog_outcome(held=True)
            return False, False, False

        tools = catalog.tools
        prompts_raw = catalog.prompts
        resources_raw = catalog.resources
        templates_raw = catalog.templates

        became_available = self.upstreams.mark_available(namespace)
        specs, schema_rejected = build_upstream_tool_specs(
            cfg,
            tools,
            schema_patches=self.upstreams.schema_patches,
            max_schema_bytes=self.upstreams.upstream_max_schema_bytes,
        )
        for route_name in schema_rejected:
            self.upstreams.mark_unpublishable(namespace, route_name)
        desired = {name: spec.fingerprint for name, spec in specs.items()}

        if not desired and previous:
            streak = self._empty_list_streak.get(namespace, 0) + 1
            self._empty_list_streak[namespace] = streak
            if streak < 2:
                logger.warning(
                    "upstream refresh namespace=%s returned zero tools; "
                    "holding previous catalog (streak=%d)",
                    namespace,
                    streak,
                )
                self._record_catalog_outcome(held=True)
                self._maybe_log_drift(became_available)
                prompts_changed = self._refresh_prompts_for_namespace_safe(cfg, prompts_raw)
                resources_changed = self._refresh_resources_for_namespace_safe(
                    cfg, resources_raw, templates_raw
                )
                return False, prompts_changed, resources_changed
            logger.warning(
                "upstream refresh namespace=%s empty twice; removing proxy tools",
                namespace,
            )
        elif desired:
            self._empty_list_streak[namespace] = 0

        tools_changed = False
        if desired == previous:
            self._record_catalog_outcome(unchanged=True)
            self._maybe_log_drift(became_available)
        else:
            added, removed, updated, skipped = self._apply_namespace_diff(
                cfg, specs, previous, desired
            )
            # Do not cache a fingerprint for a route that was skipped (an
            # unpublishable schema) or refused (a published-name collision, P09):
            # if we did, the next tick would see its fingerprint already matches
            # "previous" and never retry it. When the route was already
            # registered under an older, different spec (an update attempt that
            # failed), keep that *old* fingerprint instead of dropping the key
            # outright -- the old route is still live in both the registry and
            # FastMCP (add_route is atomic), and dropping the key would also
            # drop it out of "previous" for the removal diff above, orphaning it
            # forever once the upstream really does stop offering it.
            new_fingerprints = dict(desired)
            for route_name in skipped:
                if route_name in previous:
                    new_fingerprints[route_name] = previous[route_name]
                else:
                    new_fingerprints.pop(route_name, None)
            self._namespace_fingerprints[namespace] = new_fingerprints
            if added or removed or updated:
                logger.info(
                    "upstream catalog refreshed namespace=%s added=%d removed=%d updated=%d",
                    namespace,
                    added,
                    removed,
                    updated,
                )
                self._record_catalog_outcome(applied=True, added=added, removed=removed)
                tools_changed = True
            else:
                self._record_catalog_outcome(unchanged=True)
            self._maybe_log_drift(became_available, added=added, removed=removed, updated=updated)

        prompts_changed = self._refresh_prompts_for_namespace_safe(cfg, prompts_raw)
        resources_changed = self._refresh_resources_for_namespace_safe(
            cfg, resources_raw, templates_raw
        )
        return tools_changed, prompts_changed, resources_changed

    def _refresh_prompts_for_namespace_safe(self, cfg: object, prompts_raw: list | None) -> bool:
        from keystone_mcp.router.upstream import UpstreamConfig

        assert isinstance(cfg, UpstreamConfig)
        try:
            return self._refresh_prompts_for_namespace(cfg, prompts_raw)
        except Exception:
            logger.exception(
                "upstream prompts refresh crashed namespace=%s; keeping previous prompts",
                cfg.namespace,
            )
            return False

    def _refresh_resources_for_namespace_safe(
        self, cfg: object, resources_raw: list | None, templates_raw: list | None
    ) -> bool:
        from keystone_mcp.router.upstream import UpstreamConfig

        assert isinstance(cfg, UpstreamConfig)
        try:
            return self._refresh_resources_for_namespace(cfg, resources_raw, templates_raw)
        except Exception:
            logger.exception(
                "upstream resources refresh crashed namespace=%s; keeping previous resources",
                cfg.namespace,
            )
            return False

    def _maybe_log_drift(
        self,
        became_available: bool,
        *,
        added: int = 0,
        removed: int = 0,
        updated: int = 0,
    ) -> None:
        """Re-check RBAC allow-pattern coverage, at most once per namespace tick.

        Runs when the catalog actually changed (as before P06) or when the
        namespace just transitioned from unavailable to available -- even
        with an empty or unchanged tool list, since that is exactly the
        namespace whose allow patterns were left "not verified" at load time
        (P06) and are never otherwise re-checked.
        """
        if self.policy_manager is None:
            return
        if became_available or added or removed or updated:
            log_live_catalog_drift(self.policy_manager, self.registry)

    def _apply_namespace_diff(
        self,
        cfg: object,
        specs: dict[str, UpstreamToolSpec],
        previous: dict[str, str],
        desired: dict[str, str],
    ) -> tuple[int, int, int, frozenset[str]]:
        """Apply one namespace's diff; return ``(added, removed, updated, skipped)``.

        ``skipped`` is every ``route_name`` that could not be registered this
        tick -- either ``add_route`` raised (an unpublishable schema, e.g. a
        parameter named ``from``) or its published name collides with
        another route (P09). The caller (:meth:`_refresh_namespace`) must not
        cache a fingerprint for these: see its docstring for why.

        ``add_route`` is atomic (see ``RouterRegistry.add_route``): on
        failure it has written nothing, so a route that was already
        registered under ``route_name`` -- this is an *update* attempt, not a
        first registration -- is untouched, in both the registry and FastMCP.
        Unlike the pre-atomicity code, this method therefore must not call
        ``registry.remove_route`` on failure: there is nothing to roll back,
        and doing so anyway would delete the still-valid old entry.
        """
        from keystone_mcp.router.upstream import UpstreamConfig

        assert isinstance(cfg, UpstreamConfig)
        namespace = cfg.namespace
        sub = self.upstreams._sub_servers[namespace]
        adapter = self.upstreams._adapters[namespace]

        added = removed = updated = 0
        skipped: set[str] = set()
        prev_names = set(previous)
        new_names = set(desired)

        for route_name in sorted(prev_names - new_names):
            if self._remove_proxy_route(namespace, route_name):
                removed += 1

        for route_name in sorted(new_names):
            spec = specs[route_name]
            route_key = f"{namespace}:{route_name}"
            published = f"{namespace}_{route_name}"

            if route_name in prev_names and previous.get(route_name) == spec.fingerprint:
                continue

            owner_key = self.registry.owner_of_published_name(published)
            if owner_key is not None and owner_key != route_key:
                logger.error(
                    "upstream refresh refused namespace=%s route=%s: "
                    "published name %s already owned by %s",
                    namespace,
                    route_name,
                    published,
                    owner_key,
                )
                record_upstream_item_rejected(
                    namespace=namespace, kind="tool", reason="name_collision"
                )
                skipped.add(route_name)
                continue

            try:
                self.registry.add_route(
                    spec.route_name,
                    adapter,
                    pattern=Pattern.SYNC,
                    params=spec.params,
                    description=spec.description,
                    mode=cfg.route_mode,
                    upstream_tool=spec.upstream_tool,
                    namespace=namespace,
                    config_mode="PROXY",
                    tags={namespace},
                    meta={"upstream": cfg.name, "namespace": namespace},
                    mcp=sub,
                    input_schema=spec.input_schema,
                    output_schema=spec.output_schema,
                    title=spec.title,
                    annotations=spec.annotations,
                )
            except Exception as exc:
                logger.error(
                    "upstream tool skipped namespace=%s tool=%s: %s",
                    namespace,
                    spec.upstream_tool,
                    exc,
                )
                record_upstream_item_rejected(
                    namespace=namespace, kind="tool", reason="unpublishable_schema"
                )
                skipped.add(route_name)
                self.upstreams.mark_unpublishable(namespace, route_name)
                continue

            self.upstreams.clear_unpublishable(namespace, route_name)
            if route_name in prev_names:
                updated += 1
            else:
                added += 1

        # A tool previously marked unpublishable that the upstream no longer
        # even offers (not in new_names) is not "fixed" -- it is gone. Drop
        # the stale marker so it cannot keep excusing an unrelated typo in a
        # future policy pattern that happens to glob-match its old name.
        stale_unpublishable = set(self.upstreams._unpublishable.get(namespace, ())) - new_names
        for route_name in stale_unpublishable:
            self.upstreams.clear_unpublishable(namespace, route_name)

        return added, removed, updated, frozenset(skipped)

    def _remove_proxy_route(self, namespace: str, route_name: str) -> bool:
        route_key = f"{namespace}:{route_name}"
        route = self.registry.routes.get(route_key)
        if route is None or route.config_mode != "PROXY":
            return False
        sub = self.upstreams._sub_servers.get(namespace)
        if sub is None:
            return False
        try:
            sub.local_provider.remove_tool(route_name)
        except KeyError:
            logger.warning(
                "upstream refresh namespace=%s route=%s missing on sub-server; registry entry kept",
                namespace,
                route_name,
            )
            return False
        self.registry.remove_route(route_key)
        return True

    def _fingerprint_prompts_namespace(self, namespace: str) -> dict[str, str]:
        return {
            name: spec.fingerprint
            for name, spec in self.upstreams.content.prompts(namespace).items()
        }

    def _refresh_prompts_for_namespace(self, cfg: object, prompts_raw: list | None) -> bool:
        from keystone_mcp.router.upstream import UpstreamConfig

        assert isinstance(cfg, UpstreamConfig)
        if prompts_raw is None:
            return False
        namespace = cfg.namespace
        previous = self._namespace_prompt_fingerprints.get(namespace, {})
        prompt_specs = build_upstream_prompt_specs(cfg, prompts_raw)
        desired = {name: spec.fingerprint for name, spec in prompt_specs.items()}

        if not desired and previous:
            streak = self._empty_prompt_list_streak.get(namespace, 0) + 1
            self._empty_prompt_list_streak[namespace] = streak
            if streak < 2:
                logger.warning(
                    "upstream refresh namespace=%s returned zero prompts; "
                    "holding previous prompts (streak=%d)",
                    namespace,
                    streak,
                )
                return False
            logger.warning(
                "upstream refresh namespace=%s empty prompts twice; removing proxy prompts",
                namespace,
            )
        elif desired:
            self._empty_prompt_list_streak[namespace] = 0

        if desired == previous:
            return False

        raw_by_name = {p.name: p for p in prompts_raw}
        changed = self.upstreams._apply_prompt_specs(cfg, prompt_specs, raw_by_name)
        self._namespace_prompt_fingerprints[namespace] = dict(desired)
        return changed

    def _fingerprint_resources_namespace(self, namespace: str) -> dict[str, str]:
        return {
            uri: spec.fingerprint
            for uri, spec in self.upstreams.content.resources(namespace).items()
        }

    def _fingerprint_templates_namespace(self, namespace: str) -> dict[str, str]:
        return {
            uri_template: spec.fingerprint
            for uri_template, spec in self.upstreams.content.templates(namespace).items()
        }

    def _refresh_resources_for_namespace(
        self, cfg: object, resources_raw: list | None, templates_raw: list | None
    ) -> bool:
        from keystone_mcp.router.upstream import UpstreamConfig

        assert isinstance(cfg, UpstreamConfig)
        if resources_raw is None or templates_raw is None:
            return False
        namespace = cfg.namespace
        self.upstreams.maybe_warn_unfiltered_resources(cfg, resources_raw, templates_raw)
        previous_res = self._namespace_resource_fingerprints.get(namespace, {})
        previous_tpl = self._namespace_template_fingerprints.get(namespace, {})
        resource_specs = build_upstream_resource_specs(cfg, resources_raw)
        template_specs = build_upstream_template_specs(cfg, templates_raw)
        desired_res = {uri: spec.fingerprint for uri, spec in resource_specs.items()}
        desired_tpl = {ut: spec.fingerprint for ut, spec in template_specs.items()}

        if not desired_res and not desired_tpl and (previous_res or previous_tpl):
            streak = self._empty_resource_list_streak.get(namespace, 0) + 1
            self._empty_resource_list_streak[namespace] = streak
            if streak < 2:
                logger.warning(
                    "upstream refresh namespace=%s returned zero resources; "
                    "holding previous resources (streak=%d)",
                    namespace,
                    streak,
                )
                return False
            logger.warning(
                "upstream refresh namespace=%s empty resources twice; removing proxy resources",
                namespace,
            )
        elif desired_res or desired_tpl:
            self._empty_resource_list_streak[namespace] = 0

        if desired_res == previous_res and desired_tpl == previous_tpl:
            return False

        raw_resources = {str(r.uri): r for r in resources_raw}
        raw_templates = {t.uri_template: t for t in templates_raw}
        changed = self.upstreams._apply_resource_specs(
            cfg,
            resource_specs,
            template_specs,
            raw_resources,
            raw_templates,
        )
        self._namespace_resource_fingerprints[namespace] = self._fingerprint_resources_namespace(
            namespace
        )
        self._namespace_template_fingerprints[namespace] = self._fingerprint_templates_namespace(
            namespace
        )
        return changed

    def _fingerprint_namespace(self, namespace: str) -> dict[str, str]:
        fingerprints: dict[str, str] = {}
        for route_key, route in self.registry.routes.items():
            if route.namespace != namespace or route.config_mode != "PROXY" or route.mode != "live":
                continue
            if route.upstream_tool is None:
                continue
            fingerprints[route.name] = tool_fingerprint(
                route_name=route.name,
                upstream_tool=route.upstream_tool,
                description=route.description,
                params=route.params,
                input_schema=route.input_schema,
                output_schema=route.output_schema,
                title=route.title,
                annotations=route.annotations,
            )
        return fingerprints

    async def _maybe_reload_registry(self, *, force: bool) -> tuple[bool, bool, bool]:
        """Reload the upstream registry file when it changes (or ``force``)."""
        from pathlib import Path

        path_raw = self.settings.upstreams_path.strip()
        if not path_raw:
            if force:
                logger.info(
                    "SIGHUP: the upstream registry comes from KEYSTONE_MCP_UPSTREAMS and "
                    "cannot be reloaded; use KEYSTONE_MCP_UPSTREAMS_PATH"
                )
                if self.observability is not None:
                    self.observability.record_upstream_registry_reload(outcome="unchanged")
            return False, False, False

        current_hash = upstream_registry_file_hash(self.settings)
        if current_hash is None:
            return False, False, False

        unchanged = current_hash == self._registry_hash
        if unchanged and not force:
            return False, False, False

        if (
            not force
            and current_hash == self._registry_rejected_hash
            and current_hash != self._registry_hash
        ):
            return False, False, False

        registry_path = Path(path_raw)
        policy = _upstream_security_policy(self.settings)
        try:
            loaded = await asyncio.to_thread(
                load_upstream_registry_file,
                registry_path,
                policy=policy,
                check_environment=True,
            )
        except ValueError as exc:
            if current_hash != self._registry_rejected_hash:
                logger.warning("upstream registry reload rejected: %s", exc)
            self._registry_rejected_hash = current_hash
            if self.observability is not None:
                self.observability.record_upstream_registry_reload(outcome="rejected")
            return False, False, False

        previous = self.upstreams.applied_entry_configs()
        desired = enabled_upstream_map(loaded)
        diff = diff_upstream_registry(
            previous,
            desired,
            force_secrets=force,
            applied_secret_fingerprints=self.upstreams.applied_secret_fingerprints(),
        )
        if not diff.added and not diff.removed and not diff.changed:
            if force:
                if self.observability is not None:
                    self.observability.record_upstream_registry_reload(outcome="unchanged")
            return False, False, False

        tools_changed = bool(diff.added or diff.removed or diff.changed)
        prompts_changed = tools_changed
        resources_changed = tools_changed

        for namespace in diff.removed:
            await self.upstreams.remove_upstream(namespace)
            self._drop_namespace_snapshots(namespace)

        for namespace in diff.changed:
            await self.upstreams.remove_upstream(namespace)
            self._drop_namespace_snapshots(namespace)

        for namespace in (*diff.added, *diff.changed):
            entry = desired[namespace]
            try:
                self.upstreams.register_config(entry)
            except (ValueError, Exception) as exc:
                logger.warning(
                    "upstream registry entry failed namespace=%s: %s",
                    namespace,
                    exc,
                )
                continue
            try:
                await self.upstreams.activate_upstream(namespace)
            except Exception as exc:
                logger.warning(
                    "upstream registry activation failed namespace=%s: %s",
                    namespace,
                    exc,
                )
                self.upstreams.mark_unavailable(namespace, str(exc))
                continue
            tc, pc, rc = await self._refresh_namespace(
                next(c for c in self.upstreams._upstreams if c.namespace == namespace)
            )
            tools_changed = tools_changed or tc
            prompts_changed = prompts_changed or pc
            resources_changed = resources_changed or rc
            self._namespace_fingerprints[namespace] = self._fingerprint_namespace(namespace)
            self._namespace_prompt_fingerprints[namespace] = self._fingerprint_prompts_namespace(
                namespace
            )
            self._namespace_resource_fingerprints[namespace] = self._fingerprint_resources_namespace(
                namespace
            )
            self._namespace_template_fingerprints[namespace] = self._fingerprint_templates_namespace(
                namespace
            )

        self._registry_hash = current_hash
        self._registry_rejected_hash = None
        if self.observability is not None:
            self.observability.record_upstream_registry_reload(outcome="applied")
            self.observability.set_upstream_registry_identity(
                content_hash=upstream_registry_info_hash(current_hash)
            )
        logger.info(
            "upstream registry reloaded: added=%s removed=%s changed=%s",
            list(diff.added),
            list(diff.removed),
            list(diff.changed),
        )
        self._maybe_log_drift(
            became_available=False,
            added=len(diff.added),
            removed=len(diff.removed),
            updated=len(diff.changed),
        )
        return tools_changed, prompts_changed, resources_changed

    def _drop_namespace_snapshots(self, namespace: str) -> None:
        self._namespace_fingerprints.pop(namespace, None)
        self._namespace_prompt_fingerprints.pop(namespace, None)
        self._namespace_resource_fingerprints.pop(namespace, None)
        self._namespace_template_fingerprints.pop(namespace, None)
        self._empty_list_streak.pop(namespace, None)
        self._empty_prompt_list_streak.pop(namespace, None)
        self._empty_resource_list_streak.pop(namespace, None)

    async def _maybe_reload_policy(self, *, force: bool) -> bool:
        """Reload the RBAC policy if its files changed (or ``force``); return whether it was."""
        if self.policy_manager is None:
            return False
        current_policy, current_snapshot = await asyncio.to_thread(
            policy_files_content_hashes, self.settings
        )
        unchanged = current_policy == self._policy_hash and current_snapshot == self._snapshot_hash
        if unchanged and not force:
            return False

        result = await asyncio.to_thread(self.policy_manager.reload, self.registry)
        if self.observability is not None:
            self.observability.record_policy_reload(success=result.success)
        if result.success:
            self._policy_hash = current_policy
            self._snapshot_hash = current_snapshot
            if force:
                logger.info("rbac policy reloaded via SIGHUP")
                identity = self.policy_manager.identity
                if identity is not None and self.policy_revision_watcher is not None:
                    await self.policy_revision_watcher.publish(identity.content_hash)
            else:
                logger.info("rbac policy reloaded after file change")
        else:
            logger.warning("rbac policy reload rejected: %s", result.error)
        return result.success

    async def _observe_users_revision(self) -> bool:
        """Return whether the users-directory revision changed since the last tick."""
        if self.revision_reader is None:
            return False
        try:
            revision = await self.revision_reader.current()
        except Exception:
            return False
        if self._last_users_revision is None:
            self._last_users_revision = revision
            return False
        if revision != self._last_users_revision:
            logger.info(
                "users directory revision changed %s -> %s",
                self._last_users_revision,
                revision,
            )
            self._last_users_revision = revision
            return True
        return False

    def _record_catalog_outcome(
        self,
        *,
        unchanged: bool = False,
        held: bool = False,
        applied: bool = False,
        added: int = 0,
        removed: int = 0,
    ) -> None:
        if self.observability is None:
            return
        self.observability.record_catalog_refresh(
            unchanged=unchanged,
            held=held,
            applied=applied,
            added=added,
            removed=removed,
        )


@asynccontextmanager
async def surface_reconciler_lifespan(reconciler: SurfaceReconciler | None):
    """FastMCP lifespan hook that starts and stops the reconciler task."""
    if reconciler is not None:
        await reconciler.start()
    try:
        yield {}
    finally:
        if reconciler is not None:
            await reconciler.stop()
