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
from keystone_mcp.config import Settings
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
    fetch_upstream_prompts,
    fetch_upstream_resource_templates,
    fetch_upstream_resources,
    fetch_upstream_tools,
    list_upstream_prompts,
    list_upstream_resource_templates,
    list_upstream_resources,
    list_upstream_tools,
)

if TYPE_CHECKING:
    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.rbac.loader import RbacPolicyManager
    from keystone_mcp.router.registry import RouterRegistry
    from keystone_mcp.router.upstream import UpstreamRegistry
    from keystone_mcp.surface.client_sessions import ClientSessionRegistry
    from keystone_mcp.user_directory.revision import RevisionReader

logger = logging.getLogger(__name__)

_JITTER_MAX_SECONDS = 15.0
_RESTART_DELAY_MIN_SECONDS = 5.0
_RESTART_DELAY_MAX_SECONDS = 300.0


@dataclass
class SurfaceReconciler:
    """Background tick: refresh upstream tools, then policy files when bytes change."""

    settings: Settings
    registry: RouterRegistry
    upstreams: UpstreamRegistry
    policy_manager: RbacPolicyManager | None
    observability: RbacObservability | None
    revision_reader: RevisionReader | None = None
    client_sessions: ClientSessionRegistry | None = None

    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _policy_reload_event: asyncio.Event = field(
        default_factory=asyncio.Event, init=False, repr=False
    )
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

    def seed_snapshots(self) -> None:
        """Capture post-bootstrap state so the first tick is a no-op when unchanged."""
        self._policy_hash, self._snapshot_hash = policy_files_content_hashes(self.settings)
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

    async def start(self) -> None:
        interval = self.settings.refresh_interval_seconds
        if interval <= 0:
            return
        self._loop = asyncio.get_running_loop()
        self.seed_snapshots()
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
                    await asyncio.wait_for(
                        self._policy_reload_event.wait(),
                        timeout=wait_seconds,
                    )
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

    async def _tick_locked(self) -> None:
        force_policy = self._policy_reload_event.is_set()
        if force_policy:
            self._policy_reload_event.clear()

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

    async def _refresh_catalogs(self) -> tuple[bool, bool, bool]:
        """Refresh every namespace; return (tools, prompts, resources) changed flags."""
        tools_changed = False
        prompts_changed = False
        resources_changed = False
        for cfg in self.upstreams._upstreams:
            try:
                tc, pc, rc = await self._refresh_namespace(cfg)
                tools_changed = tools_changed or tc
                prompts_changed = prompts_changed or pc
                resources_changed = resources_changed or rc
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.upstreams.mark_unavailable(cfg.namespace, f"{type(exc).__name__}: {exc}")
                logger.exception(
                    "upstream refresh crashed namespace=%s; keeping previous catalog",
                    cfg.namespace,
                )
                self._record_catalog_outcome(held=True)
        return tools_changed, prompts_changed, resources_changed

    async def _refresh_namespace(self, cfg: object) -> tuple[bool, bool, bool]:
        """Refresh one namespace's tool, prompt and resource catalogs."""
        from keystone_mcp.router.upstream import UpstreamConfig

        assert isinstance(cfg, UpstreamConfig)
        namespace = cfg.namespace
        previous = self._namespace_fingerprints.get(namespace, {})

        discovery_timeout = (
            cfg.discovery_timeout_seconds
            if cfg.discovery_timeout_seconds is not None
            else self.upstreams.discovery_timeout_seconds
        )
        prompts_raw: list = []
        resources_raw: list = []
        templates_raw: list = []
        try:
            if cfg.transport == "stdio":
                try:
                    client = self.upstreams.connection(namespace).catalog_client(
                        timeout=discovery_timeout
                    )
                except UpstreamProcessUnavailableError as exc:
                    self.upstreams.mark_unavailable(namespace, str(exc))
                    logger.warning(
                        "upstream refresh failed namespace=%s: %s; keeping previous catalog",
                        namespace,
                        exc,
                    )
                    self._record_catalog_outcome(held=True)
                    return False, False, False
                async with client:
                    tools = await list_upstream_tools(client, timeout_seconds=discovery_timeout)
                    try:
                        prompts_raw = await list_upstream_prompts(
                            client, timeout_seconds=discovery_timeout
                        )
                    except UpstreamListToolsError as exc:
                        logger.warning(
                            "upstream prompts refresh failed namespace=%s: %s; "
                            "keeping previous prompts",
                            namespace,
                            exc,
                        )
                    try:
                        resources_raw = await list_upstream_resources(
                            client, timeout_seconds=discovery_timeout
                        )
                        templates_raw = await list_upstream_resource_templates(
                            client, timeout_seconds=discovery_timeout
                        )
                    except UpstreamListToolsError as exc:
                        logger.warning(
                            "upstream resources refresh failed namespace=%s: %s; "
                            "keeping previous resources",
                            namespace,
                            exc,
                        )
            else:
                tools = await fetch_upstream_tools(
                    cfg.url,
                    timeout_seconds=discovery_timeout,
                    httpx_client_factory=(
                        self.upstreams.http_client_factory(discovery_timeout)
                        if self.upstreams.http_client_factory
                        else None
                    ),
                    headers=self.upstreams.upstream_headers(namespace),
                )
                try:
                    prompts_raw = await fetch_upstream_prompts(
                        cfg.url,
                        timeout_seconds=discovery_timeout,
                        httpx_client_factory=(
                            self.upstreams.http_client_factory(discovery_timeout)
                            if self.upstreams.http_client_factory
                            else None
                        ),
                        headers=self.upstreams.upstream_headers(namespace),
                    )
                except UpstreamListToolsError as exc:
                    logger.warning(
                        "upstream prompts refresh failed namespace=%s: %s; keeping previous prompts",
                        namespace,
                        exc,
                    )
                try:
                    resources_raw = await fetch_upstream_resources(
                        cfg.url,
                        timeout_seconds=discovery_timeout,
                        httpx_client_factory=(
                            self.upstreams.http_client_factory(discovery_timeout)
                            if self.upstreams.http_client_factory
                            else None
                        ),
                        headers=self.upstreams.upstream_headers(namespace),
                    )
                    templates_raw = await fetch_upstream_resource_templates(
                        cfg.url,
                        timeout_seconds=discovery_timeout,
                        httpx_client_factory=(
                            self.upstreams.http_client_factory(discovery_timeout)
                            if self.upstreams.http_client_factory
                            else None
                        ),
                        headers=self.upstreams.upstream_headers(namespace),
                    )
                except UpstreamListToolsError as exc:
                    logger.warning(
                        "upstream resources refresh failed namespace=%s: %s; "
                        "keeping previous resources",
                        namespace,
                        exc,
                    )
        except UpstreamListToolsError as exc:
            self.upstreams.mark_unavailable(namespace, str(exc))
            logger.warning(
                "upstream refresh failed namespace=%s: %s; keeping previous catalog",
                namespace,
                exc,
            )
            self._record_catalog_outcome(held=True)
            return False, False, False

        became_available = self.upstreams.mark_available(namespace)
        specs = build_upstream_tool_specs(cfg, tools, schema_patches=self.upstreams.schema_patches)
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
                prompts_changed = self._refresh_prompts_for_namespace(cfg, prompts_raw)
                resources_changed = self._refresh_resources_for_namespace(
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

        prompts_changed = self._refresh_prompts_for_namespace(cfg, prompts_raw)
        resources_changed = self._refresh_resources_for_namespace(cfg, resources_raw, templates_raw)
        return tools_changed, prompts_changed, resources_changed

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

    def _refresh_prompts_for_namespace(self, cfg: object, prompts_raw: list) -> bool:
        from keystone_mcp.router.upstream import UpstreamConfig, resolve_mounted_tool_name

        assert isinstance(cfg, UpstreamConfig)
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

        raw_by_route = {
            resolve_mounted_tool_name(p.name, cfg.strip_prefix): p
            for p in prompts_raw
            if resolve_mounted_tool_name(p.name, cfg.strip_prefix)
        }
        changed = self.upstreams._apply_prompt_specs(cfg, prompt_specs, raw_by_route)
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
        self, cfg: object, resources_raw: list, templates_raw: list
    ) -> bool:
        from keystone_mcp.router.upstream import UpstreamConfig

        assert isinstance(cfg, UpstreamConfig)
        namespace = cfg.namespace
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
        self._namespace_resource_fingerprints[namespace] = dict(desired_res)
        self._namespace_template_fingerprints[namespace] = dict(desired_tpl)
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
