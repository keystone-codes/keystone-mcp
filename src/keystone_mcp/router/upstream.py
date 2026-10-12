"""Upstream API registration and 1:1 proxy auto-discovery.

Each upstream is mounted as its own FastMCP sub-server (``namespace``) so tools
appear grouped by API in MCP clients. On startup ``discover_all`` calls
``list_tools()`` on the downstream MCP server and registers live proxy routes.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import os
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlparse

from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport

from keystone_mcp.adapters.base import Pattern
from keystone_mcp.adapters.mcp_proxy import HttpClientFactoryBuilder, McpProxyAdapter
from keystone_mcp.rbac.upstream_state import UpstreamCatalogState
from keystone_mcp.router.catalog_fingerprint import tool_fingerprint
from keystone_mcp.router.proxy_schema import PatchTable, apply_proxy_schema_patches
from keystone_mcp.router.registry import Param
from keystone_mcp.router.route import Mode
from keystone_mcp.router.schema import schema_to_params

if TYPE_CHECKING:
    from mcp.shared._httpx_utils import McpHttpClientFactory

    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.router.registry import RouterRegistry

logger = logging.getLogger(__name__)

UpstreamMode = Literal["proxy_1to1"]
_DEFAULT_HTTP_PORTS = frozenset({80, 443})
ToolFilter = Callable[[str], bool]
_AUTO_PAGINATION_MAX_PAGES = 250


@dataclass(frozen=True, slots=True)
class UpstreamToolSpec:
    """One filtered upstream tool ready to mount under a namespace."""

    route_name: str
    upstream_tool: str
    params: list[Param]
    description: str
    fingerprint: str
    # The upstream's own (patched, normalized) inputSchema -- never None, see
    # _normalize_input_schema -- plus its raw outputSchema/title/annotations,
    # published verbatim by UpstreamProxyTool (P07).
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None
    title: str | None
    annotations: dict[str, Any] | None


class UpstreamListToolsError(Exception):
    """Raised when upstream list_tools cannot be trusted (timeout, pagination)."""


class UpstreamUnavailableError(RuntimeError):
    """Raised at startup when KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true and an upstream is down."""


@dataclass(slots=True)
class UpstreamStatus:
    """Last known reachability of one configured upstream."""

    available: bool  # last discovery/refresh attempt succeeded
    catalog_known: bool  # tool list was read successfully at least once
    last_error: str | None


def build_prefix_tool_filter(
    *,
    include_prefixes: tuple[str, ...] = (),
    exclude_prefixes: tuple[str, ...] = (),
) -> ToolFilter | None:
    """Build a discovery filter from optional include/exclude prefix lists."""
    if not include_prefixes and not exclude_prefixes:
        return None

    def _matches(tool_name: str) -> bool:
        if include_prefixes and not any(
            tool_name.startswith(prefix) for prefix in include_prefixes
        ):
            return False
        if exclude_prefixes and any(tool_name.startswith(prefix) for prefix in exclude_prefixes):
            return False
        return True

    return _matches


def upstream_host_for_log(url: str) -> str:
    """Return host (and non-default port) for logs — never credentials or path."""
    parsed = urlparse(url)
    host = parsed.hostname or "<unknown>"
    if parsed.port is not None and parsed.port not in _DEFAULT_HTTP_PORTS:
        return f"{host}:{parsed.port}"
    return host


def resolve_mounted_tool_name(tool_name: str, strip_prefix: str | None) -> str:
    """Derive the route name mounted under a namespace sub-server."""
    if strip_prefix and tool_name.startswith(strip_prefix):
        return tool_name[len(strip_prefix) :]
    return tool_name


async def fetch_upstream_tools(
    url: str,
    *,
    timeout_seconds: float,
    max_pages: int = _AUTO_PAGINATION_MAX_PAGES,
    httpx_client_factory: "McpHttpClientFactory | None" = None,
    headers: Mapping[str, str] | None = None,
) -> list[Any]:
    """Paginated list_tools; refuse incomplete pages (duplicate cursor or limit).

    ``httpx_client_factory`` lets tests point discovery at an in-process ASGI
    app instead of a real HTTP port; production callers leave it unset and get
    the transport's own default client. ``headers`` (e.g. the upstream's
    ``Authorization: Bearer ...``, from :meth:`UpstreamRegistry.
    upstream_headers`) are sent on every discovery request the same way they
    are sent on every proxied call.

    Always raises :class:`UpstreamListToolsError` on failure (connection
    refused, timeout, malformed pagination, ...) so callers only need to
    handle one exception type. ``asyncio.CancelledError`` is not an
    ``Exception`` and propagates unchanged.
    """
    try:
        transport = StreamableHttpTransport(
            url.rstrip("/"),
            headers=dict(headers or {}),
            httpx_client_factory=httpx_client_factory,
        )
        async with Client(transport, init_timeout=timeout_seconds) as client:
            all_tools: list[Any] = []
            cursor: str | None = None
            seen_cursors: set[str] = set()

            async def _one_page() -> Any:
                return await client.list_tools_mcp(cursor=cursor)

            for _ in range(max_pages):
                try:
                    result = await asyncio.wait_for(_one_page(), timeout=timeout_seconds)
                except Exception as exc:
                    raise UpstreamListToolsError(str(exc)) from exc
                all_tools.extend(result.tools)
                if not result.next_cursor:
                    return all_tools
                if result.next_cursor in seen_cursors:
                    raise UpstreamListToolsError(
                        f"duplicate pagination cursor {result.next_cursor!r}"
                    )
                seen_cursors.add(result.next_cursor)
                cursor = result.next_cursor
            raise UpstreamListToolsError(
                f"auto-pagination limit ({max_pages} pages) reached for {url}"
            )
    except UpstreamListToolsError:
        raise
    except Exception as exc:
        raise UpstreamListToolsError(f"{type(exc).__name__}: {exc}") from exc


def _normalize_input_schema(schema: dict[str, Any] | None) -> dict[str, Any]:
    """Deep-copy *schema* and make it a valid top-level JSON Schema object.

    MCP clients reject an ``inputSchema`` without ``"type": "object"``; an
    upstream whose advertised schema omits it (or omits ``properties``, or
    has a non-dict ``properties``) still needs a publishable one. Nothing
    else is touched: ``$defs``, ``$ref``, ``additionalProperties``,
    ``required`` and every property are kept exactly as the upstream (and any
    ``KEYSTONE_MCP_PROXY_SCHEMA_PATCHES`` patch) declared them.
    """
    normalized: dict[str, Any] = copy.deepcopy(schema) if isinstance(schema, dict) else {}
    normalized.setdefault("type", "object")
    if not isinstance(normalized.get("properties"), dict):
        normalized["properties"] = {}
    return normalized


def _copy_dict_or_none(value: Any) -> dict[str, Any] | None:
    return copy.deepcopy(value) if isinstance(value, dict) else None


def build_upstream_tool_specs(
    cfg: UpstreamConfig,
    tools: Iterable[Any],
    *,
    schema_patches: PatchTable,
) -> dict[str, UpstreamToolSpec]:
    """Map route names to specs; resolve strip_prefix collisions stably."""
    winners: dict[str, tuple[str, UpstreamToolSpec]] = {}

    for tool in tools:
        tool_name = tool.name
        if cfg.tool_filter is not None and not cfg.tool_filter(tool_name):
            continue

        route_name = resolve_mounted_tool_name(tool_name, cfg.strip_prefix)
        if not route_name:
            continue

        # Read only the snake_case names MCP SDK v2 actually uses (the
        # camelCase ones -- inputSchema, outputSchema -- still resolve, via
        # fastmcp's compatibility shim, but emit a FastMCPDeprecationWarning
        # that pyproject.toml's filterwarnings turns into a test failure).
        # ``getattr`` with a default keeps this tolerant of duck-typed
        # fixtures (tests) that only set the fields they care about, exactly
        # as it was before the SDK v2 migration.
        raw_schema = getattr(tool, "input_schema", None)
        patched_schema = apply_proxy_schema_patches(
            cfg.namespace,
            tool_name,
            raw_schema if isinstance(raw_schema, dict) else None,
            patches=schema_patches,
        )
        input_schema = _normalize_input_schema(patched_schema)
        params = schema_to_params(input_schema)
        description = tool.description or ""
        output_schema = _copy_dict_or_none(getattr(tool, "output_schema", None))
        title = getattr(tool, "title", None)
        raw_annotations = getattr(tool, "annotations", None)
        # Stored in wire form (``readOnlyHint`` etc., via ``by_alias=True``) so
        # the tool fingerprint and the published annotations do not depend on
        # how the SDK happens to name fields in Python -- see
        # ``UpstreamProxyTool.for_route``, which rebuilds ``ToolAnnotations``
        # with ``model_validate``.
        annotations = (
            raw_annotations.model_dump(by_alias=True, exclude_none=True)
            if raw_annotations is not None
            else None
        )
        spec = UpstreamToolSpec(
            route_name=route_name,
            upstream_tool=tool_name,
            params=params,
            description=description,
            input_schema=input_schema,
            output_schema=output_schema,
            title=title,
            annotations=annotations,
            fingerprint=tool_fingerprint(
                route_name=route_name,
                upstream_tool=tool_name,
                description=description,
                params=params,
                input_schema=input_schema,
                output_schema=output_schema,
                title=title,
                annotations=annotations,
            ),
        )
        existing = winners.get(route_name)
        if existing is None or tool_name < existing[0]:
            winners[route_name] = (tool_name, spec)

    return {route_name: spec for route_name, (_tool, spec) in winners.items()}


@dataclass
class UpstreamConfig:
    name: str
    url: str
    namespace: str
    mode: UpstreamMode = "proxy_1to1"
    route_mode: Mode = "live"
    tool_filter: ToolFilter | None = None
    strip_prefix: str | None = None
    discovery_timeout_seconds: float | None = None
    tool_timeout_seconds: float | None = None


@dataclass
class UpstreamRegistry:
    """Manages mounted upstream MCP APIs and auto-generated proxy routes."""

    main_mcp: FastMCP
    registry: "RouterRegistry"
    tool_timeout_seconds: float = 180.0
    discovery_timeout_seconds: float = 10.0
    tool_timeout_overrides: dict[str, float] = field(default_factory=dict)
    # false (default): proxied answers pass through as-is. true: wrap them in
    # the 0.3.x {state, tool, task_id, result} envelope (KEYSTONE_MCP_PROXY_STATUS_ENVELOPE).
    status_envelope: bool = False
    # Deployment-supplied inputSchema property patches, keyed (namespace, tool).
    schema_patches: PatchTable = field(default_factory=dict)
    # Builds the HTTP client used for discovery and proxied calls; ``None``
    # keeps the transport's own default client (production default). Tests
    # inject an in-process ASGI factory to reach a test upstream without a
    # real port.
    http_client_factory: HttpClientFactoryBuilder | None = None
    # Retries per upstream at startup discovery; upstreams are discovered in
    # parallel, so this bounds one upstream's attempts, not the overall budget.
    discovery_retries: int = 0
    # Whether the background catalog refresh (SurfaceReconciler) is enabled
    # (KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS > 0). Only changes the wording of
    # the startup "upstream unavailable" WARNING below: when it is False,
    # nothing will ever retry a startup failure, so the message must not
    # promise one.
    refresh_enabled: bool = True
    observability: "RbacObservability | None" = None
    _upstreams: list[UpstreamConfig] = field(default_factory=list)
    _sub_servers: dict[str, FastMCP] = field(default_factory=dict)
    _adapters: dict[str, McpProxyAdapter] = field(default_factory=dict)
    _status: dict[str, UpstreamStatus] = field(default_factory=dict)
    # Per-namespace extra headers (currently just ``Authorization: Bearer
    # ...``, from ``auth.bearer_env``) sent on discovery and every proxied
    # call. Never logged or repr'd as a whole — only individual header values
    # pass through the shared log redaction (observability/logging/redact.py).
    _auth_headers: dict[str, dict[str, str]] = field(default_factory=dict, repr=False)
    # route_name(s), per namespace, that the upstream currently offers but
    # that could not be published (an unpublishable schema -- e.g. a
    # parameter named ``from``). The namespace itself is reachable; only this
    # one tool is not. Consulted by the RBAC policy gate (``catalog_state``)
    # so an allow pattern that names exactly this tool is logged as "not
    # verified" rather than refusing the policy as a typo.
    _unpublishable: dict[str, set[str]] = field(default_factory=dict)

    def add_upstream(
        self,
        name: str,
        url: str,
        *,
        namespace: str,
        mode: UpstreamMode = "proxy_1to1",
        route_mode: Mode = "live",
        tool_filter: ToolFilter | None = None,
        strip_prefix: str | None = None,
        discovery_timeout_seconds: float | None = None,
        tool_timeout_seconds: float | None = None,
        bearer_env: str | None = None,
    ) -> UpstreamConfig:
        """Register an upstream MCP API and mount its namespace sub-server.

        ``bearer_env`` names an environment variable holding a bearer token
        Keystone sends to this upstream (``Authorization: Bearer <value>``) on
        discovery and every proxied call. The token itself is read here and
        kept only in ``_auth_headers``; neither ``UpstreamConfig`` nor any
        other field on this registry ever holds it, so logging or repr'ing
        the registry cannot leak it. A missing or empty variable refuses
        startup with a ``ValueError`` naming the variable, never its value.
        """
        if namespace in self._sub_servers:
            raise ValueError(f"upstream namespace already registered: {namespace}")

        resolved_url = url.rstrip("/")

        if bearer_env is not None:
            token = os.environ.get(bearer_env, "").strip()
            if not token:
                raise ValueError(
                    f"upstream {name!r}: auth.bearer_env names {bearer_env}, "
                    "which is not set or empty"
                )
            self._auth_headers[namespace] = {"Authorization": f"Bearer {token}"}
            if urlparse(resolved_url).scheme == "http":
                logger.warning(
                    "upstream namespace=%s sends a bearer token over plain http; "
                    "use https outside a private network",
                    namespace,
                )

        cfg = UpstreamConfig(
            name=name,
            url=resolved_url,
            namespace=namespace,
            mode=mode,
            route_mode=route_mode,
            tool_filter=tool_filter,
            strip_prefix=strip_prefix,
            discovery_timeout_seconds=discovery_timeout_seconds,
            tool_timeout_seconds=tool_timeout_seconds,
        )
        self._upstreams.append(cfg)

        sub = FastMCP(name=namespace)
        self.main_mcp.mount(sub, namespace=namespace)
        self._sub_servers[namespace] = sub
        resolved_tool_timeout = (
            tool_timeout_seconds if tool_timeout_seconds is not None else self.tool_timeout_seconds
        )
        self._adapters[namespace] = McpProxyAdapter(
            cfg.url,
            tool_timeout_seconds=resolved_tool_timeout,
            tool_timeout_overrides=self.tool_timeout_overrides,
            http_client_factory=self.http_client_factory,
            status_envelope=self.status_envelope,
            extra_headers=self._auth_headers.get(namespace),
        )
        self._status[namespace] = UpstreamStatus(
            available=False, catalog_known=False, last_error="not discovered yet"
        )
        if self.observability is not None:
            self.observability.record_upstream_available(namespace=namespace, available=False)
        logger.info(
            "mounted upstream namespace=%s host=%s",
            namespace,
            upstream_host_for_log(cfg.url),
        )
        return cfg

    def mark_available(self, namespace: str) -> bool:
        """Record a successful discovery/refresh. Returns True if it was down before.

        The return value tells a caller (P06's policy re-validation) whether
        this namespace just transitioned from unavailable to available,
        including the initial "not discovered yet" state.
        """
        previous = self._status.get(namespace)
        was_unavailable = previous is None or not previous.available
        recovered = previous is not None and not previous.available and previous.catalog_known
        self._status[namespace] = UpstreamStatus(
            available=True, catalog_known=True, last_error=None
        )
        if self.observability is not None:
            self.observability.record_upstream_available(namespace=namespace, available=True)
        if recovered:
            logger.info("upstream available again namespace=%s", namespace)
        return was_unavailable

    def mark_unavailable(self, namespace: str, reason: str) -> None:
        """Record a failed discovery/refresh. Keeps ``catalog_known`` as-is."""
        previous = self._status.get(namespace)
        was_available = previous is not None and previous.available
        catalog_known = previous.catalog_known if previous is not None else False
        self._status[namespace] = UpstreamStatus(
            available=False, catalog_known=catalog_known, last_error=reason
        )
        if self.observability is not None:
            self.observability.record_upstream_available(namespace=namespace, available=False)
        if was_available:
            logger.warning(
                "upstream became unavailable namespace=%s: %s; keeping its previous tool list",
                namespace,
                reason,
            )

    def unavailable_namespaces(self) -> dict[str, str]:
        """Namespace -> reason, for every registered upstream currently down."""
        return {
            namespace: status.last_error or "unknown"
            for namespace, status in self._status.items()
            if not status.available
        }

    def namespaces(self) -> frozenset[str]:
        """All registered upstream namespaces."""
        return frozenset(self._status)

    def mark_unpublishable(self, namespace: str, route_name: str) -> None:
        """Record that the upstream currently offers ``route_name`` but it
        could not be published (an unpublishable schema, e.g. a parameter
        named ``from``). The namespace stays "available"; only this one tool
        is excluded from the live catalog. See :meth:`catalog_state`."""
        self._unpublishable.setdefault(namespace, set()).add(route_name)

    def clear_unpublishable(self, namespace: str, route_name: str) -> None:
        """Drop a prior :meth:`mark_unpublishable` record, e.g. once the tool
        publishes successfully or the upstream stops offering it at all."""
        names = self._unpublishable.get(namespace)
        if names is not None:
            names.discard(route_name)

    def upstream_headers(self, namespace: str) -> dict[str, str]:
        """Extra headers (currently just a bearer token) to send to ``namespace``.

        Returns a fresh copy (or ``{}`` for an upstream with no ``auth``), so
        callers are free to add ``X-Author-Email`` on top without mutating
        registry state.
        """
        return dict(self._auth_headers.get(namespace, {}))

    def catalog_state(self) -> UpstreamCatalogState:
        """Snapshot for the RBAC policy gate (P06, FX-proxy): namespaces, which
        are down, and which individual tools of an otherwise-reachable
        namespace could not be published this cycle."""
        return UpstreamCatalogState(
            namespaces=frozenset(self._status),
            unavailable=frozenset(
                namespace for namespace, status in self._status.items() if not status.available
            ),
            unpublishable=frozenset(
                f"{namespace}_{route_name}"
                for namespace, route_names in self._unpublishable.items()
                for route_name in route_names
            ),
        )

    async def discover_all(self) -> dict[str, int]:
        """Discover tools for every registered upstream, in parallel.

        Returns tool counts only for upstreams whose discovery succeeded
        (within ``discovery_retries`` attempts each); an upstream that stays
        down is omitted, not raised, so one unreachable service never blocks
        the others.
        """
        results = await asyncio.gather(
            *(self._discover_with_retries(cfg) for cfg in self._upstreams)
        )
        return {
            cfg.namespace: count
            for cfg, count in zip(self._upstreams, results, strict=True)
            if count is not None
        }

    async def _discover_with_retries(self, cfg: UpstreamConfig) -> int | None:
        """Retry one upstream's discovery with exponential backoff.

        Never raises: a persistently unreachable upstream is recorded via
        ``mark_unavailable`` and ``None`` is returned instead.
        """
        attempts = self.discovery_retries + 1
        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                count = await self._discover_one(cfg)
            except Exception as exc:  # noqa: BLE001 - reported, not propagated
                last_exc = exc
                if attempt + 1 < attempts:
                    delay = min(2**attempt, 30)
                    logger.warning(
                        "upstream discovery attempt %d/%d failed namespace=%s: %s; retry in %ds",
                        attempt + 1,
                        attempts,
                        cfg.namespace,
                        exc,
                        delay,
                    )
                    await asyncio.sleep(delay)
                continue
            else:
                self.mark_available(cfg.namespace)
                return count

        self.mark_unavailable(cfg.namespace, f"{type(last_exc).__name__}: {last_exc}")
        if self.refresh_enabled:
            logger.warning(
                "upstream unavailable at startup namespace=%s: %s; other upstreams are "
                "proxied, this one is retried on every refresh tick",
                cfg.namespace,
                last_exc,
            )
        else:
            logger.warning(
                "upstream unavailable at startup namespace=%s: %s; other upstreams are "
                "proxied, this one will not be retried; refresh is disabled "
                "(KEYSTONE_MCP_REFRESH_INTERVAL_SECONDS=0)",
                cfg.namespace,
                last_exc,
            )
        return None

    async def _discover_one(self, cfg: UpstreamConfig) -> int:
        if cfg.mode != "proxy_1to1":
            raise ValueError(f"unsupported upstream mode: {cfg.mode}")

        sub = self._sub_servers[cfg.namespace]
        adapter = self._adapters[cfg.namespace]
        registered = 0

        discovery_timeout = (
            cfg.discovery_timeout_seconds
            if cfg.discovery_timeout_seconds is not None
            else self.discovery_timeout_seconds
        )
        tools = await fetch_upstream_tools(
            cfg.url,
            timeout_seconds=discovery_timeout,
            httpx_client_factory=(
                self.http_client_factory(discovery_timeout) if self.http_client_factory else None
            ),
            headers=self.upstream_headers(cfg.namespace),
        )
        specs = build_upstream_tool_specs(cfg, tools, schema_patches=self.schema_patches)
        for spec in specs.values():
            route_key = f"{cfg.namespace}:{spec.route_name}"
            published = f"{cfg.namespace}_{spec.route_name}"

            owner_key = self.registry.owner_of_published_name(published)
            if owner_key is not None and owner_key != route_key:
                logger.error(
                    "upstream discovery refused namespace=%s route=%s: "
                    "published name %s already owned by %s",
                    cfg.namespace,
                    spec.route_name,
                    published,
                    owner_key,
                )
                continue

            try:
                self.registry.add_route(
                    spec.route_name,
                    adapter,
                    pattern=Pattern.M_B,
                    params=spec.params,
                    description=spec.description,
                    mode=cfg.route_mode,
                    upstream_tool=spec.upstream_tool,
                    namespace=cfg.namespace,
                    config_mode="PROXY",
                    tags={cfg.namespace},
                    meta={"upstream": cfg.name, "namespace": cfg.namespace},
                    mcp=sub,
                    input_schema=spec.input_schema,
                    output_schema=spec.output_schema,
                    title=spec.title,
                    annotations=spec.annotations,
                )
            except Exception as exc:
                logger.error(
                    "upstream tool skipped namespace=%s tool=%s: %s",
                    cfg.namespace,
                    spec.upstream_tool,
                    exc,
                )
                # add_route is atomic: on failure it wrote nothing, so there
                # is nothing to roll back here (route_key never had an entry
                # at startup discovery time). Record it as unpublishable so
                # the RBAC policy gate (P06, FX-proxy) treats an allow
                # pattern naming exactly this tool as "not verified" rather
                # than a typo.
                self.mark_unpublishable(cfg.namespace, spec.route_name)
                continue
            self.clear_unpublishable(cfg.namespace, spec.route_name)
            registered += 1

        logger.info(
            "discovered upstream=%s namespace=%s tools=%d",
            cfg.name,
            cfg.namespace,
            registered,
        )
        return registered
