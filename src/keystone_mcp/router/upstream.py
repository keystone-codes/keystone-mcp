"""Upstream API registration and 1:1 proxy auto-discovery.

Each upstream is mounted as its own FastMCP sub-server (``namespace``) so tools
appear grouped by API in MCP clients. On startup ``discover_all`` calls
``list_tools()`` on the downstream MCP server and registers live proxy routes.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlparse

from fastmcp import Client, FastMCP
from fastmcp.client.transports import StreamableHttpTransport

from keystone_mcp.adapters.base import Pattern
from keystone_mcp.adapters.mcp_proxy import (
    DEFAULT_UPSTREAM_MAX_RESPONSE_BYTES,
    HttpClientFactoryBuilder,
    McpProxyAdapter,
    _http_client_factory,
)
from keystone_mcp.identity_assertion import (
    IdentityAssertionSigner,
    ec_public_key_jwk_thumbprint,
    load_ec_p256_private_key,
    resolve_identity_secret,
)
from keystone_mcp.observability.metrics import record_upstream_item_rejected
from keystone_mcp.rbac.upstream_state import UpstreamCatalogState
from keystone_mcp.router.catalog_fingerprint import (
    prompt_fingerprint,
    resource_fingerprint,
    template_fingerprint,
    tool_fingerprint,
)
from keystone_mcp.router.proxy_components import (
    UpstreamProxyPrompt,
    UpstreamProxyResource,
    UpstreamProxyTemplate,
)
from keystone_mcp.router.proxy_schema import PatchTable, apply_proxy_schema_patches
from keystone_mcp.router.registry import Param
from keystone_mcp.router.route import Mode
from keystone_mcp.router.schema import schema_to_params
from keystone_mcp.router.stdio_process import StdioUpstreamProcess, UpstreamProcessUnavailableError
from keystone_mcp.router.upstream_connection import (
    HttpUpstreamConnection,
    StdioUpstreamConnection,
    UpstreamConnection,
)
from keystone_mcp.router.upstream_content import (
    UpstreamContentCatalog,
    UpstreamPromptSpec,
    UpstreamResourceSpec,
    UpstreamTemplateSpec,
    namespaced_uri,
    normalize_resource_uri,
)

if TYPE_CHECKING:
    from mcp.shared._httpx_utils import McpHttpClientFactory

    from keystone_mcp.observability.service import RbacObservability
    from keystone_mcp.router.registry import RouterRegistry

logger = logging.getLogger(__name__)

UpstreamMode = Literal["proxy_1to1"]
_DEFAULT_HTTP_PORTS = frozenset({80, 443})
ToolFilter = Callable[[str], bool]
_AUTO_PAGINATION_MAX_PAGES = 250
DEFAULT_UPSTREAM_MAX_SCHEMA_BYTES = 64 * 1024
DEFAULT_UPSTREAM_MAX_CATALOG_ITEMS = 2000
_MAX_SCHEMA_PATTERN_CHARS = 512
_MAX_SCHEMA_DEPTH = 64


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


def _schema_json_byte_size(schema: dict[str, Any] | None) -> int:
    if not schema:
        return 0
    return len(json.dumps(schema, separators=(",", ":")))


def _schema_nesting_depth(value: Any, depth: int = 0) -> int:
    if depth > _MAX_SCHEMA_DEPTH:
        return depth
    if isinstance(value, dict):
        if not value:
            return depth
        return max(_schema_nesting_depth(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        if not value:
            return depth
        return max(_schema_nesting_depth(v, depth + 1) for v in value)
    return depth


def _schema_has_long_pattern(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "pattern" and isinstance(item, str) and len(item) > _MAX_SCHEMA_PATTERN_CHARS:
                return True
            if key == "patternProperties" and isinstance(item, dict):
                for pattern_key in item:
                    if len(pattern_key) > _MAX_SCHEMA_PATTERN_CHARS:
                        return True
            if _schema_has_long_pattern(item):
                return True
    elif isinstance(value, list):
        for item in value:
            if _schema_has_long_pattern(item):
                return True
    return False


def _tool_schema_rejection_reason(
    input_schema: dict[str, Any],
    output_schema: dict[str, Any] | None,
    *,
    max_schema_bytes: int,
) -> str | None:
    """Return a metric ``reason`` when a tool schema must not be published.

    Pattern-length limits are hygiene for schemas Keystone forwards to its own
    clients; ReDoS protection on tool *answers* is handled separately by not
    re-validating upstream results against ``outputSchema``.
    """
    for schema in (input_schema, output_schema):
        if schema is not None and _schema_json_byte_size(schema) > max_schema_bytes:
            return "schema_too_large"
    for schema in (input_schema, output_schema):
        if schema is not None and _schema_nesting_depth(schema) > _MAX_SCHEMA_DEPTH:
            return "schema_too_deep"
    for schema in (input_schema, output_schema):
        if schema is not None and _schema_has_long_pattern(schema):
            return "schema_pattern_too_long"
    return None


def _check_catalog_page_limit(
    count: int,
    *,
    max_items: int,
    kind: str,
    namespace: str | None,
) -> None:
    if count <= max_items:
        return
    if namespace is not None:
        record_upstream_item_rejected(
            namespace=namespace,
            kind="catalog",
            reason="catalog_limit",
        )
    raise UpstreamListToolsError(f"catalog exceeds {max_items} {kind}")


async def list_upstream_tools(
    client: Client,
    *,
    timeout_seconds: float,
    max_pages: int = _AUTO_PAGINATION_MAX_PAGES,
    max_items: int = DEFAULT_UPSTREAM_MAX_CATALOG_ITEMS,
    namespace: str | None = None,
) -> list[Any]:
    """Paginated ``list_tools`` on an already-constructed MCP client."""
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
        _check_catalog_page_limit(
            len(all_tools), max_items=max_items, kind="tools", namespace=namespace
        )
        if not result.next_cursor:
            return all_tools
        if result.next_cursor in seen_cursors:
            raise UpstreamListToolsError(f"duplicate pagination cursor {result.next_cursor!r}")
        seen_cursors.add(result.next_cursor)
        cursor = result.next_cursor
    raise UpstreamListToolsError(f"auto-pagination limit ({max_pages} pages) reached")


async def list_upstream_prompts(
    client: Client,
    *,
    timeout_seconds: float,
    max_pages: int = _AUTO_PAGINATION_MAX_PAGES,
    max_items: int = DEFAULT_UPSTREAM_MAX_CATALOG_ITEMS,
    namespace: str | None = None,
) -> list[Any]:
    """Paginated ``list_prompts`` on an already-constructed MCP client."""
    caps = client.server_capabilities
    if caps is None or caps.prompts is None:
        return []

    all_prompts: list[Any] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()

    async def _one_page() -> Any:
        return await client.list_prompts_mcp(cursor=cursor)

    for _ in range(max_pages):
        try:
            result = await asyncio.wait_for(_one_page(), timeout=timeout_seconds)
        except Exception as exc:
            raise UpstreamListToolsError(str(exc)) from exc
        all_prompts.extend(result.prompts)
        _check_catalog_page_limit(
            len(all_prompts), max_items=max_items, kind="prompts", namespace=namespace
        )
        if not result.next_cursor:
            return all_prompts
        if result.next_cursor in seen_cursors:
            raise UpstreamListToolsError(f"duplicate pagination cursor {result.next_cursor!r}")
        seen_cursors.add(result.next_cursor)
        cursor = result.next_cursor
    raise UpstreamListToolsError(f"auto-pagination limit ({max_pages} pages) reached")


async def list_upstream_resources(
    client: Client,
    *,
    timeout_seconds: float,
    max_pages: int = _AUTO_PAGINATION_MAX_PAGES,
    max_items: int = DEFAULT_UPSTREAM_MAX_CATALOG_ITEMS,
    namespace: str | None = None,
) -> list[Any]:
    """Paginated ``list_resources`` on an already-constructed MCP client."""
    caps = client.server_capabilities
    if caps is None or caps.resources is None:
        return []

    all_resources: list[Any] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()

    async def _one_page() -> Any:
        return await client.list_resources_mcp(cursor=cursor)

    for _ in range(max_pages):
        try:
            result = await asyncio.wait_for(_one_page(), timeout=timeout_seconds)
        except Exception as exc:
            raise UpstreamListToolsError(str(exc)) from exc
        all_resources.extend(result.resources)
        _check_catalog_page_limit(
            len(all_resources), max_items=max_items, kind="resources", namespace=namespace
        )
        if not result.next_cursor:
            return all_resources
        if result.next_cursor in seen_cursors:
            raise UpstreamListToolsError(f"duplicate pagination cursor {result.next_cursor!r}")
        seen_cursors.add(result.next_cursor)
        cursor = result.next_cursor
    raise UpstreamListToolsError(f"auto-pagination limit ({max_pages} pages) reached")


async def list_upstream_resource_templates(
    client: Client,
    *,
    timeout_seconds: float,
    max_pages: int = _AUTO_PAGINATION_MAX_PAGES,
    max_items: int = DEFAULT_UPSTREAM_MAX_CATALOG_ITEMS,
    namespace: str | None = None,
) -> list[Any]:
    """Paginated ``list_resource_templates`` on an already-constructed MCP client."""
    caps = client.server_capabilities
    if caps is None or caps.resources is None:
        return []

    all_templates: list[Any] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()

    async def _one_page() -> Any:
        return await client.list_resource_templates_mcp(cursor=cursor)

    for _ in range(max_pages):
        try:
            result = await asyncio.wait_for(_one_page(), timeout=timeout_seconds)
        except Exception as exc:
            raise UpstreamListToolsError(str(exc)) from exc
        all_templates.extend(result.resource_templates)
        _check_catalog_page_limit(
            len(all_templates),
            max_items=max_items,
            kind="resource templates",
            namespace=namespace,
        )
        if not result.next_cursor:
            return all_templates
        if result.next_cursor in seen_cursors:
            raise UpstreamListToolsError(f"duplicate pagination cursor {result.next_cursor!r}")
        seen_cursors.add(result.next_cursor)
        cursor = result.next_cursor
    raise UpstreamListToolsError(f"auto-pagination limit ({max_pages} pages) reached")


async def fetch_upstream_tools(
    url: str,
    *,
    timeout_seconds: float,
    max_pages: int = _AUTO_PAGINATION_MAX_PAGES,
    max_items: int = DEFAULT_UPSTREAM_MAX_CATALOG_ITEMS,
    namespace: str | None = None,
    httpx_client_factory: "McpHttpClientFactory | None" = None,
    headers: Mapping[str, str] | None = None,
) -> list[Any]:
    """HTTP discovery helper; opens a client and calls :func:`list_upstream_tools`.

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
            return await list_upstream_tools(
                client,
                timeout_seconds=timeout_seconds,
                max_pages=max_pages,
                max_items=max_items,
                namespace=namespace,
            )
    except UpstreamListToolsError:
        raise
    except Exception as exc:
        raise UpstreamListToolsError(f"{type(exc).__name__}: {exc}") from exc


async def fetch_upstream_prompts(
    url: str,
    *,
    timeout_seconds: float,
    max_pages: int = _AUTO_PAGINATION_MAX_PAGES,
    max_items: int = DEFAULT_UPSTREAM_MAX_CATALOG_ITEMS,
    namespace: str | None = None,
    httpx_client_factory: "McpHttpClientFactory | None" = None,
    headers: Mapping[str, str] | None = None,
) -> list[Any]:
    """HTTP discovery helper for prompts; mirrors :func:`fetch_upstream_tools`."""
    try:
        transport = StreamableHttpTransport(
            url.rstrip("/"),
            headers=dict(headers or {}),
            httpx_client_factory=httpx_client_factory,
        )
        async with Client(transport, init_timeout=timeout_seconds) as client:
            return await list_upstream_prompts(
                client,
                timeout_seconds=timeout_seconds,
                max_pages=max_pages,
                max_items=max_items,
                namespace=namespace,
            )
    except UpstreamListToolsError:
        raise
    except Exception as exc:
        raise UpstreamListToolsError(f"{type(exc).__name__}: {exc}") from exc


async def fetch_upstream_resources(
    url: str,
    *,
    timeout_seconds: float,
    max_pages: int = _AUTO_PAGINATION_MAX_PAGES,
    max_items: int = DEFAULT_UPSTREAM_MAX_CATALOG_ITEMS,
    namespace: str | None = None,
    httpx_client_factory: "McpHttpClientFactory | None" = None,
    headers: Mapping[str, str] | None = None,
) -> list[Any]:
    """HTTP discovery helper for resources; mirrors :func:`fetch_upstream_tools`."""
    try:
        transport = StreamableHttpTransport(
            url.rstrip("/"),
            headers=dict(headers or {}),
            httpx_client_factory=httpx_client_factory,
        )
        async with Client(transport, init_timeout=timeout_seconds) as client:
            return await list_upstream_resources(
                client,
                timeout_seconds=timeout_seconds,
                max_pages=max_pages,
                max_items=max_items,
                namespace=namespace,
            )
    except UpstreamListToolsError:
        raise
    except Exception as exc:
        raise UpstreamListToolsError(f"{type(exc).__name__}: {exc}") from exc


async def fetch_upstream_resource_templates(
    url: str,
    *,
    timeout_seconds: float,
    max_pages: int = _AUTO_PAGINATION_MAX_PAGES,
    max_items: int = DEFAULT_UPSTREAM_MAX_CATALOG_ITEMS,
    namespace: str | None = None,
    httpx_client_factory: "McpHttpClientFactory | None" = None,
    headers: Mapping[str, str] | None = None,
) -> list[Any]:
    """HTTP discovery helper for resource templates."""
    try:
        transport = StreamableHttpTransport(
            url.rstrip("/"),
            headers=dict(headers or {}),
            httpx_client_factory=httpx_client_factory,
        )
        async with Client(transport, init_timeout=timeout_seconds) as client:
            return await list_upstream_resource_templates(
                client,
                timeout_seconds=timeout_seconds,
                max_pages=max_pages,
                max_items=max_items,
                namespace=namespace,
            )
    except UpstreamListToolsError:
        raise
    except Exception as exc:
        raise UpstreamListToolsError(f"{type(exc).__name__}: {exc}") from exc


def resolve_stdio_child_env(env_from: Sequence[tuple[str, str]]) -> dict[str, str]:
    """Map registry ``env`` entries to values read from this process's environment."""
    return {child: os.environ[var] for child, var in env_from}


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
    max_schema_bytes: int = DEFAULT_UPSTREAM_MAX_SCHEMA_BYTES,
) -> tuple[dict[str, UpstreamToolSpec], set[str]]:
    """Map route names to specs; resolve strip_prefix collisions stably."""
    winners: dict[str, tuple[str, UpstreamToolSpec]] = {}
    schema_rejected: set[str] = set()

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
        output_schema = _copy_dict_or_none(getattr(tool, "output_schema", None))
        rejection = _tool_schema_rejection_reason(
            input_schema,
            output_schema,
            max_schema_bytes=max_schema_bytes,
        )
        if rejection is not None:
            logger.warning(
                "upstream tool refused namespace=%s tool=%s: %s",
                cfg.namespace,
                tool_name,
                rejection,
            )
            record_upstream_item_rejected(
                namespace=cfg.namespace,
                kind="tool",
                reason=rejection,
            )
            schema_rejected.add(route_name)
            continue
        params = schema_to_params(input_schema)
        description = tool.description or ""
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

    return (
        {route_name: spec for route_name, (_tool, spec) in winners.items()},
        schema_rejected,
    )


def _prompt_arguments_fingerprint(prompt: Any) -> list[dict[str, Any]]:
    raw_args = getattr(prompt, "arguments", None) or []
    payload: list[dict[str, Any]] = []
    for arg in raw_args:
        payload.append(
            {
                "name": getattr(arg, "name", ""),
                "description": getattr(arg, "description", None) or "",
                "required": bool(getattr(arg, "required", False)),
            }
        )
    return sorted(payload, key=lambda item: item["name"])


def build_upstream_prompt_specs(
    cfg: UpstreamConfig,
    prompts: Iterable[Any],
) -> dict[str, UpstreamPromptSpec]:
    """Map upstream prompt names to specs (tool prefix filters apply; strip_prefix does not)."""
    specs: dict[str, UpstreamPromptSpec] = {}
    for prompt in prompts:
        prompt_name = prompt.name
        if cfg.tool_filter is not None and not cfg.tool_filter(prompt_name):
            continue
        title = getattr(prompt, "title", None)
        description = getattr(prompt, "description", None) or ""
        arg_fp = _prompt_arguments_fingerprint(prompt)
        published = f"{cfg.namespace}_{prompt_name}"
        specs[prompt_name] = UpstreamPromptSpec(
            name=prompt_name,
            published_name=published,
            fingerprint=prompt_fingerprint(
                name=prompt_name,
                title=title,
                description=description,
                arguments=arg_fp,
            ),
        )
    return specs


def build_upstream_resource_specs(
    cfg: UpstreamConfig,
    resources: Iterable[Any],
) -> dict[str, UpstreamResourceSpec]:
    """Map upstream resource URIs to specs (tool filters do not apply)."""
    specs: dict[str, UpstreamResourceSpec] = {}
    for resource in resources:
        uri = str(resource.uri)
        name = resource.name
        published = namespaced_uri(cfg.namespace, uri)
        if published is None:
            logger.warning(
                "upstream %s refused namespace=%s name=%s: URI %r has no scheme:// part, "
                "so it cannot be namespaced",
                "resource",
                cfg.namespace,
                name,
                uri,
            )
            record_upstream_item_rejected(
                namespace=cfg.namespace, kind="resource", reason="uri_without_scheme"
            )
            continue
        rbac_name = f"{cfg.namespace}_{name}"
        title = getattr(resource, "title", None)
        description = getattr(resource, "description", None) or ""
        mime_type = getattr(resource, "mime_type", None)
        specs[uri] = UpstreamResourceSpec(
            uri=uri,
            published_uri=published,
            name=name,
            rbac_name=rbac_name,
            fingerprint=resource_fingerprint(
                uri=uri,
                name=name,
                title=title,
                description=description,
                mime_type=mime_type,
            ),
        )
    return specs


def build_upstream_template_specs(
    cfg: UpstreamConfig,
    templates: Iterable[Any],
) -> dict[str, UpstreamTemplateSpec]:
    """Map upstream template URI templates to specs (tool filters do not apply)."""
    specs: dict[str, UpstreamTemplateSpec] = {}
    for template in templates:
        uri_template = template.uri_template
        name = template.name
        published = namespaced_uri(cfg.namespace, uri_template)
        if published is None:
            logger.warning(
                "upstream %s refused namespace=%s name=%s: URI %r has no scheme:// part, "
                "so it cannot be namespaced",
                "template",
                cfg.namespace,
                name,
                uri_template,
            )
            record_upstream_item_rejected(
                namespace=cfg.namespace, kind="template", reason="uri_without_scheme"
            )
            continue
        rbac_name = f"{cfg.namespace}_{name}"
        title = getattr(template, "title", None)
        description = getattr(template, "description", None) or ""
        mime_type = getattr(template, "mime_type", None)
        specs[uri_template] = UpstreamTemplateSpec(
            uri_template=uri_template,
            published_uri_template=published,
            name=name,
            rbac_name=rbac_name,
            fingerprint=template_fingerprint(
                uri_template=uri_template,
                name=name,
                title=title,
                description=description,
                mime_type=mime_type,
            ),
        )
    return specs


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
    transport: Literal["http", "stdio"] = "http"
    command: str | None = None
    args: tuple[str, ...] = ()
    env_from: tuple[tuple[str, str], ...] = ()
    cwd: str | None = None


@dataclass(frozen=True, slots=True)
class UpstreamCatalogRead:
    """One read of an upstream's catalog. ``None`` means unread, never empty."""

    tools: list[Any]
    prompts: list[Any] | None
    resources: list[Any] | None
    templates: list[Any] | None


@dataclass
class UpstreamRegistry:
    """Manages mounted upstream MCP APIs and auto-generated proxy routes."""

    main_mcp: FastMCP
    registry: "RouterRegistry"
    content: UpstreamContentCatalog = field(default_factory=UpstreamContentCatalog)
    tool_timeout_seconds: float = 180.0
    discovery_timeout_seconds: float = 10.0
    tool_timeout_overrides: dict[str, float] = field(default_factory=dict)
    upstream_max_response_bytes: int = DEFAULT_UPSTREAM_MAX_RESPONSE_BYTES
    upstream_max_schema_bytes: int = DEFAULT_UPSTREAM_MAX_SCHEMA_BYTES
    upstream_max_catalog_items: int = DEFAULT_UPSTREAM_MAX_CATALOG_ITEMS
    # false (default): proxied answers pass through as-is. true: wrap them in
    # the 0.3.x {state, tool, task_id, result} envelope (KEYSTONE_MCP_PROXY_STATUS_ENVELOPE).
    status_envelope: bool = False
    proxy_elicitation: bool = True
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
    # ``iss`` claim for every identity assertion signed by any upstream
    # registered here (Y01) -- set by ``build_server`` from
    # ``settings.base_url`` (already stripped of a trailing slash).
    identity_issuer: str = ""
    rbac_mode: str = "off"
    # Deployment-wide ES256 signing key (Y11); never logged or repr'd.
    _identity_signing_key_pem: str = field(default="", repr=False)
    _identity_es256_private_key: Any = field(default=None, repr=False)
    _identity_es256_kid: str | None = field(default=None, repr=False)
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
    _connections: dict[str, UpstreamConnection] = field(default_factory=dict, repr=False)
    _legacy_prompt_warnings_logged: set[str] = field(default_factory=set, repr=False)
    _namespace_up_hook: Callable[[str], None] | None = field(default=None, repr=False)
    _stdio_discovery_tasks: dict[str, asyncio.Task[None]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        pem = self._identity_signing_key_pem.strip()
        if pem:
            private_key = load_ec_p256_private_key(pem)
            self._identity_es256_private_key = private_key
            self._identity_es256_kid = ec_public_key_jwk_thumbprint(private_key.public_key())
        if self.http_client_factory is None:
            max_bytes = self.upstream_max_response_bytes

            def _default_http_factory(timeout: float) -> McpHttpClientFactory:
                return _http_client_factory(timeout, max_response_bytes=max_bytes)

            self.http_client_factory = _default_http_factory

    def _catalog_list_kwargs(self, cfg: UpstreamConfig, discovery_timeout: float) -> dict[str, Any]:
        return {
            "timeout_seconds": discovery_timeout,
            "max_items": self.upstream_max_catalog_items,
            "namespace": cfg.namespace,
        }

    def _discovery_http_client_factory(self, discovery_timeout: float) -> "McpHttpClientFactory":
        return self.http_client_factory(discovery_timeout)  # type: ignore[union-attr]

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
        identity_secret_env: str | None = None,
        identity_alg: Literal["ES256"] | None = None,
        transport: Literal["http", "stdio"] = "http",
        command: str | None = None,
        args: tuple[str, ...] = (),
        env_from: tuple[tuple[str, str], ...] = (),
        cwd: str | None = None,
    ) -> UpstreamConfig:
        """Register an upstream MCP API and mount its namespace sub-server.

        ``bearer_env`` names an environment variable holding a bearer token
        Keystone sends to this upstream (``Authorization: Bearer <value>``) on
        discovery and every proxied call. The token itself is read here and
        kept only in ``_auth_headers``; neither ``UpstreamConfig`` nor any
        other field on this registry ever holds it, so logging or repr'ing
        the registry cannot leak it. A missing or empty variable refuses
        startup with a ``ValueError`` naming the variable, never its value.

        ``identity_secret_env`` names an environment variable holding this
        upstream's identity-assertion secret (``auth.identity_secret_env``,
        Y01): when set, every proxied call carries a signed
        ``X-Keystone-Identity`` JWT (``aud`` = *name*) alongside
        ``X-Author-Email``. Re-validated and re-read here (never trusted from
        an earlier parse), and kept only inside the
        :class:`~keystone_mcp.identity_assertion.IdentityAssertionSigner`
        handed to this namespace's adapter — never on this registry or on
        ``UpstreamConfig``.
        """
        if namespace in self._sub_servers:
            raise ValueError(f"upstream namespace already registered: {namespace}")

        if transport == "stdio" and bearer_env is not None:
            raise ValueError(
                f"upstream {name!r}: auth.bearer_env is not supported with transport: stdio"
            )

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

        identity_signer: IdentityAssertionSigner | None = None
        if identity_alg == "ES256":
            private_key = self._identity_es256_private_key
            kid = self._identity_es256_kid
            if private_key is None or kid is None:
                raise ValueError(
                    f"upstream {name!r}: auth.identity_alg ES256 needs "
                    "KEYSTONE_MCP_IDENTITY_SIGNING_KEY"
                )
            identity_signer = IdentityAssertionSigner(
                audience=name,
                issuer=self.identity_issuer,
                private_key=private_key,
                kid=kid,
            )
        elif identity_secret_env is not None:
            secret = resolve_identity_secret(name, identity_secret_env)
            identity_signer = IdentityAssertionSigner(
                audience=name,
                secret=secret,
                issuer=self.identity_issuer,
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
            transport=transport,
            command=command,
            args=args,
            env_from=env_from,
            cwd=cwd,
        )
        self._upstreams.append(cfg)

        sub = FastMCP(name=namespace)
        self.main_mcp.mount(sub, namespace=namespace)
        self._sub_servers[namespace] = sub
        resolved_tool_timeout = (
            tool_timeout_seconds if tool_timeout_seconds is not None else self.tool_timeout_seconds
        )
        discovery_timeout = (
            discovery_timeout_seconds
            if discovery_timeout_seconds is not None
            else self.discovery_timeout_seconds
        )
        if transport == "stdio":
            if not command:
                raise ValueError(f"upstream {name!r}: command is required for transport: stdio")
            child_env = resolve_stdio_child_env(env_from)
            process = StdioUpstreamProcess(
                namespace=namespace,
                command=command,
                args=args,
                env=child_env,
                cwd=cwd,
                init_timeout=discovery_timeout,
                on_state=self._on_process_state(namespace),
            )
            connection: UpstreamConnection = StdioUpstreamConnection(namespace, process)
            logger.info(
                "mounted upstream namespace=%s transport=stdio command=%s",
                namespace,
                Path(command).name,
            )
        else:
            connection = HttpUpstreamConnection(
                namespace,
                resolved_url,
                auth_headers=self._auth_headers.get(namespace),
                http_client_factory=self.http_client_factory,
            )
            logger.info(
                "mounted upstream namespace=%s host=%s",
                namespace,
                upstream_host_for_log(cfg.url),
            )
        self._connections[namespace] = connection
        self._adapters[namespace] = McpProxyAdapter(
            connection,
            tool_timeout_seconds=resolved_tool_timeout,
            tool_timeout_overrides=self.tool_timeout_overrides,
            http_client_factory=self.http_client_factory,
            status_envelope=self.status_envelope,
            proxy_elicitation=self.proxy_elicitation,
            extra_headers=self._auth_headers.get(namespace),
            identity_signer=identity_signer,
            max_response_bytes=self.upstream_max_response_bytes,
        )
        self._status[namespace] = UpstreamStatus(
            available=False, catalog_known=False, last_error="not discovered yet"
        )
        if self.observability is not None:
            self.observability.record_upstream_available(namespace=namespace, available=False)
        return cfg

    def connection(self, namespace: str) -> UpstreamConnection:
        try:
            return self._connections[namespace]
        except KeyError:
            raise KeyError(f"unknown upstream namespace: {namespace}") from None

    def set_namespace_up_hook(self, hook: Callable[[str], None] | None) -> None:
        """Register a callback when a stdio process reaches ``running``."""
        self._namespace_up_hook = hook

    def _invoke_namespace_up_hook(self, namespace: str) -> None:
        if self._namespace_up_hook is not None:
            self._namespace_up_hook(namespace)

    def _schedule_stdio_discovery(self, namespace: str) -> None:
        cfg = next((c for c in self._upstreams if c.namespace == namespace), None)
        if cfg is None or cfg.transport != "stdio":
            return
        existing = self._stdio_discovery_tasks.get(namespace)
        if existing is not None and not existing.done():
            return

        async def _run() -> None:
            try:
                await self._discover_with_retries(cfg)
            finally:
                self._stdio_discovery_tasks.pop(namespace, None)

        self._stdio_discovery_tasks[namespace] = asyncio.create_task(_run())

    def _on_process_state(self, namespace: str) -> Callable[[str, str | None], None]:
        def _callback(state: str, reason: str | None) -> None:
            if state == "running":
                status = self._status.get(namespace)
                if status is not None and status.catalog_known:
                    self.mark_available(namespace)
                self._invoke_namespace_up_hook(namespace)
            elif state == "stopping":
                self.mark_unavailable(namespace, reason or "process stopping")
            elif state == "backoff":
                self.mark_unavailable(namespace, reason or "process down")
                if self.observability is not None:
                    self.observability.record_upstream_process_restart(namespace=namespace)

        return _callback

    async def start_connections(self, *, wait: float | None = None) -> None:
        if self._namespace_up_hook is None and not self.refresh_enabled:
            self.set_namespace_up_hook(self._schedule_stdio_discovery)

        async def _start_one(cfg: UpstreamConfig) -> tuple[str, bool, float]:
            conn = self._connections[cfg.namespace]
            assert isinstance(conn, StdioUpstreamConnection)
            discovery_wait = (
                wait
                if wait is not None
                else (
                    cfg.discovery_timeout_seconds
                    if cfg.discovery_timeout_seconds is not None
                    else self.discovery_timeout_seconds
                )
            )
            started = await conn.start(wait=discovery_wait)
            return cfg.namespace, started, discovery_wait

        stdio_cfgs = [cfg for cfg in self._upstreams if cfg.transport == "stdio"]
        if not stdio_cfgs:
            return
        results = await asyncio.gather(*(_start_one(cfg) for cfg in stdio_cfgs))
        for namespace, started, discovery_wait in results:
            if not started:
                logger.warning(
                    "stdio upstream process did not reach running within %ss namespace=%s",
                    discovery_wait,
                    namespace,
                )

    async def stop_connections(self) -> None:
        for cfg in self._upstreams:
            if cfg.transport != "stdio":
                continue
            await self._connections[cfg.namespace].stop()

    def upstream_readiness_snapshot(self) -> dict[str, dict[str, object]]:
        """Per-namespace transport, availability, and stdio process state for /readyz."""
        snapshot: dict[str, dict[str, object]] = {}
        for cfg in self._upstreams:
            status = self._status.get(cfg.namespace)
            available = status.available if status is not None else False
            process_state: str | None = None
            if cfg.transport == "stdio":
                conn = self._connections[cfg.namespace]
                if isinstance(conn, StdioUpstreamConnection):
                    process_state = conn.process.state
            snapshot[cfg.namespace] = {
                "transport": cfg.transport,
                "available": available,
                "process": process_state,
            }
        return snapshot

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

    def _tool_timeout_for(self, cfg: UpstreamConfig) -> float:
        if cfg.tool_timeout_seconds is not None:
            return cfg.tool_timeout_seconds
        return self.tool_timeout_seconds

    def _remove_prompt_proxy(self, sub: FastMCP, namespace: str, name: str) -> bool:
        try:
            sub.local_provider.remove_prompt(name)
        except KeyError:
            logger.warning(
                "upstream prompt proxy already gone namespace=%s name=%s",
                namespace,
                name,
            )
            return False
        return True

    def _remove_resource_proxy(
        self, sub: FastMCP, namespace: str, spec: UpstreamResourceSpec
    ) -> bool:
        for uri in (spec.uri, normalize_resource_uri(spec.uri)):
            try:
                sub.local_provider.remove_resource(uri)
                return True
            except KeyError:
                continue
        logger.warning(
            "upstream resource proxy already gone namespace=%s uri=%s",
            namespace,
            spec.uri,
        )
        return False

    def _remove_template_proxy(
        self, sub: FastMCP, namespace: str, spec: UpstreamTemplateSpec
    ) -> bool:
        try:
            sub.local_provider.remove_template(spec.uri_template)
        except KeyError:
            logger.warning(
                "upstream template proxy already gone namespace=%s uri_template=%s",
                namespace,
                spec.uri_template,
            )
            return False
        return True

    def _note_legacy_prompt_rbac(
        self, cfg: UpstreamConfig, specs: dict[str, UpstreamPromptSpec]
    ) -> None:
        namespace = cfg.namespace
        legacy: set[str] = set()
        for spec in specs.values():
            stripped = resolve_mounted_tool_name(spec.name, cfg.strip_prefix)
            legacy_name = f"{namespace}_{stripped}"
            if legacy_name == spec.published_name:
                continue
            legacy.add(legacy_name)
            warn_key = f"{namespace}:{spec.name}"
            if warn_key in self._legacy_prompt_warnings_logged:
                continue
            self._legacy_prompt_warnings_logged.add(warn_key)
            logger.warning(
                "upstream prompt namespace=%s is published as %s; the name %s used by "
                "keystone-mcp 0.5.0 policy validation grants nothing",
                namespace,
                spec.published_name,
                legacy_name,
            )
        self.content.set_legacy_prompt_rbac_names(namespace, frozenset(legacy))

    async def read_catalog(self, cfg: UpstreamConfig) -> UpstreamCatalogRead:
        discovery_timeout = (
            cfg.discovery_timeout_seconds
            if cfg.discovery_timeout_seconds is not None
            else self.discovery_timeout_seconds
        )
        prompts_raw: list[Any] | None = []
        resources_raw: list[Any] | None = []
        templates_raw: list[Any] | None = []

        if cfg.transport == "stdio":
            conn = self._connections[cfg.namespace]
            if isinstance(conn, StdioUpstreamConnection) and conn.process.state == "running":
                client = conn.catalog_client(timeout=discovery_timeout)
                list_kw = self._catalog_list_kwargs(cfg, discovery_timeout)
                async with client:
                    tools = await list_upstream_tools(client, **list_kw)
                    try:
                        prompts_raw = await list_upstream_prompts(client, **list_kw)
                    except UpstreamListToolsError as exc:
                        logger.warning(
                            "upstream prompts refresh failed namespace=%s: %s; "
                            "keeping previous prompts",
                            cfg.namespace,
                            exc,
                        )
                        prompts_raw = None
                    try:
                        resources_raw = await list_upstream_resources(client, **list_kw)
                        templates_raw = await list_upstream_resource_templates(client, **list_kw)
                    except UpstreamListToolsError as exc:
                        logger.warning(
                            "upstream resources refresh failed namespace=%s: %s; "
                            "keeping previous resources",
                            cfg.namespace,
                            exc,
                        )
                        resources_raw = None
                        templates_raw = None
            else:
                self.mark_unavailable(cfg.namespace, "process not running")
                raise UpstreamProcessUnavailableError(
                    f"stdio upstream {cfg.namespace!r} process not running"
                )
        else:
            list_kw = self._catalog_list_kwargs(cfg, discovery_timeout)
            fetch_kw = {
                **list_kw,
                "httpx_client_factory": self._discovery_http_client_factory(discovery_timeout),
                "headers": self.upstream_headers(cfg.namespace),
            }
            tools = await fetch_upstream_tools(cfg.url, **fetch_kw)
            try:
                prompts_raw = await fetch_upstream_prompts(cfg.url, **fetch_kw)
            except UpstreamListToolsError as exc:
                logger.warning(
                    "upstream prompts refresh failed namespace=%s: %s; keeping previous prompts",
                    cfg.namespace,
                    exc,
                )
                prompts_raw = None
            try:
                resources_raw, templates_raw = await self._list_resources_for_config(
                    cfg, discovery_timeout
                )
            except UpstreamListToolsError as exc:
                logger.warning(
                    "upstream resources refresh failed namespace=%s: %s; keeping previous resources",
                    cfg.namespace,
                    exc,
                )
                resources_raw = None
                templates_raw = None

        return UpstreamCatalogRead(
            tools=tools,
            prompts=prompts_raw,
            resources=resources_raw,
            templates=templates_raw,
        )

    async def _list_prompts_for_config(
        self,
        cfg: UpstreamConfig,
        discovery_timeout: float,
        *,
        catalog_client: Client | None = None,
    ) -> list[Any]:
        list_kw = self._catalog_list_kwargs(cfg, discovery_timeout)
        if catalog_client is not None:
            return await list_upstream_prompts(catalog_client, **list_kw)
        if cfg.transport == "stdio":
            conn = self._connections[cfg.namespace]
            if isinstance(conn, StdioUpstreamConnection) and conn.process.state == "running":
                client = conn.catalog_client(timeout=discovery_timeout)
                async with client:
                    return await list_upstream_prompts(client, **list_kw)
            raise UpstreamProcessUnavailableError(
                f"stdio upstream {cfg.namespace!r} process not running"
            )
        return await fetch_upstream_prompts(
            cfg.url,
            httpx_client_factory=self._discovery_http_client_factory(discovery_timeout),
            headers=self.upstream_headers(cfg.namespace),
            **list_kw,
        )

    def _apply_prompt_specs(
        self,
        cfg: UpstreamConfig,
        specs: dict[str, UpstreamPromptSpec],
        raw_prompts: dict[str, Any],
    ) -> bool:
        """Mount prompt proxies on the namespace sub-server; return whether anything changed."""
        namespace = cfg.namespace
        sub = self._sub_servers[namespace]
        adapter = self._adapters[namespace]
        previous = self.content.prompts(namespace)
        desired_fp = {name: spec.fingerprint for name, spec in specs.items()}
        previous_fp = {name: spec.fingerprint for name, spec in previous.items()}
        if desired_fp == previous_fp:
            return False

        changed = False
        prev_names = set(previous_fp)
        new_names = set(desired_fp)

        for prompt_name in sorted(prev_names - new_names):
            if self._remove_prompt_proxy(sub, namespace, prompt_name):
                changed = True

        tool_timeout = self._tool_timeout_for(cfg)
        for prompt_name in sorted(new_names):
            spec = specs[prompt_name]
            if prompt_name in prev_names and previous_fp.get(prompt_name) == spec.fingerprint:
                continue

            owner = self.content.owner_of_published_prompt(spec.published_name)
            owner_key = f"{namespace}:{spec.name}"
            if owner is not None and owner != owner_key:
                logger.error(
                    "upstream prompts refused namespace=%s prompt=%s: "
                    "published name %s already owned by %s",
                    namespace,
                    spec.name,
                    spec.published_name,
                    owner,
                )
                record_upstream_item_rejected(
                    namespace=namespace, kind="prompt", reason="name_collision"
                )
                continue

            if prompt_name in prev_names:
                self._remove_prompt_proxy(sub, namespace, prompt_name)

            mcp_prompt = raw_prompts[prompt_name]
            proxy = UpstreamProxyPrompt.from_upstream_prompt(
                registry=self,
                namespace=namespace,
                mcp_prompt=mcp_prompt,
                backend_name=spec.name,
                identity_signer=adapter._identity_signer,
                extra_headers=dict(self.upstream_headers(namespace)),
                tool_timeout=tool_timeout,
                rbac_mode=self.rbac_mode,
                transport=self.connection(namespace).transport,
            )
            sub.add_prompt(proxy)
            changed = True

        self._note_legacy_prompt_rbac(cfg, specs)
        self.content.set_prompts(namespace, specs)
        return changed

    async def _list_resources_for_config(
        self,
        cfg: UpstreamConfig,
        discovery_timeout: float,
        *,
        catalog_client: Client | None = None,
    ) -> tuple[list[Any], list[Any]]:
        list_kw = self._catalog_list_kwargs(cfg, discovery_timeout)
        if catalog_client is not None:
            resources = await list_upstream_resources(catalog_client, **list_kw)
            templates = await list_upstream_resource_templates(catalog_client, **list_kw)
            return resources, templates
        if cfg.transport == "stdio":
            conn = self._connections[cfg.namespace]
            if isinstance(conn, StdioUpstreamConnection) and conn.process.state == "running":
                client = conn.catalog_client(timeout=discovery_timeout)
                async with client:
                    resources = await list_upstream_resources(client, **list_kw)
                    templates = await list_upstream_resource_templates(client, **list_kw)
                return resources, templates
            raise UpstreamProcessUnavailableError(
                f"stdio upstream {cfg.namespace!r} process not running"
            )
        fetch_kw = {
            **list_kw,
            "httpx_client_factory": self._discovery_http_client_factory(discovery_timeout),
            "headers": self.upstream_headers(cfg.namespace),
        }
        resources = await fetch_upstream_resources(cfg.url, **fetch_kw)
        templates = await fetch_upstream_resource_templates(cfg.url, **fetch_kw)
        return resources, templates

    def _apply_resource_specs(
        self,
        cfg: UpstreamConfig,
        resource_specs: dict[str, UpstreamResourceSpec],
        template_specs: dict[str, UpstreamTemplateSpec],
        raw_resources: dict[str, Any],
        raw_templates: dict[str, Any],
    ) -> bool:
        namespace = cfg.namespace
        sub = self._sub_servers[namespace]
        adapter = self._adapters[namespace]
        previous_resources = self.content.resources(namespace)
        previous_templates = self.content.templates(namespace)
        desired_res = {uri: spec.fingerprint for uri, spec in resource_specs.items()}
        desired_tpl = {ut: spec.fingerprint for ut, spec in template_specs.items()}
        prev_res = {uri: spec.fingerprint for uri, spec in previous_resources.items()}
        prev_tpl = {ut: spec.fingerprint for ut, spec in previous_templates.items()}
        if desired_res == prev_res and desired_tpl == prev_tpl:
            return False

        changed = False
        tool_timeout = self._tool_timeout_for(cfg)

        for uri in sorted(set(prev_res) - set(desired_res)):
            spec = previous_resources[uri]
            if self._remove_resource_proxy(sub, namespace, spec):
                changed = True

        for uri_template in sorted(set(prev_tpl) - set(desired_tpl)):
            spec = previous_templates[uri_template]
            if self._remove_template_proxy(sub, namespace, spec):
                changed = True

        for uri in sorted(desired_res):
            spec = resource_specs[uri]
            if uri in prev_res and prev_res[uri] == spec.fingerprint:
                continue
            owner = self.content.owner_of_resource_rbac(spec.rbac_name)
            owner_key = f"{namespace}:{spec.uri}"
            if owner is not None and owner != owner_key:
                logger.error(
                    "upstream resources refused namespace=%s resource=%s: "
                    "rbac name %s already owned by %s",
                    namespace,
                    spec.name,
                    spec.rbac_name,
                    owner,
                )
                record_upstream_item_rejected(
                    namespace=namespace, kind="resource", reason="name_collision"
                )
                continue
            if uri in prev_res:
                self._remove_resource_proxy(sub, namespace, spec)
            mcp_resource = raw_resources[uri]
            proxy = UpstreamProxyResource.from_upstream_resource(
                registry=self,
                namespace=namespace,
                upstream_name=cfg.name,
                mcp_resource=mcp_resource,
                backend_uri=spec.uri,
                identity_signer=adapter._identity_signer,
                extra_headers=dict(self.upstream_headers(namespace)),
                tool_timeout=tool_timeout,
                rbac_mode=self.rbac_mode,
                transport=self.connection(namespace).transport,
            )
            sub.add_resource(proxy)
            changed = True

        for uri_template in sorted(desired_tpl):
            spec = template_specs[uri_template]
            if uri_template in prev_tpl and prev_tpl[uri_template] == spec.fingerprint:
                continue
            owner = self.content.owner_of_template_rbac(spec.rbac_name)
            owner_key = f"{namespace}:{spec.uri_template}"
            if owner is not None and owner != owner_key:
                logger.error(
                    "upstream templates refused namespace=%s template=%s: "
                    "rbac name %s already owned by %s",
                    namespace,
                    spec.name,
                    spec.rbac_name,
                    owner,
                )
                record_upstream_item_rejected(
                    namespace=namespace, kind="template", reason="name_collision"
                )
                continue
            if uri_template in prev_tpl:
                self._remove_template_proxy(sub, namespace, spec)
            mcp_template = raw_templates[uri_template]
            proxy = UpstreamProxyTemplate.from_upstream_template(
                registry=self,
                namespace=namespace,
                upstream_name=cfg.name,
                mcp_template=mcp_template,
                backend_uri_template=spec.uri_template,
                identity_signer=adapter._identity_signer,
                extra_headers=dict(self.upstream_headers(namespace)),
                tool_timeout=tool_timeout,
                rbac_mode=self.rbac_mode,
                transport=self.connection(namespace).transport,
            )
            sub.add_template(proxy)
            changed = True

        self.content.set_resources(namespace, resource_specs)
        self.content.set_templates(namespace, template_specs)
        return changed

    async def _discover_one(self, cfg: UpstreamConfig) -> int:
        if cfg.mode != "proxy_1to1":
            raise ValueError(f"unsupported upstream mode: {cfg.mode}")

        sub = self._sub_servers[cfg.namespace]
        adapter = self._adapters[cfg.namespace]
        registered = 0

        catalog = await self.read_catalog(cfg)
        tools = catalog.tools
        prompts_raw = catalog.prompts
        resources_raw = catalog.resources
        templates_raw = catalog.templates
        specs, schema_rejected = build_upstream_tool_specs(
            cfg,
            tools,
            schema_patches=self.schema_patches,
            max_schema_bytes=self.upstream_max_schema_bytes,
        )
        for route_name in schema_rejected:
            self.mark_unpublishable(cfg.namespace, route_name)
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
                record_upstream_item_rejected(
                    namespace=cfg.namespace, kind="tool", reason="name_collision"
                )
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
                record_upstream_item_rejected(
                    namespace=cfg.namespace, kind="tool", reason="unpublishable_schema"
                )
                self.mark_unpublishable(cfg.namespace, spec.route_name)
                continue
            self.clear_unpublishable(cfg.namespace, spec.route_name)
            registered += 1

        if prompts_raw is not None:
            prompt_specs = build_upstream_prompt_specs(cfg, prompts_raw)
            raw_by_name = {p.name: p for p in prompts_raw}
            self._apply_prompt_specs(cfg, prompt_specs, raw_by_name)

        if resources_raw is not None and templates_raw is not None:
            resource_specs = build_upstream_resource_specs(cfg, resources_raw)
            template_specs = build_upstream_template_specs(cfg, templates_raw)
            raw_resources = {str(r.uri): r for r in resources_raw}
            raw_templates = {t.uri_template: t for t in templates_raw}
            self._apply_resource_specs(
                cfg, resource_specs, template_specs, raw_resources, raw_templates
            )

        logger.info(
            "discovered upstream=%s namespace=%s tools=%d",
            cfg.name,
            cfg.namespace,
            registered,
        )
        return registered
