"""Transport-specific MCP client factories for upstream proxy and discovery."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, Literal, Protocol

import httpx2
from fastmcp import Client
from fastmcp.client.client import ConnectMode
from fastmcp.client.transports import StreamableHttpTransport
from mcp.server.connection import MODERN_PROTOCOL_VERSIONS
from mcp.shared.exceptions import MCPError
from mcp.types import DiscoverResult

from keystone_mcp.router.stdio_process import StdioUpstreamProcess

if TYPE_CHECKING:
    from keystone_mcp.adapters.mcp_proxy import ClientFactory, HttpClientFactoryBuilder

logger = logging.getLogger(__name__)

_STALE_ERA_MCP_CODES = frozenset({-32600, -32601, -32602})


def _response_body_looks_like_mcp_error(response: httpx2.Response) -> bool:
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001
        return False
    if not isinstance(payload, dict):
        return False
    return "error" in payload and isinstance(payload.get("error"), dict)


def is_pinned_era_failure(exc: BaseException) -> bool:
    """True when a pinned-era call likely failed because the era is wrong."""
    if isinstance(exc, MCPError):
        return exc.error.code in _STALE_ERA_MCP_CODES
    if isinstance(exc, httpx2.HTTPStatusError):
        return exc.response.status_code in (400, 404, 405)
    return False


def is_safe_era_transport_retry(exc: BaseException) -> bool:
    """True when nothing clearly reached the upstream as a successful MCP exchange."""
    if isinstance(exc, (httpx2.ConnectError, httpx2.TimeoutException)):
        return True
    if isinstance(exc, httpx2.HTTPStatusError):
        if exc.response.status_code in (400, 404, 405):
            return not _response_body_looks_like_mcp_error(exc.response)
    return False


class UpstreamConnection(Protocol):
    namespace: str
    transport: Literal["http", "stdio"]

    def call_client(self, *, headers: Mapping[str, str], timeout: float) -> Client: ...

    def catalog_client(self, *, timeout: float) -> Client: ...

    async def start(self, *, wait: float) -> bool: ...

    async def stop(self) -> None: ...


class HttpUpstreamConnection:
    """Streamable HTTP upstream; reuses TCP/TLS per namespace, pins protocol era."""

    transport: Literal["http"] = "http"

    def __init__(
        self,
        namespace: str,
        url: str,
        *,
        auth_headers: Mapping[str, str] | None = None,
        http_client_factory: HttpClientFactoryBuilder | None = None,
        client_factory: ClientFactory | None = None,
    ) -> None:
        self.namespace = namespace
        self._url = url.rstrip("/")
        self._auth_headers = dict(auth_headers or {})
        self._http_client_factory = http_client_factory
        self._client_factory = client_factory
        self._mode: ConnectMode = "auto"
        self._prior_discover: DiscoverResult | None = None
        self._shared_transport: httpx2.AsyncHTTPTransport | None = None

    def remember_era(self, client: Client) -> None:
        previous = self._mode
        if client.protocol_version in MODERN_PROTOCOL_VERSIONS:
            self._mode = client.protocol_version
            self._prior_discover = client.session.discover_result
        else:
            self._mode = "legacy"
            self._prior_discover = None
        if previous != self._mode:
            logger.info("upstream namespace=%s era=%s", self.namespace, self._mode)
        else:
            logger.debug("upstream namespace=%s era=%s", self.namespace, self._mode)

    def prepare_stale_era_retry(self, exc: BaseException) -> bool:
        """Drop a pinned era after a protocol mismatch; retry once when safe."""
        if self._client_factory is not None or self._mode == "auto":
            return False
        if not is_pinned_era_failure(exc):
            return False
        self._mode = "auto"
        self._prior_discover = None
        return is_safe_era_transport_retry(exc)

    def _pool_transport(self) -> httpx2.AsyncHTTPTransport | None:
        if self._http_client_factory is not None:
            return None
        if self._shared_transport is None:
            self._shared_transport = httpx2.AsyncHTTPTransport()
        return self._shared_transport

    def _http_factory_for(self, timeout: float) -> Any:
        if self._http_client_factory is not None:
            return self._http_client_factory(timeout)
        from keystone_mcp.adapters.mcp_proxy import _http_client_factory

        shared = self._pool_transport()
        return _http_client_factory(timeout, shared_transport=shared)

    def _build_client(
        self,
        headers: Mapping[str, str],
        timeout: float,
        *,
        mode: ConnectMode,
        prior_discover: DiscoverResult | None,
        for_catalog: bool = False,
    ) -> Client:
        merged = {**self._auth_headers, **headers}
        if self._client_factory is not None and not for_catalog:
            return self._client_factory(headers=merged, timeout=timeout)
        factory = self._http_factory_for(timeout)
        return Client(
            StreamableHttpTransport(
                self._url,
                headers=merged,
                httpx_client_factory=factory,
            ),
            timeout=timeout,
            mode=mode,
            prior_discover=prior_discover,
        )

    def call_client(self, *, headers: Mapping[str, str], timeout: float) -> Client:
        if self._client_factory is not None:
            merged = {**self._auth_headers, **headers}
            return self._client_factory(headers=merged, timeout=timeout)
        return self._build_client(
            headers,
            timeout,
            mode=self._mode,
            prior_discover=self._prior_discover,
        )

    def catalog_client(self, *, timeout: float) -> Client:
        return self._build_client(
            {},
            timeout,
            mode="auto",
            prior_discover=None,
            for_catalog=True,
        )

    async def start(self, *, wait: float) -> bool:
        return True

    async def stop(self) -> None:
        if self._shared_transport is not None:
            await self._shared_transport.aclose()
            self._shared_transport = None


class StdioUpstreamConnection:
    """Supervised stdio child; one shared client while the process is running."""

    transport: Literal["stdio"] = "stdio"

    def __init__(self, namespace: str, process: StdioUpstreamProcess) -> None:
        self.namespace = namespace
        self._process = process

    @property
    def process(self) -> StdioUpstreamProcess:
        return self._process

    def call_client(self, *, headers: Mapping[str, str], timeout: float) -> Client:
        return self.catalog_client(timeout=timeout)

    def catalog_client(self, *, timeout: float) -> Client:
        return self._process.client()

    async def start(self, *, wait: float) -> bool:
        return await self._process.start(wait=wait)

    async def stop(self) -> None:
        await self._process.stop()
