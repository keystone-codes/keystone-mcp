"""Transport-specific MCP client factories for upstream proxy and discovery."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Literal, Protocol

from fastmcp import Client
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport

from keystone_mcp.router.stdio_process import StdioUpstreamProcess

if TYPE_CHECKING:
    from keystone_mcp.adapters.mcp_proxy import ClientFactory, HttpClientFactoryBuilder


class UpstreamConnection(Protocol):
    namespace: str
    transport: Literal["http", "stdio"]

    def call_client(self, *, headers: Mapping[str, str], timeout: float) -> Client: ...

    def catalog_client(self, *, timeout: float) -> Client: ...

    async def start(self, *, wait: float) -> None: ...

    async def stop(self) -> None: ...


class HttpUpstreamConnection:
    """Streamable HTTP upstream; each call opens a fresh client session."""

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

    def _build_client(self, headers: Mapping[str, str], timeout: float) -> Client:
        merged = {**self._auth_headers, **headers}
        if self._client_factory is not None:
            return self._client_factory(headers=merged, timeout=timeout)
        from keystone_mcp.adapters.mcp_proxy import _http_client_factory

        factory = self._http_client_factory or _http_client_factory
        return Client(
            StreamableHttpTransport(
                self._url,
                headers=merged,
                httpx_client_factory=factory(timeout),
            ),
            timeout=timeout,
        )

    def call_client(self, *, headers: Mapping[str, str], timeout: float) -> Client:
        return self._build_client(headers, timeout)

    def catalog_client(self, *, timeout: float) -> Client:
        return self._build_client({}, timeout)

    async def start(self, *, wait: float) -> None:
        return None

    async def stop(self) -> None:
        return None


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

    async def start(self, *, wait: float) -> None:
        await self._process.start(wait=wait)

    async def stop(self) -> None:
        await self._process.stop()


def temporary_stdio_client(
    *,
    command: str,
    args: Sequence[str],
    env: Mapping[str, str],
    cwd: str | None,
    init_timeout: float,
) -> Client:
    """Client for one-shot bootstrap discovery (``keep_alive=False``)."""
    transport = StdioTransport(
        command,
        list(args),
        env=dict(env),
        cwd=cwd,
        keep_alive=False,
    )
    return Client(transport, init_timeout=init_timeout, mode="legacy")
