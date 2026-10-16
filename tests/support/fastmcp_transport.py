"""Streamable HTTP transport helpers for in-process MCP tests.

fastmcp 4 builds ``BearerAuth`` for ``httpx2``; factories must return
``httpx2.AsyncClient`` (see ``tests/test_fastmcp_boundary.py``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx2
from fastmcp.client.transports import StreamableHttpTransport
from httpx2 import ASGITransport, AsyncClient

from support.oauth_harness import BASE_URL


def asgi_mcp_http_client_factory(
    app: object,
    *,
    base_url: str = BASE_URL,
    follow_redirects: bool = True,
) -> Callable[..., httpx2.AsyncClient]:
    def factory(
        headers: dict[str, str] | None = None,
        timeout: Any = None,
        auth: Any = None,
        **_kw: Any,
    ) -> httpx2.AsyncClient:
        return AsyncClient(
            transport=ASGITransport(app=app),
            base_url=base_url,
            headers=headers,
            timeout=timeout or httpx2.Timeout(30.0),
            auth=auth,
            follow_redirects=follow_redirects,
        )

    return factory


def streamable_http_transport_to_app(
    app: object,
    transport_url: str,
    token: str,
    *,
    base_url: str = BASE_URL,
) -> StreamableHttpTransport:
    return StreamableHttpTransport(
        transport_url,
        auth=token,
        httpx_client_factory=asgi_mcp_http_client_factory(app, base_url=base_url),
    )
