"""Pins the httpx2 boundary ``McpProxyAdapter`` builds for fastmcp's transport.

fastmcp 4's ``StreamableHttpTransport`` hands its HTTP client factory an
``auth`` object built for ``httpx2`` (``fastmcp.client.auth.bearer.BearerAuth``),
which an ``httpx.AsyncClient`` rejects with ``TypeError: Invalid "auth"
argument`` -- the single biggest break found migrating off fastmcp 3.4.4 (see
``internal/tasks-0.5.0/X-extensibility/X01-spike-report.md``). This guards
against a regression back to ``httpx``.
"""

from __future__ import annotations

import httpx2

from keystone_mcp.adapters.mcp_proxy import _http_client_factory


def test_proxy_http_factory_builds_httpx2_client():
    client = _http_client_factory(5.0)(headers=None, timeout=None, auth=None)

    assert isinstance(client, httpx2.AsyncClient)
    assert client.timeout.read == 5.0
    assert client.timeout.connect == 5.0
