"""Canonicalize resource URIs for provider lookup after client-side normalization."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastmcp.server.middleware import Middleware, MiddlewareContext

if TYPE_CHECKING:
    from mcp.types import ReadResourceRequestParams

    from keystone_mcp.router.upstream_content import UpstreamContentCatalog


class UpstreamResourceUriMiddleware(Middleware):
    """Rewrite ``resources/read`` URIs to the catalog's published form."""

    def __init__(self, catalog: UpstreamContentCatalog) -> None:
        self._catalog = catalog

    async def on_read_resource(
        self,
        context: MiddlewareContext[ReadResourceRequestParams],
        call_next,
    ):
        published = self._catalog.resolve_published_uri(str(context.message.uri))
        context.message.uri = published
        return await call_next(context)
