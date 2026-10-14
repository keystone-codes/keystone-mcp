"""Subprocess entrypoint: keystone-mcp HTTP server with a route that raises."""

from __future__ import annotations

from keystone_mcp import server

_original_build_server = server.build_server


def _build_server_with_boom(*args, **kwargs):
    mcp, registry, oauth, upstreams, policy_manager, observability, reconciler = (
        _original_build_server(*args, **kwargs)
    )

    @mcp.custom_route("/__boom", methods=["GET"])
    async def _boom(_request):  # noqa: ANN001
        raise RuntimeError("boom for stderr NDJSON test")

    return mcp, registry, oauth, upstreams, policy_manager, observability, reconciler


server.build_server = _build_server_with_boom

if __name__ == "__main__":
    server.main()
