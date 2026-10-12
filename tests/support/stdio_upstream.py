"""A stdio MCP upstream for tests of :mod:`keystone_mcp.router.stdio_process`.

Built on the low-level ``mcp`` SDK only (no FastMCP), served over stdio via
``mcp.server.stdio.stdio_server``. Run directly as a subprocess:

    python tests/support/stdio_upstream.py

Tools:

- ``pid`` — this process's PID, so a test can tell a restarted child from the
  one it replaced.
- ``env`` — arg ``name``; that environment variable's value, or ``"<unset>"``.
  Used to prove the child receives only the variables
  :class:`~keystone_mcp.router.stdio_process.StdioUpstreamProcess` maps in,
  never Keystone's own environment.
- ``greet`` — arg ``name``; a friendly string, for a plain happy-path call.
- ``stderr`` — writes one line to stderr and returns, to exercise the
  supervisor's stderr-to-log bridge.
- ``crash`` — exits the process immediately (``os._exit``), before a response
  is written, to exercise restart-on-crash.
- ``meta`` — returns JSON of the request ``_meta`` dict (for identity assertion).
- ``count`` — counts to ``n`` with progress notifications when a token is set.
- ``slow`` — sleeps; on cancel writes ``slow-cancelled`` to stderr.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import anyio
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

_EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}

_NAME_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"name": {"type": "string"}},
    "required": ["name"],
}

_TOOL_DEFINITIONS: dict[str, types.Tool] = {
    "pid": types.Tool(
        name="pid",
        description="This process's PID.",
        inputSchema=_EMPTY_SCHEMA,
    ),
    "env": types.Tool(
        name="env",
        description="The named environment variable's value, or '<unset>'.",
        inputSchema=_NAME_SCHEMA,
    ),
    "greet": types.Tool(
        name="greet",
        description="Greet someone by name.",
        inputSchema=_NAME_SCHEMA,
    ),
    "stderr": types.Tool(
        name="stderr",
        description="Write one line to stderr.",
        inputSchema=_EMPTY_SCHEMA,
    ),
    "crash": types.Tool(
        name="crash",
        description="Exit the process immediately, before answering.",
        inputSchema=_EMPTY_SCHEMA,
    ),
    "meta": types.Tool(
        name="meta",
        description="Echo the call request _meta as JSON.",
        inputSchema=_EMPTY_SCHEMA,
    ),
    "count": types.Tool(
        name="count",
        description="Count up to n, reporting progress along the way.",
        inputSchema={
            "type": "object",
            "properties": {"n": {"type": "integer", "default": 3}},
        },
    ),
    "slow": types.Tool(
        name="slow",
        description="Sleep for a long time; used to exercise cancellation.",
        inputSchema={
            "type": "object",
            "properties": {"seconds": {"type": "number", "default": 30}},
        },
    ),
}

_TOOL_ORDER: tuple[str, ...] = (
    "pid",
    "env",
    "greet",
    "stderr",
    "crash",
    "meta",
    "count",
    "slow",
)


async def _on_list_tools(_ctx: Any, _params: Any) -> types.ListToolsResult:
    return types.ListToolsResult(tools=[_TOOL_DEFINITIONS[name] for name in _TOOL_ORDER])


async def _run_tool(
    ctx: Any,
    name: str,
    arguments: dict[str, Any],
    *,
    call_meta: Any = None,
) -> list[types.ContentBlock]:
    if name == "pid":
        return [types.TextContent(type="text", text=str(os.getpid()))]

    if name == "env":
        value = os.environ.get(arguments["name"], "<unset>")
        return [types.TextContent(type="text", text=value)]

    if name == "greet":
        return [types.TextContent(type="text", text=f"Hello, {arguments['name']}!")]

    if name == "stderr":
        print("hello-from-stderr", file=sys.stderr, flush=True)
        return [types.TextContent(type="text", text="ok")]

    if name == "crash":
        sys.stderr.flush()
        sys.stdout.flush()
        os._exit(3)

    if name == "meta":
        payload: dict[str, Any] = {}
        if call_meta is not None:
            if hasattr(call_meta, "model_dump"):
                payload = call_meta.model_dump(by_alias=True)
            elif isinstance(call_meta, dict):
                payload = call_meta
        return [types.TextContent(type="text", text=json.dumps(payload))]

    if name == "count":
        n = int(arguments.get("n", 3))
        token = None
        for source in (call_meta, ctx.meta):
            if source is None:
                continue
            if isinstance(source, dict):
                token = source.get("progressToken") or source.get("progress_token")
            else:
                token = getattr(source, "progress_token", None) or getattr(
                    source, "progressToken", None
                )
            if token is not None:
                break
        if token is not None:
            for i in range(1, n + 1):
                await ctx.session.report_progress(i, n, f"step {i}")
        return [types.TextContent(type="text", text=f"counted to {n}")]

    if name == "slow":
        try:
            await anyio.sleep(float(arguments.get("seconds", 30)))
        except anyio.get_cancelled_exc_class():
            print("slow-cancelled", file=sys.stderr, flush=True)
            raise
        return [types.TextContent(type="text", text="slow done")]

    raise ValueError(f"unknown tool: {name}")


async def _on_call_tool(ctx: Any, params: types.CallToolRequestParams) -> types.CallToolResult:
    try:
        content = await _run_tool(
            ctx,
            params.name,
            params.arguments or {},
            call_meta=getattr(params, "meta", None) or getattr(params, "_meta", None),
        )
    except Exception as exc:  # noqa: BLE001 — turn any failure into an error result
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=str(exc))],
            is_error=True,
        )
    return types.CallToolResult(content=content)


async def main() -> None:
    server: Server = Server(
        "stdio-upstream",
        on_list_tools=_on_list_tools,
        on_call_tool=_on_call_tool,
    )
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(main)
