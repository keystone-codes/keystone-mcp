# 0010 — Why Keystone runs on fastmcp 4

## Status

Accepted (Keystone-MCP 0.5.0)

## Context

Keystone-MCP is built on FastMCP and the official MCP Python SDK. Release 0.4.x
pinned fastmcp 3.4.x and MCP SDK 1.28.x. fastmcp 4.x ships with MCP SDK 2.x,
different HTTP client expectations, and protocol-era changes that affect proxy,
OAuth record types, and test harnesses.

## Decision

We upgraded to **fastmcp 4.1** with **MCP SDK 2.x** (`pyproject.toml`:
`fastmcp>=4.1.0,<5`, `mcp>=2.0,<3`, direct `httpx2` for FastMCP client
transports). Dependabot is configured to ignore major bumps of `fastmcp` and
`mcp`; those upgrades stay planned work.

A one-day spike on the 0.5.0 branch measured the migration cost. After bumping
lockfile versions, the suite reported 19 failures and 6 collection errors from
**two** root causes only:

1. **HTTP client boundary** — FastMCP 4 passes `BearerAuth` objects meant for
   `httpx2` into client factories that still built `httpx.AsyncClient`. Keystone's
   proxy and test factories were switched to `httpx2` without changing their
   public signatures.
2. **Low-level test upstream** — MCP SDK v2's `mcp.server.lowlevel.Server` takes
   `on_list_tools` / `on_call_tool` handlers in the constructor instead of
   decorators; the shared test upstream was rewritten accordingly.

With those fixes, the full suite returned to the same pass count as on 3.4.4
before other 0.5.0 features landed. Remaining camelCase field access in
`router/upstream.py` still works via FastMCP's compatibility bridge but should
move to snake_case names to avoid deprecation warnings in CI.

Staying on fastmcp 3.4.x behind a single `framework.py` facade was considered;
it would defer SDK 2 protocol work and duplicate maintenance. The spike showed
the 4.x migration fit within roughly two weeks of focused engineering, so we
migrated now rather than isolating imports.

## Consequences

Keystone rides FastMCP 4's MCP 2026-07-28 behaviour (subscriptions for
`list_changed`, elicitation constraints, cancellation semantics). Cards and docs
for protocol features must name the era they target.

Contributors need `httpx2` anywhere they construct a FastMCP HTTP client used by
Keystone's proxy or OAuth tests.

## Alternatives considered

**Remain on fastmcp 3.4.8** — Lower immediate churn, but every new FastMCP
import would need a shim and SDK 2 features would stay out of reach; not chosen
after the spike.

**Big-bang rewrite of the proxy** — Unnecessary; two localized fixes restored
the test baseline.

## Links

- [CONTRIBUTING.md](../CONTRIBUTING.md#dependencies)
- `pyproject.toml`, `src/keystone_mcp/adapters/mcp_proxy.py`,
  `tests/support/lowlevel_upstream.py`

## Amendment (0.6.0)

The migration to snake_case field names on FastMCP upstream objects is complete;
`pyproject.toml` sets `filterwarnings = error::fastmcp.exceptions.FastMCPDeprecationWarning`
so CI fails on regressions.
