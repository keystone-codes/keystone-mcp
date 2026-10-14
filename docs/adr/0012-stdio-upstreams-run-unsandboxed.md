# 0012 — A stdio upstream is trusted like Keystone itself

## Status

Accepted (Keystone-MCP 0.5.0)

## Context

Some MCP servers only speak stdio. Keystone must start them as child processes,
keep a session for discovery and proxying, and recover from crashes without
treating process health as global readiness (unless explicitly required).

## Decision

Registry entries with `transport: stdio` (`keystone_mcp.config.UpstreamConfig`)
run a local command under the **same OS user** as the Keystone process. The
child environment is not a copy of Keystone's entire environ: only variables
listed in the entry's `env` map are resolved from named parent variables and
passed through (values never appear in the registry file).

`StdioUpstreamProcess` (`keystone_mcp.router.stdio_process`) supervises one
child: stderr is logged, health uses EOF on stderr and periodic `client.ping()`,
and restarts use backoff **1 s, doubling to 60 s**, resetting after a stable
minute. The MCP client uses `mode="legacy"` because most packaged stdio servers
still speak the handshake-era protocol where `ping` exists.

In the `production` deployment profile, `startup_warnings` logs for each enabled
stdio upstream that the command runs with Keystone's user and **no sandbox** —
operators must trust that binary as much as they trust Keystone itself.

There is no container, seccomp, or UID separation inside Keystone: sandboxing
would break typical `npx`, `python`, and volume-mounted tools without a
separate operator workflow for building isolated images per upstream.

## Consequences

A compromised or malicious stdio upstream can read any secret present in the
passed environment and act with Keystone's filesystem and network identity.
Only vetted commands belong in the registry.

Readiness (`/readyz`) reports stdio process state under the top-level `upstreams`
key (and under `checks.upstreams` when `KEYSTONE_MCP_UPSTREAM_REQUIRE_ALL=true`)
but does not fail the probe unless that flag is set.

## Alternatives considered

**Per-upstream Linux namespaces** — High operational cost and not portable
across macOS dev machines; rejected for the gateway product.

**Always HTTP sidecars** — Many community MCP packages are stdio-only; rejected
as the only option.

**Implicit full environment inheritance** — Would leak `KEYSTONE_MCP_*` secrets
into untrusted code; rejected in favour of explicit `env` maps.

## Amendment (0.6.0)

The stdio child still runs under the **same OS user** as Keystone, but it does
not receive Keystone's environment wholesale — only the entry's `env` map (see
above). That does **not** isolate secrets: on Linux, any process of that user
may read `/proc/<pid>/environ` for the Keystone parent, and any file readable
by that user (mounted secrets, a shared `.env`, etc.).

**Operator guidance** (product/security owner decision):

- Run stdio upstream commands under a **dedicated OS user** (wrapper such as
  `setpriv` / `su-exec`); keep Keystone-owned files accessible only to the
  Keystone user.
- Run the Keystone container with **`--init`** (`docker run --init`, `init:
  true` in Compose) so orphaned upstream children are reaped and do not become
  zombies.
- Treat untrusted upstream code as an **HTTP service in a separate container**,
  not as a stdio child in the gateway process.
- Keep Keystone secrets in files with mode `0600` (or tighter), not in a shared
  `.env` visible to upstream users; minimize the container environment.

Process-level sandboxing inside Keystone remains out of scope for this ADR.

The MCP stdio client also passes `HOME`, `LOGNAME`, `PATH`, `SHELL`, `TERM`, and
`USER` into the child in addition to the entry's explicit `env` map.

## Links

- [connecting-services.md](../connecting-services.md#running-a-stdio-server)
- `src/keystone_mcp/router/stdio_process.py`,
  `src/keystone_mcp/upstream_registry/`
