# Keystone-MCP

<p align="center">
  <a href="https://github.com/keystone-codes/keystone-mcp/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/keystone-codes/keystone-mcp/actions/workflows/ci.yml/badge.svg"></a>
  &nbsp;&nbsp;&nbsp;&nbsp;
  <a href="pyproject.toml"><img alt="Python 3.11, 3.12, 3.13" src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&logoColor=white"></a>
  &nbsp;&nbsp;&nbsp;&nbsp;
  <a href="CHANGELOG.md"><img alt="version 0.4.0" src="https://img.shields.io/badge/version-0.4.0-0f172a"></a>
  &nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://github.com/jlowin/fastmcp"><img alt="FastMCP 3.4.4" src="https://img.shields.io/badge/FastMCP-3.4.4-059669"></a>
  &nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://modelcontextprotocol.io"><img alt="MCP Streamable HTTP" src="https://img.shields.io/badge/MCP-Streamable%20HTTP-0891b2"></a>
  &nbsp;&nbsp;&nbsp;&nbsp;
  <a href="skills/keystone-user-admin/SKILL.md"><img alt="CLAUDE skill" src="https://img.shields.io/badge/CLAUDE-skill-c96442"></a>
</p>

Keystone-MCP is the single front door of an agent application. A person
works in one MCP client — Claude Desktop, Cursor, Claude Code — and that
client talks only to Keystone-MCP. Behind it you run your own services,
each in its own language, with its own storage, exposing its work as MCP
tools.

Keystone-MCP is one layer with three jobs: **facade** (one address and one
tool catalog for the client, split into sections), **router** (every call
is forwarded to the service that actually owns that tool), and
**authorization** (it checks who signed in and decides, from one policy
file, what that person may see and call). Services keep their business
logic and do not check roles themselves — Keystone-MCP already decided
before the call reaches them.

![One front door, many services behind it. Clients connect through Keystone-MCP. Keystone-MCP authenticates the caller, applies a role policy, and routes the call. Each service speaks MCP and keeps its own storage.](docs/architecture.svg)

Documents, Billing and Search on the diagram are examples of services you
bring. Keystone-MCP ships the facade, the built-in users directory, and
the proxy.

## Try it locally

Three containers — Keystone-MCP, Redis, and a sample upstream service — up
in one command, with a sign-in, a second person with a smaller role, and
that person's catalog shrinking to match:

```bash
git clone https://github.com/keystone-codes/keystone-mcp.git
cd keystone-mcp
docker compose -f docker-compose.demo.yml up -d --build --wait
```

Then connect a client and sign in:
[docs/paths/local-compose.md](docs/paths/local-compose.md) (about 15 minutes).

> **DEV tokens are for your machine only.** They are a shared password —
> anyone holding one signs in as any email already in the users directory.
> The `production` profile refuses to start with one set. See the
> [security model](docs/security-model.md).

## Get started

- **Local** — [Run Keystone-MCP on your machine](docs/paths/local-compose.md)
- **Production** — [Deploy with Docker, Postgres and TLS](docs/paths/production-docker.md)

## Why Keystone-MCP

- **One facade.** A client sees one address and one tool catalog, split into
  sections, one per service.
- **Any users directory.** Built in (SQLite for one host, Postgres for
  production), or your own directory over HTTP.
- **Any sign-in method.** Google and DEV tokens today; a common interface
  for your own identity provider is on the roadmap for 0.5.0.
- **Onboarding and access through the agent.** An administrator adds
  people, changes roles, and manages access by asking the agent, with the
  `users_*` tools, the `keystone-user-admin` skill, or
  `setup.sh --non-interactive`; the access-policy file itself is still
  edited by hand in 0.4.0.
- **Services in any language or SDK.** Each one is a plain MCP server
  behind a transparent proxy; it keeps its own stack and storage.
- **One policy file, reloaded live.** Access rules live in a single file;
  a change takes effect on `SIGHUP`, no restart.
- **Services never check roles themselves.** RBAC is decided once, on
  Keystone-MCP, before a call is forwarded.
- **`production` refuses a weak setup.** DEV tokens, a SQLite users
  directory, and plain HTTP on a public host all fail startup instead of
  only logging a warning.
- **Metrics and audit included.** Prometheus series and structured
  authorization events ship with the process.
- **One image, two architectures.** `linux/amd64` and `linux/arm64`.
- **A working demo in about 15 minutes.** See "Try it locally" above.

Full description of every capability, and what is still 0.5.0:
[docs/features.md](docs/features.md).

## Documentation

All guides, grouped by role: [docs/README.md](docs/README.md).

Metrics and structured logs: [audit and metrics](docs/observability-rbac.md),
[logging](docs/observability-logging.md).

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## Security reports

See [SECURITY.md](SECURITY.md).

## License

Keystone-MCP is released under the [Apache License 2.0](LICENSE).
Copyright 2026 Alexey Klochkov (skynet@kofe.in).

You may use, modify and distribute it, including inside a commercial product
and as a hosted service. Keep this license and the copyright notice with the
code, and mark the files you change. The license includes a patent grant from
the copyright holder.

<p align="center">
  <a href="LICENSE"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-1e3a8a"></a>
</p>
