# 0001 — The users directory is built in

## Status

Accepted (Keystone-MCP 0.5.0)

## Context

Early deployments depended on a separate, unpublished users service. Keystone-MCP
could not start usefully without that sidecar, and operators had no default path
to sign-in and RBAC.

Product teams also need a stable seam to swap storage: a single host with SQLite,
production with PostgreSQL, or an external HTTP catalog.

## Decision

We ship the users directory inside Keystone-MCP. The built-in backend uses
SQLite locally (`KEYSTONE_MCP_USERS_DB_URL` defaulting to a file path) and
PostgreSQL in the `production` deployment profile
(`postgresql+psycopg://…` only). Tables are `keystone_user`, `keystone_user_role`,
and `keystone_users_alembic_version`. Migrations run on startup via
`keystone_mcp.users.migrate`; on PostgreSQL, a transactional advisory lock
serializes concurrent starters.

A cache, revision marker (`KEYSTONE_MCP_USERS_REDIS_REVISION_KEY`, default
`km:users:revision`), and circuit breaker live in `keystone_mcp/user_directory/`
above any backend. Custom sources implement the `UserDirectory` protocol
(`keystone_mcp.user_directory`); the factory wires `local` or `http` from
`KEYSTONE_MCP_USERS_BACKEND`.

## Consequences

Operators get a working directory out of the box. Forks can replace storage
without forking login or RBAC, as long as they honour the protocol contract.

We maintain SQL migrations and database rules in-tree. Multi-replica production
must use Postgres for the built-in backend; SQLite is one file per process.

## Alternatives considered

**Separate users microservice** — Adds a hard dependency before first login; rejected.

**Roles only from the login provider's groups** — Couples access to IdP group
sync and hides reviewable role changes; rejected.

**SCIM or periodic directory sync** — Heavy operational model for the default
case; not chosen for the built-in path (custom `UserDirectory` implementations
may still integrate externally).

## Links

- [users.md](../users.md), [user-directory.md](../user-directory.md)
- [environment.md](../environment.md#users-directory)
- `src/keystone_mcp/users/`, `src/keystone_mcp/user_directory/`
