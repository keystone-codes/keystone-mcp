# 0004 — Redis is required

## Status

Accepted (Keystone-MCP 0.5.0)

## Context

OAuth clients, authorization codes, access and refresh tokens, and pending login
state must survive process restarts and stay consistent across replicas. The
users-directory cache needs a shared revision marker so one replica's mutation
invalidates every other replica's cache.

## Decision

We require Redis for production OAuth and RBAC paths. `validate_settings` refuses
to start when RBAC mode is not `off` and `KEYSTONE_MCP_REDIS_URL` is empty.
There is no in-memory fallback for OAuth session data.

Key namespaces include `KEYSTONE_MCP_REDIS_KEY_PREFIX` (default `km:oauth:`),
`KEYSTONE_MCP_LOGIN_PENDING_KEY_PREFIX` (default `km:login:`), and
`KEYSTONE_MCP_USERS_REDIS_REVISION_KEY` (default `km:users:revision`). Records
carry TTLs aligned with token and login lifetimes.

The store factory always uses Redis outside tests.

## Consequences

Deployments run a small Redis service (or managed equivalent). Horizontal scale
gets shared OAuth state and coherent directory-cache invalidation.

Some per-process limits (tool-call throttles) remain local to each replica;
see [environment.md](../environment.md#more-than-one-replica).

## Alternatives considered

**Process memory only** — Sessions die on restart; replicas diverge; rejected.

**PostgreSQL for OAuth sessions** — Adds load and TTL ergonomics to a database
that is optional for local dev; rejected for session storage.

## Links

- [environment.md](../environment.md#redis)
- [security-model.md](../security-model.md)
- `src/keystone_mcp/config.py` (`validate_settings`), OAuth and login stores
