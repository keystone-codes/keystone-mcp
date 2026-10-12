# 0002 — Roles and their tools live in the policy file

## Status

Accepted (Keystone-MCP 0.5.0)

## Context

Tool access must be reviewable in git, reloadable without restart, and checked
against the live users directory. Operators need deny-by-default semantics and
a global kill list stronger than any role's `allow`.

## Decision

We treat the RBAC policy YAML as the single source of truth for role names and
their tool patterns. The file uses `version: "2.0.0"` and only these top-level
keys (`keystone_mcp.rbac.policy.POLICY_TOP_LEVEL_KEYS`): `version`,
`default_deny`, `roles`, `deny`, `requires_human_identity`, `critical_tools`,
`reserved_allow_patterns`, `tool_dispositions`. `default_deny` must be boolean
`true`. Effective permission for a person is the union of `allow` patterns
across assigned roles; any matching `deny` pattern wins, including over `*`.

The users directory stores only role names on each person. Assigning a role that
is not declared in the file fails with `validation_error` (`unknown role: …`).
The name `administrator` is reserved in the directory (last-administrator and
self-mutation rules), not as a special case in policy evaluation.

Policy reloads on file change and on `SIGHUP` (`keystone_mcp.rbac.loader`).

## Consequences

Access changes are diffable, revertible, and auditable with the policy version
string and content hash. The directory stays a people catalog; permission
design stays in the policy repo overlay.

Operators must keep policy and directory assignments aligned when renaming roles.

## Alternatives considered

**Roles and permissions in the database with an admin UI** — Harder to review,
no native git history; rejected for the core model.

**Permissions derived from OAuth scopes alone** — Scopes describe the client app,
not the signed-in person's tool entitlements; rejected.

## Links

- [rbac-policy-format.md](../rbac-policy-format.md)
- [users.md](../users.md)
- `src/keystone_mcp/rbac/policy.py`, `src/keystone_mcp/rbac/loader.py`
