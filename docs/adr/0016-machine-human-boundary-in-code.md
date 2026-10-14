# 0016 — Machines never administer, enforced in code

## Status

Accepted (Keystone-MCP 0.6.0)

## Context

The policy file can list `requires_human_identity` patterns, but that list is
empty by default. Relying on it alone would let a deployment accidentally
allow service accounts to mutate users, keys, or policy.

## Decision

Every mutating built-in administration adapter (`users_*`, `service_accounts_*`,
`api_keys_*`, `policy_*`) refuses service callers with `forbidden` before the
directory or policy store is touched. The check uses `subject_type == "service"`
from the verified identity (API keys and Bearer service accounts set
`subject_type: service` in token claims; interactive sign-in sets `human`).

Read-only administration tools (`users_list`, `service_accounts_list`,
`api_keys_list`, `policy_read`, `policy_catalog`, `policy_validate`) stay
governed by RBAC only so operators can audit without signing in as a person.

## Consequences

Operators cannot override this floor in the policy file: even a wildcard allow
for a service account does not reach mutating admin tools. DEV-token and
API-key human sign-in remain `subject_type: human` and are not blocked by this
rule.

## Alternatives considered

**Ship a default `requires_human_identity` list in the bundled policy** —
Rejected: it would block legitimate human administrators who sign in with DEV
tokens or API keys on the login form, and it would still be editable away.

## Links

- [users.md § Service accounts](../users.md#service-accounts)
- `src/keystone_mcp/adapters/guards.py`
