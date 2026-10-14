# 0013 — Management roles come from the policy file

## Status

Accepted (Keystone-MCP 0.6.0)

## Context

A deployment names its roles freely in the RBAC policy file. Protection cannot
depend on a fixed role name such as `administrator`, or on a default policy
shape, because operators rename roles and ship custom policies.

## Decision

We derive **management roles** and **full administrators** from the live policy
and catalog:

- A **management role** is any declared role whose `allow` patterns reach at
  least one mutating built-in administration tool (`users_*`,
  `service_accounts_*`, `api_keys_*`, `policy_*`, excluding read-only tools
  such as `users_list` and `policy_read`). Evaluation uses glob matching and
  respects the policy-wide `deny` list.
- A **full administrator** is a person whose combined roles reach every
  mutating built-in administration tool (again honoring `deny`).

Only a full administrator may grant or revoke a management role, change an
account that already holds one (person or service account), or make `policy_*`
changes that touch administration. Other roles may grant ordinary roles only
within their own permissions (subset check against published tool names).

Management checks use `policy.allows` with the stricter of the in-memory
snapshot and the on-disk file when they differ.

## Consequences

Renaming roles in the policy does not weaken these gates as long as the
patterns still cover the administration families. `keystone-mcp users
grant-admin` grants whichever role the policy defines as full administration,
not a hardcoded name.

## Alternatives considered

**Reserve the name `administrator`** — Rejected: it fights custom policies and
gives a false sense of safety when another role reaches the same tools.

**Maintain a `grantable_roles` list in the policy** — Rejected for management
roles: a static list would drift from the catalog; delegation instead compares
role permissions to the actor's permissions at grant time.

## Links

- [rbac-policy-format.md §2.10](../rbac-policy-format.md#210-management-roles-and-full-administrators)
- `src/keystone_mcp/rbac/management.py`
