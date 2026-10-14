# 0008 — API keys are hashed, shown once, and Bearer-only for machines

## Status

Accepted (Keystone-MCP 0.5.0)

## Context

People sign in through the browser; automation (CI, schedulers, service
integrations) needs credentials that do not depend on OAuth refresh flows.
Keystone also needs machine identities that are not person-shaped emails in the
users table, with roles but without interactive sign-in or full administrator
power.

## Decision

API keys use the `ksk_<key_id>_<secret>` format (`keystone_mcp.user_directory.types`).
Only a SHA-256 hash of the secret is stored (`keystone_api_key` table, migration
`0003_api_keys`). The full key is returned once from `api_keys_issue` or
`keystone-mcp keys issue`; list and revoke never reveal the secret.

**People** may use a key on the form login provider (`api_key` type) when policy
allows. **Machines** authenticate with `Authorization: Bearer ksk_…` on the MCP
HTTP endpoint; `KeystoneOAuthProvider.load_access_token` and `verify_token`
detect the prefix and resolve the key through the users directory on every
request (cache invalidates with directory revision — no separate revocation
index for keys).

**Service accounts** live in `keystone_service_account` and
`keystone_service_account_role` (migration `0002_service_accounts`). Their
subject is `svc:<name>`; they receive normal RBAC roles but never
`administrator`, never satisfy `requires_human_identity`, and are always
non-interactive. Human JWT `sub` remains the lower-cased email.

OAuth access tokens for people and directory API keys are separate: human Bearer
tokens from `/token` are not accepted as API keys.

## Consequences

Operators issue machine keys on the server host in `production` (the
`api_keys_issue` tool is withheld there). Revoking a key or blocking a subject
takes effect on the next directory-backed verification.

HTTP-backed `UserDirectory` implementations do not store keys or service
accounts; only the built-in `local` backend does.

Mutating administration tools refuse service accounts in code (0.6.0).

## Alternatives considered

**Separate auth microservice for keys** — Extra moving part; rejected for 0.5.0
(built into the directory).

**Long-lived OAuth refresh tokens for machines** — Harder to scope, rotate, and
audit per workload; rejected in favour of directory-backed keys.

**Service accounts with OAuth sessions** — Would require token revocation
machinery for machines; rejected (keys re-checked each call).

## Links

- [users.md](../users.md), [user-directory.md](../user-directory.md)
- `src/keystone_mcp/users/`, `src/keystone_mcp/auth/keystone_oauth_provider.py`
