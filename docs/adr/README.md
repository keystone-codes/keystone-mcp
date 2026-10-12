# Architecture decision records (ADR)

This folder holds short, durable notes on decisions that shape Keystone-MCP's
architecture or public contract. Each record answers one question: *why is it
built this way?*

## When to add a record

Write a new ADR when a change would update `docs/compatibility.md` (once that
file exists) or otherwise alters a frozen contract: environment variables,
policy keys, HTTP headers, tool names, registry fields, or behaviour operators
depend on.

Do not edit an accepted record in place. Supersede it: add a new numbered file
and set the old record's status to **Superseded by** `NNNN-title.md` (linked from
the old record).

## Template

Copy this skeleton into `NNNN-short-slug.md` (four-digit id, kebab-case slug):

```markdown
# NNNN — Title in sentence case

## Status

Accepted (Keystone-MCP 0.5.0)

## Context

…

## Decision

We …

## Consequences

…

## Alternatives considered

…

## Links

…
```

Keep each record under roughly 80 lines. Use short sentences and present tense.

## Index

| ID | Title | Status |
|---|---|---|
| [0001](0001-built-in-users-directory.md) | The users directory is built in | Accepted (0.5.0) |
| [0002](0002-roles-in-the-policy-file.md) | Roles and their tools live in the policy file | Accepted (0.5.0) |
| [0003](0003-signed-identity-assertion.md) | Upstreams get a signed identity assertion, not the user's token | Accepted (0.5.0) |
| [0004](0004-redis-is-required.md) | Redis is required | Accepted (0.5.0) |
| [0005](0005-dynamic-client-registration-on-by-default.md) | Dynamic client registration is on by default | Accepted (0.5.0) |
| [0006](0006-no-file-api-in-the-core.md) | File transfer is an upstream service; reference adapters live in contrib | Accepted (0.5.0) |
| [0007](0007-login-providers.md) | Sign-in goes through `LoginProvider`; Google is one OIDC provider | Accepted (0.5.0) |
| [0008](0008-api-keys-and-service-accounts.md) | API keys are hashed, shown once, and Bearer-only for machines | Accepted (0.5.0) |
| [0009](0009-plugins-via-entry-points.md) | Extensions are discovered only through entry points; built-ins use the same path | Accepted (0.5.0) |
| [0010](0010-fastmcp-major-version.md) | Why Keystone runs on fastmcp 4 | Accepted (0.5.0) |
| [0011](0011-rbac-by-name-for-prompts-and-resources.md) | Prompts are authorised by name with the tool patterns | Accepted (0.5.0) |
| [0012](0012-stdio-upstreams-run-unsandboxed.md) | A stdio upstream is trusted like Keystone itself | Accepted (0.5.0) |
