# Security Policy

## Reporting a vulnerability

Please report suspected security vulnerabilities privately, using
[GitHub Security Advisories](https://github.com/keystone-codes/keystone-mcp/security/advisories/new)
on this repository. Do not open a public issue for a suspected vulnerability.

Include as much detail as you can: affected version/commit, reproduction
steps, and the impact you believe it has. We will acknowledge your report and
follow up with next steps as we investigate.

## Supported versions

| Version | Supported |
|---|---|
| `0.4.x` (currently `0.4.0`) | yes |
| `0.3.x` and older | no |

Only the latest released minor version receives security fixes.

Dependencies are audited on every PR and weekly (`uv audit`); the container
image is scanned with Trivy.

## Security documentation

- [Security model](docs/security-model.md) — trust zones, RBAC modes, dev tokens
- [Production checklist](docs/production-checklist.md) — before exposing Keystone-MCP on the internet

## Scope

In scope: authentication and authorization logic (OAuth flows, token
handling, RBAC policy evaluation and enforcement), identity propagation to
upstream servers, and the built-in `users_*` administrative tools.

Out of scope: vulnerabilities in a deployment's own upstream MCP servers,
users directory, or RBAC policy file content — those are the responsibility
of whoever operates them.
