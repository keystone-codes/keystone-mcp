# 0003 — Upstreams get a signed identity assertion, not the user's token

## Status

Accepted (Keystone-MCP 0.5.0)

## Context

The MCP authorization model forbids forwarding the client's access token to an
upstream (token passthrough). Upstreams still need to know who called, which
roles RBAC used for this call, and that the request came from Keystone-MCP.

See the MCP specification on access-token privilege delegation:
https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization#access-token-privilege-delegation

## Decision

We send a short-lived signed JWT in `X-Keystone-Identity` on proxied tool calls
when the registry entry sets `auth.identity_secret_env`. The token uses HS256,
header `typ: keystone-identity+jwt`, and `aud` equal to the registry entry's
`name` (not its namespace). The secret is read from the named environment
variable at startup (minimum 32 bytes); each upstream has its own secret.

Claims include `sub`, `sub_type`, `roles` (from the RBAC decision for this
call), `rbac`, `auth_method`, `interactive`, `task_id`, `mcp_method`,
`mcp_target`, and optional `email` / `client_id`. Signing lives in
`keystone_mcp.identity_assertion`.

`X-Author-Email` is still sent alongside for compatibility; it is unsigned,
deprecated since 0.5.0, and removed in 2.0. Upstreams must verify
`X-Keystone-Identity` when configured, not trust the email header alone.

## Consequences

Upstreams authenticate callers without holding OAuth tokens. Compromise of one
upstream secret cannot forge assertions for another (`aud` binding).

Operators must provision per-upstream secrets and implement verification
(examples under `examples/keystone-identity/`).

## Alternatives considered

**OAuth token exchange (RFC 8693)** — Extra protocol surface and token issuance
path; rejected for 0.5.0.

**mTLS only** — Proves transport, not subject and roles per call; insufficient alone.

**Unsigned identity headers** — Trivially spoofable on a shared network; rejected.

## Links

- [connecting-services.md](../connecting-services.md#who-is-calling-x-keystone-identity)
- [security-model.md](../security-model.md)
- `src/keystone_mcp/identity_assertion.py`, `src/keystone_mcp/adapters/mcp_proxy.py`
