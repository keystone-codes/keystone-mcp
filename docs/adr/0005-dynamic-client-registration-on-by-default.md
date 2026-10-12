# 0005 — Dynamic client registration is on by default

## Status

Accepted (Keystone-MCP 0.5.0)

## Context

MCP desktop and IDE clients expect OAuth dynamic client registration (RFC 7591).
Requiring manual client provisioning for every installation blocks adoption, but
open registration without guardrails enables redirect theft and client sprawl.

## Decision

We enable dynamic client registration by default
(`KEYSTONE_MCP_OAUTH_DCR_ENABLED`, default `true`). Operators of closed
installations set it to `false` and register clients manually in Redis.

Mitigations shipped with DCR:

1. **Client cap** — `KEYSTONE_MCP_OAUTH_MAX_CLIENTS` (default `10000`, soft limit
   checked against the shared Redis client count).
2. **Client lifetime** — OAuth client records expire with token TTL settings
   (see [environment.md](../environment.md#redis)).
3. **IP throttling** — `KEYSTONE_MCP_OAUTH_THROTTLE_IP_MAX` (default `120`) on
   `/authorize` and `/token` within the login throttle window.
4. **Consent screen** — Every `/authorize` shows client name and redirect host
   before login proceeds.
5. **Redirect allowlist** — Optional `KEYSTONE_MCP_OAUTH_ALLOWED_REDIRECT_HOSTS`
   restricts registration, authorization, and token exchange to named hosts.

DCR registers a program, not a person: the client still needs a directory user
through `/login` before any tool call.

## Consequences

Default installs work with standard MCP clients. Operators must consciously
tighten redirect hosts or disable DCR on exposed deployments.

## Alternatives considered

**DCR off by default** — Forces manual steps for every client; rejected for the
default product path.

**CLI-only client registration** — Same operational burden without RFC 7591
interop; rejected as the default.

## Links

- [environment.md](../environment.md#server)
- [security-model.md](../security-model.md)
- `src/keystone_mcp/config.py`, OAuth registration and consent handlers
